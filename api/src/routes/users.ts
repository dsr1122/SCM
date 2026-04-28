import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and, isNull } from 'drizzle-orm';
import { createHash, randomBytes, createPublicKey } from 'crypto';
import { db } from '../db/client.js';
import { users, personalAccessTokens, sshKeys, notificationPreferences } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { logAuditEvent } from '../services/audit.service.js';
import type { RepoRole } from '../types/index.js';

const updateBody = z.object({
  email:    z.string().email().max(255).optional(),
  password: z.string().min(10).max(128).optional(),
}).strict();

const createPatBody = z.object({
  name:      z.string().min(1).max(100),
  scopes:    z.array(z.enum(['repo:read', 'repo:write', 'org:read', 'admin'])).min(1),
  expiresAt: z.string().datetime().optional(),
}).strict();

const addSshKeyBody = z.object({
  title:     z.string().min(1).max(100),
  publicKey: z.string().min(20).max(8192),
}).strict();

const notifPrefsBody = z.object({
  notifyPrReview:  z.boolean().optional(),
  notifyPrMention: z.boolean().optional(),
  notifyOrgInvite: z.boolean().optional(),
  notifyPush:      z.boolean().optional(),
  emailEnabled:    z.boolean().optional(),
}).strict();

function parseSshPublicKey(keyText: string): { fingerprint: string } {
  const parts = keyText.trim().split(/\s+/);
  if (parts.length < 2) throw new Error('Invalid SSH public key format');
  const keyType = parts[0]!;
  const keyBase64 = parts[1]!;

  const validTypes = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com'];
  if (!validTypes.includes(keyType)) throw new Error(`Unsupported key type: ${keyType}`);

  // Compute SHA256 fingerprint matching ssh-keygen -l -E sha256 output
  const keyBytes = Buffer.from(keyBase64, 'base64');
  const fp = createHash('sha256').update(keyBytes).digest('base64').replace(/=+$/, '');
  return { fingerprint: `SHA256:${fp}` };
}

export default async function userRoutes(app: FastifyInstance) {
  // ── Profile ───────────────────────────────────────────────────────────────

  app.get('/me', { preHandler: [requireAuth] }, async (req, reply) => {
    const [user] = await db
      .select({ id: users.id, username: users.username, email: users.email, isSuperadmin: users.isSuperadmin, createdAt: users.createdAt })
      .from(users).where(eq(users.id, req.user!.id)).limit(1);
    if (!user) return reply.status(404).send({ error: 'User not found' });
    return reply.send(user);
  });

  app.get('/:username', { preHandler: [requireAuth] }, async (req, reply) => {
    const { username } = req.params as { username: string };
    const [user] = await db
      .select({ id: users.id, username: users.username, createdAt: users.createdAt })
      .from(users).where(eq(users.username, username)).limit(1);
    if (!user) return reply.status(404).send({ error: 'User not found' });
    return reply.send(user);
  });

  app.patch('/me', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = updateBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }
    const updates: Partial<{ email: string; passwordHash: string; updatedAt: Date }> = { updatedAt: new Date() };

    if (parsed.data.email) updates.email = parsed.data.email;
    if (parsed.data.password) {
      // Require current password before allowing a password change — prevents account
      // takeover with a stolen (not-yet-expired) access token.
      const { currentPassword } = (req.body ?? {}) as { currentPassword?: string };
      if (!currentPassword) {
        return reply.status(400).send({ error: 'currentPassword is required to change password' });
      }
      const [row] = await db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, req.user!.id)).limit(1);
      const { verifyPassword, hashPassword } = await import('../services/auth.service.js');
      if (!row || !(await verifyPassword(row.passwordHash, currentPassword))) {
        return reply.status(401).send({ error: 'Current password is incorrect' });
      }
      updates.passwordHash = await hashPassword(parsed.data.password);
      logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'user.password_changed', ipAddress: req.ip });
    }

    const [updated] = await db.update(users).set(updates).where(eq(users.id, req.user!.id))
      .returning({ id: users.id, username: users.username, email: users.email, updatedAt: users.updatedAt });
    return reply.send(updated);
  });

  // ── Personal Access Tokens ────────────────────────────────────────────────

  app.get('/me/tokens', { preHandler: [requireAuth] }, async (req, reply) => {
    const tokens = await db
      .select({ id: personalAccessTokens.id, name: personalAccessTokens.name, prefix: personalAccessTokens.prefix, scopes: personalAccessTokens.scopes, expiresAt: personalAccessTokens.expiresAt, lastUsedAt: personalAccessTokens.lastUsedAt, createdAt: personalAccessTokens.createdAt })
      .from(personalAccessTokens)
      .where(and(eq(personalAccessTokens.userId, req.user!.id), isNull(personalAccessTokens.revokedAt)));
    return reply.send(tokens);
  });

  app.post('/me/tokens', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = createPatBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    const raw = 'scm_' + randomBytes(20).toString('hex');
    const hash = createHash('sha256').update(raw).digest('hex');
    const prefix = raw.slice(0, 8);

    const [token] = await db.insert(personalAccessTokens).values({
      userId:    req.user!.id,
      name:      parsed.data.name,
      tokenHash: hash,
      prefix,
      scopes:    parsed.data.scopes,
      expiresAt: parsed.data.expiresAt ? new Date(parsed.data.expiresAt) : undefined,
    }).returning({ id: personalAccessTokens.id, name: personalAccessTokens.name, prefix: personalAccessTokens.prefix, scopes: personalAccessTokens.scopes, expiresAt: personalAccessTokens.expiresAt, createdAt: personalAccessTokens.createdAt });

    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'pat.created', resourceId: token!.id, metadata: { name: parsed.data.name, scopes: parsed.data.scopes }, ipAddress: req.ip });

    // Return the raw token ONCE — never stored
    return reply.status(201).send({ ...token, token: raw });
  });

  app.delete('/me/tokens/:tokenId', { preHandler: [requireAuth] }, async (req, reply) => {
    const { tokenId } = req.params as { tokenId: string };
    await db.update(personalAccessTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(personalAccessTokens.id, tokenId), eq(personalAccessTokens.userId, req.user!.id)));

    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'pat.revoked', resourceId: tokenId, ipAddress: req.ip });
    return reply.status(204).send();
  });

  // ── SSH Keys ──────────────────────────────────────────────────────────────

  app.get('/me/ssh-keys', { preHandler: [requireAuth] }, async (req, reply) => {
    const keys = await db
      .select({ id: sshKeys.id, title: sshKeys.title, fingerprint: sshKeys.fingerprint, createdAt: sshKeys.createdAt, lastUsedAt: sshKeys.lastUsedAt })
      .from(sshKeys).where(eq(sshKeys.userId, req.user!.id));
    return reply.send(keys);
  });

  app.post('/me/ssh-keys', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = addSshKeyBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    let fingerprint: string;
    try {
      ({ fingerprint } = parseSshPublicKey(parsed.data.publicKey));
    } catch (err) {
      return reply.status(400).send({ error: `Invalid SSH public key: ${String(err)}` });
    }

    const [existing] = await db.select({ id: sshKeys.id }).from(sshKeys).where(eq(sshKeys.fingerprint, fingerprint)).limit(1);
    if (existing) return reply.status(409).send({ error: 'SSH key already in use' });

    const [key] = await db.insert(sshKeys).values({ userId: req.user!.id, title: parsed.data.title, fingerprint, publicKey: parsed.data.publicKey.trim() })
      .returning({ id: sshKeys.id, title: sshKeys.title, fingerprint: sshKeys.fingerprint, createdAt: sshKeys.createdAt });

    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'ssh_key.added', resourceId: key!.id, metadata: { fingerprint }, ipAddress: req.ip });
    return reply.status(201).send(key);
  });

  app.delete('/me/ssh-keys/:keyId', { preHandler: [requireAuth] }, async (req, reply) => {
    const { keyId } = req.params as { keyId: string };
    await db.delete(sshKeys).where(and(eq(sshKeys.id, keyId), eq(sshKeys.userId, req.user!.id)));
    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'ssh_key.removed', resourceId: keyId, ipAddress: req.ip });
    return reply.status(204).send();
  });

  // ── Notification Preferences ──────────────────────────────────────────────

  app.get('/me/notifications', { preHandler: [requireAuth] }, async (req, reply) => {
    const [prefs] = await db.select().from(notificationPreferences).where(eq(notificationPreferences.userId, req.user!.id)).limit(1);
    return reply.send(prefs ?? { userId: req.user!.id, notifyPrReview: true, notifyPrMention: true, notifyOrgInvite: true, notifyPush: false, emailEnabled: true });
  });

  app.patch('/me/notifications', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = notifPrefsBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed' });

    const [prefs] = await db.insert(notificationPreferences)
      .values({ userId: req.user!.id, ...parsed.data })
      .onConflictDoUpdate({ target: [notificationPreferences.userId], set: parsed.data })
      .returning();
    return reply.send(prefs);
  });
}
