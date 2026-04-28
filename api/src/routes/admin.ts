import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, like, or, desc, gte, lte, and, count, sql } from 'drizzle-orm';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { db } from '../db/client.js';
import { users, organizations, repositories, pullRequests, auditLog } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireSuperadmin } from '../middleware/superadmin.js';
import { config } from '../config.js';
import { checkPushAllowed } from '../services/branchProtection.service.js';

const execFileAsync = promisify(execFile);

const updateUserBody = z.object({
  isActive:     z.boolean().optional(),
  isSuperadmin: z.boolean().optional(),
}).strict();

const checkPushBody = z.object({
  repoId: z.string().uuid(),
  userId: z.string().uuid(),
  updates: z.array(z.object({
    oldSha: z.string(),
    newSha: z.string(),
    ref:    z.string(),
  })),
}).strict();

let cachedStorageBytes = 0;
let lastStorageCheck = 0;
const STORAGE_CACHE_TTL = 300_000; // 5 minutes

export default async function adminRoutes(app: FastifyInstance) {
  const pre = [requireAuth, requireSuperadmin];

  // ── Internal: Check Push ──────────────────────────────────────────────────
  // This endpoint is called by the pre-receive hook.
  app.post('/internal/check-push', async (req, reply) => {
    // Only allow localhost
    if (req.ip !== '127.0.0.1' && req.ip !== '::1') {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const parsed = checkPushBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Invalid body' });

    const { repoId, userId, updates } = parsed.data;

    for (const update of updates) {
      if (!update.ref.startsWith('refs/heads/')) continue;
      const branch = update.ref.replace('refs/heads/', '');
      const isForcePush = update.oldSha !== '0'.repeat(40) && update.newSha !== '0'.repeat(40); // Simplistic check

      const result = await checkPushAllowed(repoId, branch, userId, isForcePush);
      if (!result.allowed) {
        return reply.status(403).send({ error: result.reason });
      }
    }

    return reply.status(200).send({ ok: true });
  });

  // ── Users ─────────────────────────────────────────────────────────────────
  app.get('/users', { preHandler: pre }, async (req, reply) => {
...

    const search = query['q'];
    const limit  = Math.min(parseInt(query['limit']  ?? '50', 10), 200);
    const offset = parseInt(query['offset'] ?? '0', 10);

    const where = search
      ? or(like(users.username, `%${search}%`), like(users.email, `%${search}%`))
      : undefined;

    const rows = await db
      .select({ id: users.id, username: users.username, email: users.email, isActive: users.isActive, isSuperadmin: users.isSuperadmin, createdAt: users.createdAt })
      .from(users)
      .where(where)
      .orderBy(desc(users.createdAt))
      .limit(limit)
      .offset(offset);

    return reply.send(rows);
  });

  app.get('/users/:userId', { preHandler: pre }, async (req, reply) => {
    const { userId } = req.params as { userId: string };
    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) return reply.status(404).send({ error: 'User not found' });
    const { passwordHash: _, ...safe } = user;
    return reply.send(safe);
  });

  app.patch('/users/:userId', { preHandler: pre }, async (req, reply) => {
    const { userId } = req.params as { userId: string };
    const parsed = updateUserBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed' });

    const [updated] = await db.update(users)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(eq(users.id, userId))
      .returning({ id: users.id, username: users.username, isActive: users.isActive, isSuperadmin: users.isSuperadmin });

    if (!updated) return reply.status(404).send({ error: 'User not found' });
    return reply.send(updated);
  });

  app.delete('/users/:userId', { preHandler: pre }, async (req, reply) => {
    const { userId } = req.params as { userId: string };
    // Prevent superadmin from deleting themselves
    if (userId === req.user!.id) return reply.status(400).send({ error: 'Cannot delete your own account' });
    await db.delete(users).where(eq(users.id, userId));
    return reply.status(204).send();
  });

  // ── Organizations ─────────────────────────────────────────────────────────
  app.get('/orgs', { preHandler: pre }, async (req, reply) => {
    const query = req.query as Record<string, string>;
    const limit  = Math.min(parseInt(query['limit']  ?? '50', 10), 200);
    const offset = parseInt(query['offset'] ?? '0', 10);

    const rows = await db.select()
      .from(organizations)
      .orderBy(desc(organizations.createdAt))
      .limit(limit)
      .offset(offset);
    return reply.send(rows);
  });

  app.delete('/orgs/:orgId', { preHandler: pre }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    await db.delete(organizations).where(eq(organizations.id, orgId));
    return reply.status(204).send();
  });

  // ── System Stats ──────────────────────────────────────────────────────────
  app.get('/stats', { preHandler: pre }, async (_req, reply) => {
    const [[userCount], [orgCount], [repoCount], [prCount]] = await Promise.all([
      db.select({ c: count() }).from(users),
      db.select({ c: count() }).from(organizations),
      db.select({ c: count() }).from(repositories),
      db.select({ c: count() }).from(pullRequests),
    ]);

    const now = Date.now();
    if (now - lastStorageCheck > STORAGE_CACHE_TTL) {
      try {
        const { stdout } = await execFileAsync('du', ['-sb', config.gitReposRoot]);
        cachedStorageBytes = parseInt(stdout.split('\t')[0] ?? '0', 10);
        lastStorageCheck = now;
      } catch {
        // git repos dir may be empty
      }
    }

    return reply.send({
      users:        userCount?.c ?? 0,
      organizations: orgCount?.c ?? 0,
      repositories: repoCount?.c ?? 0,
      pullRequests: prCount?.c ?? 0,
      storageBytes: cachedStorageBytes,
    });
  });

  // ── Audit Log ─────────────────────────────────────────────────────────────
  app.get('/audit-log', { preHandler: pre }, async (req, reply) => {
    const query = req.query as Record<string, string>;
    const limit  = Math.min(parseInt(query['limit']  ?? '50', 10), 500);
    const offset = parseInt(query['offset'] ?? '0', 10);

    const conditions = [];
    if (query['actor'])    conditions.push(eq(auditLog.actorUsername, query['actor']!));
    if (query['action'])   conditions.push(eq(auditLog.action, query['action']!));
    if (query['orgId'])    conditions.push(eq(auditLog.orgId, query['orgId']!));
    if (query['repoId'])   conditions.push(eq(auditLog.repoId, query['repoId']!));
    if (query['since'])    conditions.push(gte(auditLog.createdAt, new Date(query['since']!)));
    if (query['until'])    conditions.push(lte(auditLog.createdAt, new Date(query['until']!)));

    const rows = await db.select()
      .from(auditLog)
      .where(conditions.length ? and(...conditions) : undefined)
      .orderBy(desc(auditLog.createdAt))
      .limit(limit)
      .offset(offset);

    return reply.send(rows);
  });
}
