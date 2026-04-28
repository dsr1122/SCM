import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { randomBytes } from 'crypto';
import { db } from '../db/client.js';
import { ssoProviders, userIdentities, users, orgMembers } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireSuperadmin } from '../middleware/superadmin.js';
import { encryptClientSecret, decryptClientSecret, generateState } from '../services/sso.service.js';
import { issueAccessToken, issueRefreshToken } from '../services/auth.service.js';
import { logAuditEvent } from '../services/audit.service.js';
import { config } from '../config.js';
import { redis } from '../middleware/rateLimiter.js';
import type { OrgRole } from '../types/index.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const createProviderBody = z.object({
  name:          z.string().min(1).max(100),
  slug:          z.string().min(1).max(50).regex(/^[a-z0-9-]+$/),
  providerType:  z.enum(['oidc', 'oauth2']),
  clientId:      z.string().min(1),
  clientSecret:  z.string().min(1),
  discoveryUrl:  z.string().url().optional(),
  authUrl:       z.string().url().optional(),
  tokenUrl:      z.string().url().optional(),
  defaultOrgRole: z.enum(['admin', 'member', 'guest']).default('member'),
  orgId:         z.string().uuid().optional(),
}).strict();

export default async function ssoRoutes(app: FastifyInstance) {
  // ── Authorize redirect ────────────────────────────────────────────────────
  app.get('/authorize/:slug', async (req, reply) => {
    const { slug } = req.params as { slug: string };
    const [provider] = await db.select().from(ssoProviders)
      .where(and(eq(ssoProviders.slug, slug), eq(ssoProviders.isEnabled, true))).limit(1);
    if (!provider) return reply.status(404).send({ error: 'SSO provider not found' });

    const state = generateState();
    const callbackUrl = `${config.ssoCallbackBaseUrl}/auth/sso/callback/${slug}`;

    // Store state + provider in Redis (5 min TTL)
    await redis.setex(`sso:state:${state}`, 300, JSON.stringify({ providerId: provider.id, callbackUrl }));

    let authUrl: string;

    if (provider.providerType === 'oidc' && provider.discoveryUrl) {
      // Discover authorization_endpoint from OIDC discovery document
      try {
        const discovery = await fetch(`${provider.discoveryUrl}/.well-known/openid-configuration`);
        const meta = await discovery.json() as Record<string, string>;
        const base = meta['authorization_endpoint'] ?? '';
        const params = new URLSearchParams({
          response_type: 'code',
          client_id:     provider.clientId,
          redirect_uri:  callbackUrl,
          scope:         'openid email profile',
          state,
        });
        authUrl = `${base}?${params}`;
      } catch {
        return reply.status(502).send({ error: 'Failed to contact OIDC discovery endpoint' });
      }
    } else if (provider.authUrl) {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id:     provider.clientId,
        redirect_uri:  callbackUrl,
        state,
      });
      authUrl = `${provider.authUrl}?${params}`;
    } else {
      return reply.status(400).send({ error: 'Provider misconfigured: no discoveryUrl or authUrl' });
    }

    return reply.redirect(authUrl);
  });

  // ── OAuth2 callback ───────────────────────────────────────────────────────
  app.get('/callback/:slug', async (req, reply) => {
    const { slug } = req.params as { slug: string };
    const query = req.query as Record<string, string>;
    const { code, state } = query;

    if (!code || !state) return reply.status(400).send({ error: 'Missing code or state' });

    const stateData = await redis.get(`sso:state:${state}`);
    if (!stateData) return reply.status(400).send({ error: 'Invalid or expired state parameter' });
    await redis.del(`sso:state:${state}`);

    const { providerId } = JSON.parse(stateData) as { providerId: string };
    const [provider] = await db.select().from(ssoProviders).where(eq(ssoProviders.id, providerId)).limit(1);
    if (!provider) return reply.status(404).send({ error: 'Provider not found' });

    const clientSecret = decryptClientSecret(provider.clientSecretEncrypted);
    const callbackUrl = `${config.ssoCallbackBaseUrl}/auth/sso/callback/${slug}`;

    // Exchange code for tokens
    let tokenEndpoint = provider.tokenUrl ?? '';
    let jwksUri: string | null = null;
    let issuer: string | null = null;

    if (provider.providerType === 'oidc' && provider.discoveryUrl) {
      try {
        const disc = await fetch(`${provider.discoveryUrl}/.well-known/openid-configuration`);
        const meta = await disc.json() as Record<string, string>;
        tokenEndpoint = meta['token_endpoint'] ?? '';
        jwksUri = meta['jwks_uri'] ?? null;
        issuer = meta['issuer'] ?? null;
      } catch {
        return reply.status(502).send({ error: 'Failed to contact OIDC discovery endpoint' });
      }
    }

    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:   'authorization_code',
        code,
        redirect_uri: callbackUrl,
        client_id:    provider.clientId,
        client_secret: clientSecret,
      }),
    });

    if (!tokenRes.ok) return reply.status(502).send({ error: 'Token exchange failed' });
    const tokens = await tokenRes.json() as Record<string, string>;

    // Get user info from id_token or userinfo endpoint
    let externalId: string;
    let email: string;
    let rawClaims: Record<string, unknown> = {};

    if (tokens['id_token']) {
      if (provider.providerType === 'oidc' && jwksUri) {
        try {
          const JWKS = createRemoteJWKSet(new URL(jwksUri));
          const { payload } = await jwtVerify(tokens['id_token'], JWKS, {
            issuer: issuer ?? undefined,
            audience: provider.clientId,
          });
          rawClaims = payload as Record<string, unknown>;
        } catch (err) {
          req.log.error(err, 'ID token verification failed');
          return reply.status(401).send({ error: 'Invalid ID token signature' });
        }
      } else {
        // Fallback for non-OIDC or missing discovery (less secure, but better than nothing)
        const parts = tokens['id_token'].split('.');
        rawClaims = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString()) as Record<string, unknown>;
      }
      externalId = String(rawClaims['sub'] ?? '');
      email = String(rawClaims['email'] ?? '');
    } else {
      return reply.status(502).send({ error: 'No id_token in response' });
    }

    if (!externalId) return reply.status(502).send({ error: 'Could not extract user identity from token' });

    // JIT provisioning: find or create user
    const [existingIdentity] = await db.select({ userId: userIdentities.userId })
      .from(userIdentities)
      .where(and(eq(userIdentities.providerId, provider.id), eq(userIdentities.externalId, externalId)))
      .limit(1);

    let userId: string;
    if (existingIdentity) {
      userId = existingIdentity.userId;
      await db.update(userIdentities).set({ lastLoginAt: new Date(), rawClaims, email })
        .where(and(eq(userIdentities.providerId, provider.id), eq(userIdentities.externalId, externalId)));
    } else {
      // Create user (generate username from email or claim)
      const rawName = (rawClaims['preferred_username'] ?? rawClaims['name'] ?? email.split('@')[0] ?? 'user') as string;
      let username = rawName.toLowerCase().replace(/[^a-z0-9_-]/g, '_').slice(0, 39);
      const [taken] = await db.select({ id: users.id }).from(users).where(eq(users.username, username)).limit(1);
      if (taken) username = `${username}_${randomBytes(3).toString('hex')}`;

      const [newUser] = await db.insert(users)
        .values({ username, email, passwordHash: `sso:${provider.slug}`, isActive: true })
        .returning({ id: users.id });
      userId = newUser!.id;

      // If provider is org-scoped, auto-add to org
      if (provider.orgId) {
        await db.insert(orgMembers)
          .values({ orgId: provider.orgId, userId, role: provider.defaultOrgRole as OrgRole })
          .onConflictDoNothing();
      }

      await db.insert(userIdentities).values({ userId, providerId: provider.id, externalId, email, rawClaims, lastLoginAt: new Date() });
    }

    const [userRecord] = await db.select({ username: users.username }).from(users).where(eq(users.id, userId)).limit(1);
    const accessToken  = await issueAccessToken(userId, userRecord?.username ?? '');
    const refreshToken = await issueRefreshToken(userId);

    logAuditEvent({ actorId: userId, action: 'sso.login', metadata: { provider: provider.slug }, ipAddress: req.ip });

    return reply.send({ accessToken, refreshToken });
  });

  // ── Admin: manage SSO providers ───────────────────────────────────────────
  app.get('/providers', { preHandler: [requireAuth, requireSuperadmin] }, async (_req, reply) => {
    const providers = await db.select({
      id: ssoProviders.id, name: ssoProviders.name, slug: ssoProviders.slug,
      providerType: ssoProviders.providerType, isEnabled: ssoProviders.isEnabled,
      orgId: ssoProviders.orgId, defaultOrgRole: ssoProviders.defaultOrgRole, createdAt: ssoProviders.createdAt,
    }).from(ssoProviders);
    return reply.send(providers);
  });

  app.post('/providers', { preHandler: [requireAuth, requireSuperadmin] }, async (req, reply) => {
    const parsed = createProviderBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    if (!config.secretEncryptionKey) return reply.status(501).send({ error: 'SECRET_ENCRYPTION_KEY not configured' });

    const { clientSecret, ...rest } = parsed.data;
    const [provider] = await db.insert(ssoProviders).values({
      ...rest,
      clientSecretEncrypted: encryptClientSecret(clientSecret),
    }).returning({ id: ssoProviders.id, name: ssoProviders.name, slug: ssoProviders.slug, createdAt: ssoProviders.createdAt });

    return reply.status(201).send(provider);
  });

  app.patch('/providers/:providerId', { preHandler: [requireAuth, requireSuperadmin] }, async (req, reply) => {
    const { providerId } = req.params as { providerId: string };
    const body = (req.body ?? {}) as Record<string, unknown>;
    const updates: Record<string, unknown> = {};
    if (body['name'])        updates['name']        = body['name'];
    if (body['isEnabled'] !== undefined) updates['isEnabled'] = body['isEnabled'];
    if (body['defaultOrgRole']) updates['defaultOrgRole'] = body['defaultOrgRole'];
    if (body['clientSecret'] && typeof body['clientSecret'] === 'string') {
      updates['clientSecretEncrypted'] = encryptClientSecret(body['clientSecret']);
    }

    const [updated] = await db.update(ssoProviders).set(updates).where(eq(ssoProviders.id, providerId)).returning({ id: ssoProviders.id, name: ssoProviders.name });
    if (!updated) return reply.status(404).send({ error: 'Provider not found' });
    return reply.send(updated);
  });

  app.delete('/providers/:providerId', { preHandler: [requireAuth, requireSuperadmin] }, async (req, reply) => {
    const { providerId } = req.params as { providerId: string };
    await db.delete(ssoProviders).where(eq(ssoProviders.id, providerId));
    return reply.status(204).send();
  });
}
