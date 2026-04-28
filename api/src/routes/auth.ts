import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { db } from '../db/client.js';
import { users } from '../db/schema.js';
import { eq, or } from 'drizzle-orm';
import {
  hashPassword, verifyPassword,
  issueAccessToken, issueRefreshToken,
  rotateRefreshToken, revokeAccessToken, revokeRefreshTokenForUser,
} from '../services/auth.service.js';
import { isTotpEnabled } from '../services/twoFactor.service.js';
import { issue2faPendingToken } from './twoFactor.js';
import { requireAuth } from '../middleware/auth.js';
import { ipRateLimit } from '../middleware/rateLimiter.js';
import { logAuditEvent } from '../services/audit.service.js';

const registerBody = z.object({
  username: z.string().min(3).max(40).regex(/^[a-zA-Z0-9_-]+$/),
  email:    z.string().email().max(255),
  password: z.string().min(10).max(128),
});

const loginBody = z.object({
  login:    z.string(),
  password: z.string(),
});

const refreshBody = z.object({
  refreshToken: z.string(),
});

export default async function authRoutes(app: FastifyInstance) {
  const strictLimit = ipRateLimit(20);

  app.post('/register', async (req, reply) => {
    await strictLimit(req, reply);
    if (reply.sent) return;

    const parsed = registerBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }
    const { username, email, password } = parsed.data;

    const [existing] = await db
      .select({ id: users.id })
      .from(users)
      .where(or(eq(users.username, username), eq(users.email, email)))
      .limit(1);

    if (existing) {
      return reply.status(409).send({ error: 'Username or email already taken' });
    }

    const passwordHash = await hashPassword(password);
    const [user] = await db
      .insert(users)
      .values({ username, email, passwordHash })
      .returning({ id: users.id, username: users.username, email: users.email, createdAt: users.createdAt });

    logAuditEvent({ actorId: user!.id, actorUsername: user!.username, action: 'user.register', ipAddress: req.ip, userAgent: req.headers['user-agent'] });

    return reply.status(201).send({ user });
  });

  app.post('/login', async (req, reply) => {
    await strictLimit(req, reply);
    if (reply.sent) return;

    const parsed = loginBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed' });

    const { login, password } = parsed.data;
    const [user] = await db
      .select()
      .from(users)
      .where(or(eq(users.username, login), eq(users.email, login)))
      .limit(1);

    // Always run Argon2 to avoid timing-based user enumeration
    const hashToCheck = user?.passwordHash ?? '$argon2id$v=19$m=65536,t=3,p=4$placeholder';
    const valid = user ? await verifyPassword(hashToCheck, password) : false;

    if (!user || !valid || !user.isActive) {
      logAuditEvent({ actorId: user?.id, actorUsername: user?.username, action: 'user.login_failed', metadata: { login }, ipAddress: req.ip, userAgent: req.headers['user-agent'] });
      return reply.status(401).send({ error: 'Invalid credentials' });
    }

    // If 2FA is enabled, return a short-lived pending token instead of full JWT pair
    const totpEnabled = await isTotpEnabled(user.id);
    if (totpEnabled) {
      const sessionToken = await issue2faPendingToken(user.id);
      return reply.send({ requiresTwoFactor: true, sessionToken });
    }

    const accessToken  = await issueAccessToken(user.id, user.username);
    const refreshToken = await issueRefreshToken(user.id);

    logAuditEvent({ actorId: user.id, actorUsername: user.username, action: 'user.login', ipAddress: req.ip, userAgent: req.headers['user-agent'] });

    return reply.send({ accessToken, refreshToken });
  });

  app.post('/refresh', async (req, reply) => {
    await strictLimit(req, reply);
    if (reply.sent) return;

    const parsed = refreshBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Missing refreshToken' });

    const result = await rotateRefreshToken(parsed.data.refreshToken);
    if (!result) return reply.status(401).send({ error: 'Invalid or expired refresh token' });

    return reply.send({ accessToken: result.accessToken, refreshToken: result.refreshToken });
  });

  app.post('/logout', { preHandler: [requireAuth] }, async (req, reply) => {
    const header = req.headers.authorization ?? '';
    const accessToken = header.slice(7);
    const { refreshToken } = (req.body ?? {}) as { refreshToken?: string };

    await revokeAccessToken(accessToken);
    if (refreshToken && req.user) {
      await revokeRefreshTokenForUser(refreshToken, req.user.id);
    }

    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'user.logout', ipAddress: req.ip, userAgent: req.headers['user-agent'] });

    return reply.status(204).send();
  });
}
