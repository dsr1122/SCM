import type { FastifyRequest, FastifyReply } from 'fastify';
import { importSPKI, jwtVerify } from 'jose';
import { createHash } from 'crypto';
import { config } from '../config.js';
import { redis } from './rateLimiter.js';
import type { JwtPayload, AuthenticatedUser } from '../types/index.js';
import { db } from '../db/client.js';
import { users, personalAccessTokens } from '../db/schema.js';
import { eq, and, isNull, gt } from 'drizzle-orm';

let _publicKey: Awaited<ReturnType<typeof importSPKI>> | null = null;

async function getPublicKey() {
  if (!_publicKey) _publicKey = await importSPKI(config.jwtPublicKey, 'RS256');
  return _publicKey;
}

async function resolveUserById(id: string): Promise<AuthenticatedUser | null> {
  const [user] = await db
    .select({ id: users.id, username: users.username, email: users.email, isSuperadmin: users.isSuperadmin, isActive: users.isActive })
    .from(users)
    .where(eq(users.id, id))
    .limit(1);
  if (!user?.isActive) return null;
  return { id: user.id, username: user.username, email: user.email, isSuperadmin: user.isSuperadmin };
}

async function tryJwtAuth(token: string): Promise<AuthenticatedUser | null> {
  const revoked = await redis.get(`blocklist:${token}`);
  if (revoked) return null;

  try {
    const pubKey = await getPublicKey();
    const { payload: p } = await jwtVerify(token, pubKey, { algorithms: ['RS256'] });
    const payload = p as unknown as JwtPayload;
    return resolveUserById(payload.sub);
  } catch {
    return null;
  }
}

async function tryPatAuth(token: string): Promise<AuthenticatedUser | null> {
  if (!token.startsWith('scm_')) return null;
  const hash = createHash('sha256').update(token).digest('hex');

  const [pat] = await db
    .select({ userId: personalAccessTokens.userId, revokedAt: personalAccessTokens.revokedAt, expiresAt: personalAccessTokens.expiresAt })
    .from(personalAccessTokens)
    .where(and(eq(personalAccessTokens.tokenHash, hash), isNull(personalAccessTokens.revokedAt)))
    .limit(1);

  if (!pat) return null;
  if (pat.expiresAt && pat.expiresAt < new Date()) return null;

  // Update last_used_at async
  setImmediate(() => {
    db.update(personalAccessTokens)
      .set({ lastUsedAt: new Date() })
      .where(eq(personalAccessTokens.tokenHash, hash))
      .catch(() => undefined);
  });

  return resolveUserById(pat.userId);
}

export async function requireAuth(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return reply.status(401).send({ error: 'Missing or invalid Authorization header' });
  }

  const token = header.slice(7);
  const user = (await tryJwtAuth(token)) ?? (await tryPatAuth(token));

  if (!user) {
    return reply.status(401).send({ error: 'Invalid or expired token' });
  }

  req.user = user;
}

// Extracts a token from either Bearer or HTTP Basic auth.
// Git clients use Basic with any username and the token as password.
function extractToken(header: string | undefined): string | null {
  if (!header) return null;
  if (header.startsWith('Bearer ')) return header.slice(7);
  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf-8');
    const colonIdx = decoded.indexOf(':');
    if (colonIdx === -1) return null;
    return decoded.slice(colonIdx + 1); // password field carries the token
  }
  return null;
}

export async function optionalAuth(req: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const token = extractToken(req.headers.authorization);
  if (!token) return;
  const user = (await tryJwtAuth(token)) ?? (await tryPatAuth(token));
  if (user) req.user = user;
}
