import type { FastifyRequest, FastifyReply } from 'fastify';
import { importSPKI, jwtVerify } from 'jose';
import { config } from '../config.js';
import { redis } from './rateLimiter.js';
import type { JwtPayload, AuthenticatedUser } from '../types/index.js';
import { db } from '../db/client.js';
import { users } from '../db/schema.js';
import { eq } from 'drizzle-orm';

let _publicKey: Awaited<ReturnType<typeof importSPKI>> | null = null;

async function getPublicKey() {
  if (!_publicKey) {
    _publicKey = await importSPKI(config.jwtPublicKey, 'RS256');
  }
  return _publicKey;
}

export async function requireAuth(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    reply.status(401).send({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = header.slice(7);

  const revoked = await redis.get(`blocklist:${token}`);
  if (revoked) {
    reply.status(401).send({ error: 'Token has been revoked' });
    return;
  }

  let payload: JwtPayload;
  try {
    const pubKey = await getPublicKey();
    const { payload: p } = await jwtVerify(token, pubKey, { algorithms: ['RS256'] });
    payload = p as unknown as JwtPayload;
  } catch {
    reply.status(401).send({ error: 'Invalid or expired token' });
    return;
  }

  const [user] = await db
    .select({
      id: users.id,
      username: users.username,
      email: users.email,
      isSuperadmin: users.isSuperadmin,
      isActive: users.isActive,
    })
    .from(users)
    .where(eq(users.id, payload.sub))
    .limit(1);

  if (!user || !user.isActive) {
    reply.status(401).send({ error: 'User not found or inactive' });
    return;
  }

  req.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    isSuperadmin: user.isSuperadmin,
  };
}

export async function optionalAuth(req: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return;

  const token = header.slice(7);
  const revoked = await redis.get(`blocklist:${token}`);
  if (revoked) return;

  try {
    const pubKey = await getPublicKey();
    const { payload: p } = await jwtVerify(token, pubKey, { algorithms: ['RS256'] });
    const payload = p as unknown as JwtPayload;

    const [user] = await db
      .select({
        id: users.id,
        username: users.username,
        email: users.email,
        isSuperadmin: users.isSuperadmin,
        isActive: users.isActive,
      })
      .from(users)
      .where(eq(users.id, payload.sub))
      .limit(1);

    if (user?.isActive) {
      req.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        isSuperadmin: user.isSuperadmin,
      };
    }
  } catch {
    // ignore — optional auth
  }
}
