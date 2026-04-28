import * as argon2 from 'argon2';
import { SignJWT, importPKCS8, importSPKI } from 'jose';
import { createHash, randomBytes } from 'crypto';
import { db } from '../db/client.js';
import { users, refreshTokens } from '../db/schema.js';
import { eq, and, gt, isNull } from 'drizzle-orm';
import { config } from '../config.js';
import { redis } from '../middleware/rateLimiter.js';

const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
};

let _privateKey: Awaited<ReturnType<typeof importPKCS8>> | null = null;
let _publicKey:  Awaited<ReturnType<typeof importSPKI>>  | null = null;

async function getPrivateKey() {
  if (!_privateKey) _privateKey = await importPKCS8(config.jwtPrivateKey, 'RS256');
  return _privateKey;
}
async function getPublicKey() {
  if (!_publicKey) _publicKey = await importSPKI(config.jwtPublicKey, 'RS256');
  return _publicKey;
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  return argon2.verify(hash, password, ARGON2_OPTIONS);
}

export async function issueAccessToken(userId: string, username: string): Promise<string> {
  const key = await getPrivateKey();
  return new SignJWT({ username })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(`${config.accessTokenTtl}s`)
    .sign(key);
}

export async function issueRefreshToken(userId: string): Promise<string> {
  const raw = randomBytes(48).toString('hex');
  const hash = createHash('sha256').update(raw).digest('hex');

  const expiresAt = new Date(Date.now() + config.refreshTokenTtl * 1000);
  await db.insert(refreshTokens).values({ userId, tokenHash: hash, expiresAt });

  return raw;
}

export async function rotateRefreshToken(
  rawToken: string,
): Promise<{ accessToken: string; refreshToken: string; userId: string } | null> {
  const hash = createHash('sha256').update(rawToken).digest('hex');

  const [stored] = await db
    .select()
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.tokenHash, hash),
        isNull(refreshTokens.revokedAt),
        gt(refreshTokens.expiresAt, new Date()),
      ),
    )
    .limit(1);

  if (!stored) return null;

  // Revoke old token
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(eq(refreshTokens.id, stored.id));

  const [user] = await db
    .select({ id: users.id, username: users.username, isActive: users.isActive })
    .from(users)
    .where(eq(users.id, stored.userId))
    .limit(1);

  if (!user?.isActive) return null;

  const accessToken  = await issueAccessToken(user.id, user.username);
  const refreshToken = await issueRefreshToken(user.id);

  return { accessToken, refreshToken, userId: user.id };
}

export async function revokeAccessToken(token: string): Promise<void> {
  const key = await getPublicKey();
  try {
    const { payload } = await (await import('jose')).jwtVerify(token, key);
    const ttl = (payload.exp ?? 0) - Math.floor(Date.now() / 1000);
    if (ttl > 0) {
      await redis.setex(`blocklist:${token}`, ttl, '1');
    }
  } catch {
    // Already expired — no need to blocklist
  }
}

export async function revokeRefreshTokenForUser(rawToken: string, userId: string): Promise<void> {
  const hash = createHash('sha256').update(rawToken).digest('hex');
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(refreshTokens.tokenHash, hash),
        eq(refreshTokens.userId, userId),
        isNull(refreshTokens.revokedAt),
      ),
    );
}
