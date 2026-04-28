import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { importPKCS8, SignJWT } from 'jose';
import { setupTotp, confirmTotp, verifyTotpCode, disableTotp, isTotpEnabled } from '../services/twoFactor.service.js';
import { verifyPassword } from '../services/auth.service.js';
import { requireAuth } from '../middleware/auth.js';
import { ipRateLimit } from '../middleware/rateLimiter.js';
import { logAuditEvent } from '../services/audit.service.js';
import { config } from '../config.js';
import { db } from '../db/client.js';
import { users } from '../db/schema.js';
import { eq } from 'drizzle-orm';

const verifyBody = z.object({ code: z.string().min(4).max(10) }).strict();
const disableBody = z.object({ password: z.string(), code: z.string() }).strict();

// Issues a short-lived (5 min) "2fa_pending" JWT used only to call /auth/2fa/verify
async function issue2faPendingToken(userId: string): Promise<string> {
  const key = await importPKCS8(config.jwtPrivateKey, 'RS256');
  return new SignJWT({ scope: '2fa_pending' })
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);
}

export { issue2faPendingToken };

export default async function twoFactorRoutes(app: FastifyInstance) {
  // Initiate 2FA setup — returns secret + otpauthUrl (and optional QR code PNG)
  app.post('/setup', { preHandler: [requireAuth] }, async (req, reply) => {
    if (!config.totpEncryptionKey) {
      return reply.status(501).send({ error: '2FA is not configured on this server (TOTP_ENCRYPTION_KEY missing)' });
    }
    // If 2FA is already active, require the current TOTP code before allowing re-setup.
    // Without this, a stolen access token can silently overwrite the user's authenticator.
    const alreadyEnabled = await isTotpEnabled(req.user!.id);
    if (alreadyEnabled) {
      const { code } = (req.body ?? {}) as { code?: string };
      if (!code) {
        return reply.status(400).send({ error: '2FA is already enabled. Provide your current TOTP code to re-setup.' });
      }
      const valid = await verifyTotpCode(req.user!.id, code);
      if (!valid) {
        return reply.status(401).send({ error: 'Invalid current 2FA code' });
      }
    }
    const { secret, otpauthUrl } = await setupTotp(req.user!.id, req.user!.username);

    let qrCodeDataUrl: string | undefined;
    try {
      const qrcode = await import('qrcode');
      qrCodeDataUrl = await qrcode.default.toDataURL(otpauthUrl);
    } catch {
      // QR code generation is optional
    }

    return reply.send({ secret, otpauthUrl, qrCodeDataUrl });
  });

  // Confirm setup with first TOTP code — returns backup codes (shown once)
  app.post('/confirm', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = verifyBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'code required' });

    let backupCodes: string[];
    try {
      backupCodes = await confirmTotp(req.user!.id, parsed.data.code);
    } catch (err) {
      return reply.status(400).send({ error: String(err) });
    }

    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'user.2fa_enabled', ipAddress: req.ip });
    return reply.send({ message: '2FA enabled. Save these backup codes — they will not be shown again.', backupCodes });
  });

  // Verify TOTP code during login (exchanges 2fa_pending token for full JWT pair)
  app.post('/verify', async (req, reply) => {
    await ipRateLimit(20)(req, reply);
    if (reply.sent) return;

    const parsed = verifyBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'code required' });

    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return reply.status(401).send({ error: 'Missing 2fa_pending token' });

    const pendingToken = header.slice(7);
    let userId: string;
    try {
      const { importSPKI, jwtVerify } = await import('jose');
      const { redis } = await import('../middleware/rateLimiter.js');
      const { createHash } = await import('crypto');
      const tokenHash = createHash('sha256').update(pendingToken).digest('hex');
      // Check blocklist — 2fa_pending tokens must be single-use
      const revoked = await redis.get(`blocklist:${tokenHash}`);
      if (revoked) throw new Error('token revoked');
      const pubKey = await importSPKI(config.jwtPublicKey, 'RS256');
      const { payload } = await jwtVerify(pendingToken, pubKey, { algorithms: ['RS256'] });
      if (payload['scope'] !== '2fa_pending') throw new Error('wrong scope');
      userId = payload.sub as string;
      // Consume the pending token immediately so it cannot be replayed
      const ttl = (payload.exp ?? 0) - Math.floor(Date.now() / 1000);
      if (ttl > 0) await redis.setex(`blocklist:${tokenHash}`, ttl, '1');
    } catch {
      return reply.status(401).send({ error: 'Invalid or expired 2FA session token' });
    }

    const valid = await verifyTotpCode(userId, parsed.data.code);
    if (!valid) return reply.status(401).send({ error: 'Invalid 2FA code' });

    const [user] = await db.select({ username: users.username }).from(users).where(eq(users.id, userId)).limit(1);
    const { issueAccessToken, issueRefreshToken } = await import('../services/auth.service.js');
    const accessToken  = await issueAccessToken(userId, user?.username ?? '');
    const refreshToken = await issueRefreshToken(userId);

    return reply.send({ accessToken, refreshToken });
  });

  // Disable 2FA (requires password + current TOTP code)
  app.post('/disable', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = disableBody.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'password and code required' });

    const [user] = await db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, req.user!.id)).limit(1);
    if (!user) return reply.status(404).send({ error: 'User not found' });

    const pwValid = await verifyPassword(user.passwordHash, parsed.data.password);
    if (!pwValid) return reply.status(401).send({ error: 'Invalid password' });

    const codeValid = await verifyTotpCode(req.user!.id, parsed.data.code);
    if (!codeValid) return reply.status(401).send({ error: 'Invalid 2FA code' });

    await disableTotp(req.user!.id);
    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'user.2fa_disabled', ipAddress: req.ip });
    return reply.send({ message: '2FA disabled' });
  });
}
