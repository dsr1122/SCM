import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import * as argon2 from 'argon2';
import { db } from '../db/client.js';
import { userTotp } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { config } from '../config.js';

// Lazy imports to avoid loading at startup when 2FA not configured
async function getOTPAuth() {
  return import('otpauth');
}

function encryptSecret(plaintext: string): string {
  if (!config.totpEncryptionKey) throw new Error('TOTP_ENCRYPTION_KEY is not configured');
  const key = Buffer.from(config.totpEncryptionKey, 'hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('hex'), encrypted.toString('hex'), tag.toString('hex')].join(':');
}

function decryptSecret(ciphertext: string): string {
  if (!config.totpEncryptionKey) throw new Error('TOTP_ENCRYPTION_KEY is not configured');
  const key = Buffer.from(config.totpEncryptionKey, 'hex');
  const [ivHex, encHex, tagHex] = ciphertext.split(':');
  if (!ivHex || !encHex || !tagHex) throw new Error('Invalid ciphertext format');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted) + decipher.final('utf8');
}

export async function setupTotp(userId: string, username: string): Promise<{ secret: string; otpauthUrl: string }> {
  const { TOTP, Secret } = await getOTPAuth();
  const secretObj = new Secret({ size: 20 });
  const plainSecret = secretObj.base32;

  const totp = new TOTP({ issuer: 'SCM', label: username, algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
  const otpauthUrl = totp.toString();

  const encryptedSecret = encryptSecret(plainSecret);

  await db.insert(userTotp)
    .values({ userId, secret: encryptedSecret, isEnabled: false, backupCodes: [] })
    .onConflictDoUpdate({ target: [userTotp.userId], set: { secret: encryptedSecret, isEnabled: false, backupCodes: [] } });

  return { secret: plainSecret, otpauthUrl };
}

export async function confirmTotp(userId: string, code: string): Promise<string[]> {
  const [record] = await db.select().from(userTotp).where(eq(userTotp.userId, userId)).limit(1);
  if (!record) throw new Error('2FA setup not initiated');

  const { TOTP, Secret } = await getOTPAuth();
  const plainSecret = decryptSecret(record.secret);
  const totp = new TOTP({ issuer: 'SCM', algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(plainSecret) });

  const delta = totp.validate({ token: code, window: 1 });
  if (delta === null) throw new Error('Invalid TOTP code');

  // Generate 10 backup codes
  const rawCodes = Array.from({ length: 10 }, () => randomBytes(4).toString('hex').toUpperCase());
  const hashedCodes = await Promise.all(rawCodes.map((c) => argon2.hash(c, { type: argon2.argon2id })));

  await db.update(userTotp).set({ isEnabled: true, backupCodes: hashedCodes }).where(eq(userTotp.userId, userId));

  return rawCodes;
}

export async function verifyTotpCode(userId: string, code: string): Promise<boolean> {
  const [record] = await db.select().from(userTotp).where(eq(userTotp.userId, userId)).limit(1);
  if (!record?.isEnabled) return false;

  const { TOTP, Secret } = await getOTPAuth();
  const plainSecret = decryptSecret(record.secret);
  const totp = new TOTP({ issuer: 'SCM', algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(plainSecret) });
  const delta = totp.validate({ token: code, window: 1 });
  if (delta !== null) return true;

  // Try backup codes
  const backupCodes = record.backupCodes as string[];
  for (let i = 0; i < backupCodes.length; i++) {
    const hash = backupCodes[i]!;
    const valid = await argon2.verify(hash, code, { type: argon2.argon2id });
    if (valid) {
      // Consume the backup code
      const remaining = backupCodes.filter((_, idx) => idx !== i);
      await db.update(userTotp).set({ backupCodes: remaining }).where(eq(userTotp.userId, userId));
      return true;
    }
  }

  return false;
}

export async function disableTotp(userId: string): Promise<void> {
  await db.update(userTotp).set({ isEnabled: false, backupCodes: [] }).where(eq(userTotp.userId, userId));
}

export async function isTotpEnabled(userId: string): Promise<boolean> {
  const [record] = await db.select({ isEnabled: userTotp.isEnabled }).from(userTotp).where(eq(userTotp.userId, userId)).limit(1);
  return record?.isEnabled ?? false;
}
