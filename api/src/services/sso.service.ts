import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';
import { lookup } from 'dns/promises';
import ipaddr from 'ipaddr.js';
import { config } from '../config.js';

export function encryptClientSecret(plaintext: string): string {
  if (!config.secretEncryptionKey) throw new Error('SECRET_ENCRYPTION_KEY is not configured');
  const key = Buffer.from(config.secretEncryptionKey, 'hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('hex'), encrypted.toString('hex'), tag.toString('hex')].join(':');
}

export function decryptClientSecret(ciphertext: string): string {
  if (!config.secretEncryptionKey) throw new Error('SECRET_ENCRYPTION_KEY is not configured');
  const key = Buffer.from(config.secretEncryptionKey, 'hex');
  const [ivHex, encHex, tagHex] = ciphertext.split(':');
  if (!ivHex || !encHex || !tagHex) throw new Error('Invalid ciphertext format');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted) + decipher.final('utf8');
}

// Generate PKCE code verifier + challenge
export function generatePkce(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function generateState(): string {
  return randomBytes(16).toString('hex');
}

export async function isSafeExternalUrl(urlStr: string): Promise<boolean> {
  try {
    const url = new URL(urlStr);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
    const { address } = await lookup(url.hostname);
    const range = ipaddr.parse(address).range();
    const blocked = ['private', 'loopback', 'linkLocal', 'multicast', 'unspecified'];
    return !blocked.includes(range);
  } catch {
    return false;
  }
}
