import { createHmac, createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { db } from '../db/client.js';
import { webhooks, webhookDeliveries } from '../db/schema.js';
import { eq, and } from 'drizzle-orm';
import { config } from '../config.js';
import type { WebhookEvent } from '../types/index.js';
import { lookup } from 'dns/promises';
import ipaddr from 'ipaddr.js';

// Webhooks store the signing secret encrypted at rest (AES-256-GCM).
// The plaintext is recovered at delivery time and used as the HMAC-SHA256 key,
// matching the standard GitHub-style receiver verification pattern.
export function encryptWebhookSecret(secret: string): string {
  if (!config.secretEncryptionKey) throw new Error('SECRET_ENCRYPTION_KEY not configured — cannot store webhook secret');
  const key = Buffer.from(config.secretEncryptionKey, 'hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('hex'), enc.toString('hex'), tag.toString('hex')].join(':');
}

export function decryptWebhookSecret(ciphertext: string): string {
  if (!config.secretEncryptionKey) throw new Error('SECRET_ENCRYPTION_KEY not configured');
  const key = Buffer.from(config.secretEncryptionKey, 'hex');
  const [ivHex, encHex, tagHex] = ciphertext.split(':');
  if (!ivHex || !encHex || !tagHex) throw new Error('Invalid webhook secret ciphertext');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return decipher.update(Buffer.from(encHex, 'hex')) + decipher.final('utf8');
}

// SHA256 fingerprint — stored alongside the encrypted secret for quick lookup/display.
export function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

export function signPayload(secret: string, body: string): string {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

async function isSafeUrl(urlStr: string): Promise<boolean> {
  try {
    const url = new URL(urlStr);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;

    const hostname = url.hostname;
    // Resolve hostname to IP
    const { address } = await lookup(hostname);
    const addr = ipaddr.parse(address);
    const range = addr.range();

    // Block private, loopback, link-local, etc.
    const unsafeRanges = ['private', 'loopback', 'linkLocal', 'multicast', 'unspecified'];
    if (unsafeRanges.includes(range)) return false;

    return true;
  } catch {
    return false;
  }
}

async function deliverOnce(
  webhookId: string,
  url: string,
  encryptedSecret: string,
  event: WebhookEvent,
  payload: Record<string, unknown>,
): Promise<{ status: number | null; durationMs: number; error?: string }> {
  const start = Date.now();

  if (!(await isSafeUrl(url))) {
    return { status: null, durationMs: Date.now() - start, error: 'Unsafe webhook URL blocked' };
  }

  const body = JSON.stringify(payload);
  let plaintextSecret: string;
  try {
    plaintextSecret = decryptWebhookSecret(encryptedSecret);
  } catch {
    return { status: null, durationMs: Date.now() - start, error: 'Failed to decrypt webhook secret' };
  }
  const signature = signPayload(plaintextSecret, body);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.webhookTimeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SCM-Event': event,
        'X-SCM-Signature-256': signature,
        'User-Agent': 'SCM-Webhook/1.0',
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timer);
    return { status: res.status, durationMs: Date.now() - start };
  } catch (err) {
    clearTimeout(timer);
    return { status: null, durationMs: Date.now() - start, error: String(err) };
  }
}

export async function dispatchWebhookEvent(
  repoId: string,
  event: WebhookEvent,
  payload: Record<string, unknown>,
): Promise<void> {
  const hooks = await db.select()
    .from(webhooks)
    .where(and(eq(webhooks.repoId, repoId), eq(webhooks.isActive, true)));

  for (const hook of hooks) {
    const events = hook.events as WebhookEvent[];
    if (!events.includes(event)) continue;

    let attempt = 0;
    let result = { status: null as number | null, durationMs: 0, error: undefined as string | undefined };

    while (attempt <= config.webhookMaxRetries) {
      result = await deliverOnce(hook.id, hook.url, hook.secretHash, event, payload);
      if (result.error === 'Unsafe webhook URL blocked') break;
      if (result.status && result.status < 500) break;
      attempt++;
      if (attempt <= config.webhookMaxRetries) {
        await new Promise((r) => setTimeout(r, 1000 * 2 ** (attempt - 1))); // exponential backoff
      }
    }

    await db.insert(webhookDeliveries).values({
      webhookId: hook.id,
      event,
      payload,
      responseStatus: result.status ?? undefined,
      durationMs: result.durationMs,
      error: result.error,
    });
  }
}
