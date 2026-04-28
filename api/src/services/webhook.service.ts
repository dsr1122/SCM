import { createHmac, createHash, timingSafeEqual } from 'crypto';
import { db } from '../db/client.js';
import { webhooks, webhookDeliveries } from '../db/schema.js';
import { eq, and } from 'drizzle-orm';
import { config } from '../config.js';
import type { WebhookEvent } from '../types/index.js';
import { lookup } from 'dns/promises';
import ipaddr from 'ipaddr.js';

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
  secret: string,
  event: WebhookEvent,
  payload: Record<string, unknown>,
): Promise<{ status: number | null; durationMs: number; error?: string }> {
  const start = Date.now();

  if (!(await isSafeUrl(url))) {
    return { status: null, durationMs: Date.now() - start, error: 'Unsafe webhook URL blocked' };
  }

  const body = JSON.stringify(payload);
  const signature = signPayload(secret, body);

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
