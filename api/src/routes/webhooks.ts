import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and, desc } from 'drizzle-orm';
import { db } from '../db/client.js';
import { webhooks, webhookDeliveries } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireRepoAccess } from '../middleware/rbac.js';
import { encryptWebhookSecret } from '../services/webhook.service.js';
import type { WebhookEvent } from '../types/index.js';

const VALID_EVENTS: WebhookEvent[] = ['push', 'pull_request'];

const createBody = z.object({
  url:    z.string().url().max(500),
  secret: z.string().min(16).max(256),
  events: z.array(z.enum(['push', 'pull_request'])).min(1).default(['push', 'pull_request']),
}).strict();

export default async function webhookRoutes(app: FastifyInstance) {
  // List webhooks (admin+)
  app.get('/', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const hooks = await db.select({
      id: webhooks.id, url: webhooks.url,
      events: webhooks.events, isActive: webhooks.isActive, createdAt: webhooks.createdAt,
    }).from(webhooks).where(eq(webhooks.repoId, repoId));
    return reply.send(hooks);
  });

  // Create webhook (admin+)
  app.post('/', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const parsed = createBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    const [hook] = await db.insert(webhooks).values({
      repoId,
      url:        parsed.data.url,
      secretHash: encryptWebhookSecret(parsed.data.secret),
      events:     parsed.data.events,
    }).returning({ id: webhooks.id, url: webhooks.url, events: webhooks.events, createdAt: webhooks.createdAt });

    return reply.status(201).send(hook);
  });

  // Get webhook (admin+)
  app.get('/:hookId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId, hookId } = req.params as { repoId: string; hookId: string };
    const [hook] = await db.select({
      id: webhooks.id, url: webhooks.url,
      events: webhooks.events, isActive: webhooks.isActive, createdAt: webhooks.createdAt,
    })
      .from(webhooks)
      .where(and(eq(webhooks.id, hookId), eq(webhooks.repoId, repoId)))
      .limit(1);
    if (!hook) return reply.status(404).send({ error: 'Webhook not found' });
    return reply.send(hook);
  });

  // Update webhook (admin+)
  app.patch('/:hookId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId, hookId } = req.params as { repoId: string; hookId: string };
    const body = (req.body ?? {}) as {
      url?: string; secret?: string;
      events?: WebhookEvent[]; isActive?: boolean;
    };

    const updates: Record<string, unknown> = {};
    if (body.url)      updates['url']        = body.url;
    if (body.secret)   updates['secretHash'] = encryptWebhookSecret(body.secret);
    if (body.events)   updates['events']     = body.events.filter((e) => VALID_EVENTS.includes(e));
    if (body.isActive !== undefined) updates['isActive'] = body.isActive;

    const [updated] = await db.update(webhooks)
      .set(updates)
      .where(and(eq(webhooks.id, hookId), eq(webhooks.repoId, repoId)))
      .returning({ id: webhooks.id, url: webhooks.url, events: webhooks.events, isActive: webhooks.isActive });

    if (!updated) return reply.status(404).send({ error: 'Webhook not found' });
    return reply.send(updated);
  });

  // Delete webhook (admin+)
  app.delete('/:hookId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId, hookId } = req.params as { repoId: string; hookId: string };
    await db.delete(webhooks).where(and(eq(webhooks.id, hookId), eq(webhooks.repoId, repoId)));
    return reply.status(204).send();
  });

  // List deliveries (admin+)
  app.get('/:hookId/deliveries', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { hookId } = req.params as { hookId: string };
    const query = req.query as Record<string, string>;
    const limit = Math.min(parseInt(query['limit'] ?? '50', 10), 200);

    const deliveries = await db.select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.webhookId, hookId))
      .orderBy(desc(webhookDeliveries.createdAt))
      .limit(limit);

    return reply.send(deliveries);
  });
}
