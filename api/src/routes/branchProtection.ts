import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { branchProtectionRules } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireRepoAccess } from '../middleware/rbac.js';
import { logAuditEvent } from '../services/audit.service.js';

const createBody = z.object({
  pattern:              z.string().min(1).max(200),
  requirePullRequest:   z.boolean().default(true),
  requiredApprovals:    z.number().int().min(0).max(10).default(1),
  dismissStaleReviews:  z.boolean().default(false),
  restrictPushers:      z.boolean().default(false),
  allowedPusherIds:     z.array(z.string().uuid()).default([]),
  blockForcePush:       z.boolean().default(true),
  requireLinearHistory: z.boolean().default(false),
}).strict();

export default async function branchProtectionRoutes(app: FastifyInstance) {
  app.get('/', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const rules = await db.select().from(branchProtectionRules)
      .where(eq(branchProtectionRules.repoId, repoId));
    return reply.send(rules);
  });

  app.post('/', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const parsed = createBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }
    const [rule] = await db.insert(branchProtectionRules)
      .values({ repoId, ...parsed.data })
      .returning();

    logAuditEvent({
      actorId: req.user!.id, actorUsername: req.user!.username,
      action: 'branch_protection.created', resourceType: 'branch_protection_rule',
      resourceId: rule!.id, repoId,
      metadata: { pattern: parsed.data.pattern },
      ipAddress: req.ip, userAgent: req.headers['user-agent'],
    });

    return reply.status(201).send(rule);
  });

  app.patch('/:ruleId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId, ruleId } = req.params as { repoId: string; ruleId: string };
    const parsed = createBody.partial().safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed' });

    const [updated] = await db.update(branchProtectionRules)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(and(eq(branchProtectionRules.id, ruleId), eq(branchProtectionRules.repoId, repoId)))
      .returning();
    if (!updated) return reply.status(404).send({ error: 'Rule not found' });
    return reply.send(updated);
  });

  app.delete('/:ruleId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId, ruleId } = req.params as { repoId: string; ruleId: string };
    await db.delete(branchProtectionRules)
      .where(and(eq(branchProtectionRules.id, ruleId), eq(branchProtectionRules.repoId, repoId)));

    logAuditEvent({
      actorId: req.user!.id, actorUsername: req.user!.username,
      action: 'branch_protection.deleted', resourceType: 'branch_protection_rule',
      resourceId: ruleId, repoId,
      ipAddress: req.ip, userAgent: req.headers['user-agent'],
    });

    return reply.status(204).send();
  });
}
