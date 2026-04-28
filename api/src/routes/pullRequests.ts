import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and, desc } from 'drizzle-orm';
import { db } from '../db/client.js';
import { pullRequests, prReviews, prComments, users } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireRepoAccess } from '../middleware/rbac.js';
import { nextPrNumber, mergePullRequest } from '../services/pr.service.js';
import { dispatchWebhookEvent } from '../services/webhook.service.js';
import { logAuditEvent } from '../services/audit.service.js';
import { notifyPrReviewSubmitted, notifyPrCommentAdded, notifyPrMergedOrClosed } from '../services/email.service.js';

const createPrBody = z.object({
  title:        z.string().min(1).max(255),
  body:         z.string().max(65535).default(''),
  sourceBranch: z.string().min(1).max(255),
  targetBranch: z.string().min(1).max(255),
}).strict();

const reviewBody = z.object({
  state: z.enum(['approved', 'changes_requested', 'commented']),
  body:  z.string().max(65535).default(''),
}).strict();

const commentBody = z.object({
  body:      z.string().min(1).max(65535),
  reviewId:  z.string().uuid().optional(),
  commitSha: z.string().max(40).optional(),
  path:      z.string().max(500).optional(),
  line:      z.number().int().positive().optional(),
}).strict();

export default async function prRoutes(app: FastifyInstance) {
  // List PRs
  app.get('/', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const query = req.query as Record<string, string>;
    const status = query['status'] ?? 'open';

    const rows = await db
      .select({
        id: pullRequests.id, number: pullRequests.number,
        title: pullRequests.title, status: pullRequests.status,
        sourceBranch: pullRequests.sourceBranch, targetBranch: pullRequests.targetBranch,
        authorId: pullRequests.authorId, createdAt: pullRequests.createdAt,
      })
      .from(pullRequests)
      .where(and(eq(pullRequests.repoId, repoId), eq(pullRequests.status, status)))
      .orderBy(desc(pullRequests.createdAt));

    return reply.send(rows);
  });

  // Create PR
  app.post('/', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const parsed = createPrBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    const number = await nextPrNumber(repoId);
    const [pr] = await db.insert(pullRequests).values({
      repoId,
      number,
      authorId: req.user!.id,
      ...parsed.data,
    }).returning();

    setImmediate(() => {
      dispatchWebhookEvent(repoId, 'pull_request', { action: 'opened', pullRequest: pr }).catch(() => undefined);
    });
    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'pr.opened', resourceType: 'pull_request', resourceId: pr!.id, repoId, metadata: { title: parsed.data.title }, ipAddress: req.ip });

    return reply.status(201).send(pr);
  });

  // Get PR
  app.get('/:prId', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const [pr] = await db.select().from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (!pr) return reply.status(404).send({ error: 'Pull request not found' });
    return reply.send(pr);
  });

  // Update PR (author or admin)
  app.patch('/:prId', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const [pr] = await db.select().from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (!pr) return reply.status(404).send({ error: 'Pull request not found' });

    const isAuthor = pr.authorId === req.user!.id;
    if (!isAuthor && !req.user!.isSuperadmin) {
      return reply.status(403).send({ error: 'Only the PR author can edit it' });
    }

    const { title, body } = (req.body ?? {}) as { title?: string; body?: string };
    const [updated] = await db.update(pullRequests)
      .set({ ...(title && { title }), ...(body !== undefined && { body }), updatedAt: new Date() })
      .where(eq(pullRequests.id, prId))
      .returning();

    return reply.send(updated);
  });

  // Close PR
  app.post('/:prId/close', { preHandler: [requireAuth, requireRepoAccess('write')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const [pr] = await db.select().from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (!pr || pr.status !== 'open') {
      return reply.status(400).send({ error: 'PR is not open' });
    }
    const [updated] = await db.update(pullRequests)
      .set({ status: 'closed', updatedAt: new Date() })
      .where(eq(pullRequests.id, prId))
      .returning();

    logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'pr.closed', resourceType: 'pull_request', resourceId: prId, repoId: pr.repoId, ipAddress: req.ip });
    notifyPrMergedOrClosed(pr.authorId, req.user!.username, pr.title, `/repos/${pr.repoId}/pulls/${prId}`, 'closed');

    return reply.send(updated);
  });

  // Merge PR (write+)
  app.post('/:prId/merge', { preHandler: [requireAuth, requireRepoAccess('write')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const [pr] = await db.select().from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (!pr) return reply.status(404).send({ error: 'Pull request not found' });
    if (pr.status !== 'open') return reply.status(400).send({ error: `PR is already ${pr.status}` });

    const [actor] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.user!.id)).limit(1);

    try {
      const result = await mergePullRequest(prId, req.user!.username, actor?.email ?? '');
      logAuditEvent({ actorId: req.user!.id, actorUsername: req.user!.username, action: 'pr.merged', resourceType: 'pull_request', resourceId: prId, repoId: pr.repoId, metadata: { sha: result.sha, strategy: result.strategy }, ipAddress: req.ip });
      notifyPrMergedOrClosed(pr.authorId, req.user!.username, pr.title, `/repos/${pr.repoId}/pulls/${prId}`, 'merged');
      return reply.send({ merged: true, sha: result.sha, strategy: result.strategy });
    } catch (err) {
      return reply.status(422).send({ error: String(err) });
    }
  });

  // Submit review
  app.post('/:prId/reviews', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const parsed = reviewBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed' });
    }

    const [pr] = await db.select({ status: pullRequests.status })
      .from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (!pr || pr.status !== 'open') return reply.status(400).send({ error: 'PR is not open' });

    const [review] = await db.insert(prReviews).values({
      prId,
      reviewerId: req.user!.id,
      state: parsed.data.state,
      body: parsed.data.body,
    }).returning();

    const [prRecord] = await db.select({ authorId: pullRequests.authorId, title: pullRequests.title, repoId: pullRequests.repoId }).from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (prRecord) {
      notifyPrReviewSubmitted(prRecord.authorId, req.user!.username, prRecord.title, `/repos/${prRecord.repoId}/pulls/${prId}`);
    }

    return reply.status(201).send(review);
  });

  // List reviews
  app.get('/:prId/reviews', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const reviews = await db.select().from(prReviews)
      .where(eq(prReviews.prId, prId))
      .orderBy(desc(prReviews.submittedAt));
    return reply.send(reviews);
  });

  // Add comment
  app.post('/:prId/comments', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const parsed = commentBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    const [comment] = await db.insert(prComments).values({
      prId,
      authorId: req.user!.id,
      ...parsed.data,
    }).returning();

    const [prRecord] = await db.select({ authorId: pullRequests.authorId, title: pullRequests.title, repoId: pullRequests.repoId }).from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
    if (prRecord && prRecord.authorId !== req.user!.id) {
      notifyPrCommentAdded(prRecord.authorId, req.user!.username, prRecord.title, `/repos/${prRecord.repoId}/pulls/${prId}`);
    }

    return reply.status(201).send(comment);
  });

  // List comments
  app.get('/:prId/comments', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { prId } = req.params as { prId: string };
    const comments = await db.select().from(prComments)
      .where(eq(prComments.prId, prId))
      .orderBy(prComments.createdAt);
    return reply.send(comments);
  });
}
