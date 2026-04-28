import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { repositories, repoCollaborators, users } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireOrgRole, requireRepoAccess } from '../middleware/rbac.js';
import { initBareRepo, deleteBareRepo, repoDiskPath, listBranches, listTags, getCommits } from '../services/repo.service.js';
import type { RepoRole } from '../types/index.js';

const createBody = z.object({
  name:          z.string().min(1).max(100),
  slug:          z.string().min(1).max(50).regex(/^[a-z0-9_-]+$/),
  description:   z.string().max(500).optional(),
  isPrivate:     z.boolean().default(true),
  defaultBranch: z.string().max(100).default('main'),
}).strict();

export default async function repoRoutes(app: FastifyInstance) {
  // List repos in org
  app.get('/', { preHandler: [requireAuth] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const rows = await db
      .select({
        id: repositories.id, slug: repositories.slug, name: repositories.name,
        description: repositories.description, isPrivate: repositories.isPrivate,
        defaultBranch: repositories.defaultBranch, createdAt: repositories.createdAt,
      })
      .from(repositories)
      .where(eq(repositories.orgId, orgId));
    return reply.send(rows);
  });

  // Create repo (org member+)
  app.post('/', { preHandler: [requireAuth, requireOrgRole('member')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const parsed = createBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    const existing = await db.select({ id: repositories.id })
      .from(repositories)
      .where(and(eq(repositories.orgId, orgId), eq(repositories.slug, parsed.data.slug)))
      .limit(1);
    if (existing.length) return reply.status(409).send({ error: 'Repository slug already exists in this org' });

    const repoId = crypto.randomUUID();
    const diskPath = repoDiskPath(repoId);
    await initBareRepo(repoId, diskPath);

    const [repo] = await db.insert(repositories).values({
      ...parsed.data,
      id: repoId,
      orgId,
      ownerId: req.user!.id,
      diskPath,
    }).returning();

    return reply.status(201).send(repo);
  });

  // Get repo
  app.get('/:repoId', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const [repo] = await db.select().from(repositories).where(eq(repositories.id, repoId)).limit(1);
    if (!repo) return reply.status(404).send({ error: 'Repository not found' });
    return reply.send(repo);
  });

  // Update repo (admin+)
  app.patch('/:repoId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const parsed = createBody.partial().safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed' });
    const [updated] = await db.update(repositories)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(eq(repositories.id, repoId))
      .returning();
    return reply.send(updated);
  });

  // Delete repo (admin+)
  app.delete('/:repoId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const [repo] = await db.select({ diskPath: repositories.diskPath })
      .from(repositories).where(eq(repositories.id, repoId)).limit(1);
    if (!repo) return reply.status(404).send({ error: 'Repository not found' });

    await db.delete(repositories).where(eq(repositories.id, repoId));
    await deleteBareRepo(repo.diskPath);
    return reply.status(204).send();
  });

  // List branches
  app.get('/:repoId/branches', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const [repo] = await db.select({ diskPath: repositories.diskPath })
      .from(repositories).where(eq(repositories.id, repoId)).limit(1);
    if (!repo) return reply.status(404).send({ error: 'Not found' });
    const branches = await listBranches(repo.diskPath);
    return reply.send(branches);
  });

  // List tags
  app.get('/:repoId/tags', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const [repo] = await db.select({ diskPath: repositories.diskPath })
      .from(repositories).where(eq(repositories.id, repoId)).limit(1);
    if (!repo) return reply.status(404).send({ error: 'Not found' });
    const tags = await listTags(repo.diskPath);
    return reply.send(tags);
  });

  // Commits on a branch
  app.get('/:repoId/commits', { preHandler: [requireAuth, requireRepoAccess('read')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const query = req.query as Record<string, string>;
    const rawBranch = query['branch'] ?? 'main';
    // Reject branch names that look like flags or contain path separators
    if (!/^[a-zA-Z0-9_./-]{1,255}$/.test(rawBranch) || rawBranch.startsWith('-')) {
      return reply.status(400).send({ error: 'Invalid branch name' });
    }
    const branch = rawBranch;
    const limit  = Math.min(parseInt(query['limit']  ?? '30', 10), 100);
    const offset = parseInt(query['offset'] ?? '0', 10);

    const [repo] = await db.select({ diskPath: repositories.diskPath })
      .from(repositories).where(eq(repositories.id, repoId)).limit(1);
    if (!repo) return reply.status(404).send({ error: 'Not found' });

    const commits = await getCommits(repo.diskPath, branch, limit, offset);
    return reply.send(commits);
  });

  // Add collaborator (admin+)
  app.post('/:repoId/collaborators', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId } = req.params as { repoId: string };
    const { username, role } = (req.body ?? {}) as { username?: string; role?: string };
    const validRoles: RepoRole[] = ['admin', 'write', 'read'];
    if (!username || !role || !validRoles.includes(role as RepoRole)) {
      return reply.status(400).send({ error: 'username and role (admin|write|read) required' });
    }

    const [target] = await db.select({ id: users.id }).from(users).where(eq(users.username, username)).limit(1);
    if (!target) return reply.status(404).send({ error: 'User not found' });

    await db.insert(repoCollaborators)
      .values({ repoId, userId: target.id, role })
      .onConflictDoUpdate({
        target: [repoCollaborators.repoId, repoCollaborators.userId],
        set: { role },
      });

    return reply.status(201).send({ userId: target.id, role });
  });

  // Remove collaborator (admin+)
  app.delete('/:repoId/collaborators/:userId', { preHandler: [requireAuth, requireRepoAccess('admin')] }, async (req, reply) => {
    const { repoId, userId } = req.params as { repoId: string; userId: string };
    await db.delete(repoCollaborators)
      .where(and(eq(repoCollaborators.repoId, repoId), eq(repoCollaborators.userId, userId)));
    return reply.status(204).send();
  });
}
