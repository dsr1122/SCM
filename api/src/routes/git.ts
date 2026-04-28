import type { FastifyInstance } from 'fastify';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { organizations, repositories } from '../db/schema.js';
import { optionalAuth } from '../middleware/auth.js';
import { resolveRepoAccess } from '../middleware/rbac.js';
import { infoRefs, runGitProcess } from '../services/git.service.js';
import { dispatchWebhookEvent } from '../services/webhook.service.js';

async function resolveRepo(orgSlug: string, repoSlug: string) {
  const [org] = await db.select({ id: organizations.id })
    .from(organizations).where(eq(organizations.slug, orgSlug)).limit(1);
  if (!org) return null;

  const [repo] = await db.select()
    .from(repositories)
    .where(and(eq(repositories.orgId, org.id), eq(repositories.slug, repoSlug)))
    .limit(1);
  return repo ?? null;
}

export default async function gitRoutes(app: FastifyInstance) {
  // GET /:orgSlug/:repoSlug.git/info/refs?service=git-upload-pack|git-receive-pack
  app.get('/info/refs', { preHandler: [optionalAuth] }, async (req, reply) => {
    const { orgSlug, repoSlug } = req.params as { orgSlug: string; repoSlug: string };
    const query = req.query as Record<string, string>;
    const service = query['service'];

    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      return reply.status(400).send('Invalid service');
    }

    const repo = await resolveRepo(orgSlug, repoSlug);
    if (!repo) return reply.status(404).send('Repository not found');

    const requiredRole = service === 'git-receive-pack' ? 'write' : 'read';
    const userId = req.user?.id;

    if (!userId) {
      if (repo.isPrivate || requiredRole === 'write') {
        reply.header('WWW-Authenticate', 'Basic realm="SCM"');
        return reply.status(401).send('Authentication required');
      }
    } else {
      const { role } = await resolveRepoAccess(userId, repo.id);
      const rank = { admin: 3, write: 2, read: 1, null: 0 };
      if ((rank[role ?? 'null'] ?? 0) < rank[requiredRole]) {
        return reply.status(403).send('Forbidden');
      }
    }

    await infoRefs(req, reply, service, repo.diskPath);
  });

  // POST /:orgSlug/:repoSlug.git/git-upload-pack  (fetch/clone)
  app.post('/git-upload-pack', { preHandler: [optionalAuth] }, async (req, reply) => {
    const { orgSlug, repoSlug } = req.params as { orgSlug: string; repoSlug: string };
    const repo = await resolveRepo(orgSlug, repoSlug);
    if (!repo) return reply.status(404).send('Repository not found');

    if (repo.isPrivate) {
      if (!req.user) {
        reply.header('WWW-Authenticate', 'Basic realm="SCM"');
        return reply.status(401).send('Authentication required');
      }
      const { role } = await resolveRepoAccess(req.user.id, repo.id);
      if (!role) return reply.status(403).send('Forbidden');
    }

    await runGitProcess(req, reply, 'git-upload-pack', repo.diskPath, true);
  });

  // POST /:orgSlug/:repoSlug.git/git-receive-pack  (push)
  app.post('/git-receive-pack', { preHandler: [optionalAuth] }, async (req, reply) => {
    const { orgSlug, repoSlug } = req.params as { orgSlug: string; repoSlug: string };
    const repo = await resolveRepo(orgSlug, repoSlug);
    if (!repo) return reply.status(404).send('Repository not found');

    if (!req.user) {
      reply.header('WWW-Authenticate', 'Basic realm="SCM"');
      return reply.status(401).send('Authentication required');
    }

    const { role } = await resolveRepoAccess(req.user.id, repo.id);
    if (!role || role === 'read') return reply.status(403).send('Forbidden');

    await runGitProcess(req, reply, 'git-receive-pack', repo.diskPath, true);

    // Fire-and-forget webhook dispatch
    setImmediate(() => {
      dispatchWebhookEvent(repo.id, 'push', {
        repository: { id: repo.id, slug: repo.slug },
        pusher: { id: req.user!.id, username: req.user!.username },
        ref: 'refs/heads/' + repo.defaultBranch,
      }).catch((err) => req.log.error(err, '[webhook] push dispatch failed'));
    });
  });
}
