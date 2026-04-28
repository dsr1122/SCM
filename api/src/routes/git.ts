import type { FastifyInstance } from 'fastify';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { organizations, repositories } from '../db/schema.js';
import { optionalAuth } from '../middleware/auth.js';
import { resolveRepoAccess, REPO_ROLE_RANK } from '../middleware/rbac.js';
import { infoRefs, runGitProcess } from '../services/git.service.js';
import { dispatchWebhookEvent } from '../services/webhook.service.js';
import { checkPushAllowed } from '../services/branchProtection.service.js';
import { logAuditEvent } from '../services/audit.service.js';
import { config } from '../config.js';

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
      if (!role || REPO_ROLE_RANK[role] < REPO_ROLE_RANK[requiredRole]) {
        return reply.status(403).send('Forbidden');
      }
    }

    await infoRefs(req, reply, service, repo.diskPath);
  });

  app.post('/git-upload-pack', { preHandler: [optionalAuth], bodyLimit: 536_870_912 }, async (req, reply) => {
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

  app.post('/git-receive-pack', { preHandler: [optionalAuth], bodyLimit: 536_870_912 }, async (req, reply) => {
    const { orgSlug, repoSlug } = req.params as { orgSlug: string; repoSlug: string };
    const repo = await resolveRepo(orgSlug, repoSlug);
    if (!repo) return reply.status(404).send('Repository not found');

    if (!req.user) {
      reply.header('WWW-Authenticate', 'Basic realm="SCM"');
      return reply.status(401).send('Authentication required');
    }

    const { role } = await resolveRepoAccess(req.user.id, repo.id);
    if (!role || role === 'read') return reply.status(403).send('Forbidden');

    const envVars = {
      SCM_REPO_ID: repo.id,
      SCM_USER_ID: req.user.id,
      SCM_INTERNAL_API_URL: `http://127.0.0.1:${config.port}`,
    };

    await runGitProcess(req, reply, 'git-receive-pack', repo.diskPath, true, envVars);

    logAuditEvent({ actorId: req.user.id, actorUsername: req.user.username, action: 'repo.pushed', resourceType: 'repository', resourceId: repo.id, repoId: repo.id, ipAddress: req.ip });

    setImmediate(() => {
      dispatchWebhookEvent(repo.id, 'push', {
        repository: { id: repo.id, slug: repo.slug },
        pusher: { id: req.user!.id, username: req.user!.username },
        ref: 'refs/heads/' + repo.defaultBranch,
      }).catch((err) => req.log.error(err, '[webhook] push dispatch failed'));
    });
  });
}
