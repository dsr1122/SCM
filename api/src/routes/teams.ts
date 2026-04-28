import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { teams, teamMembers, teamRepoPermissions, users, repositories } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireOrgRole } from '../middleware/rbac.js';
import type { RepoRole } from '../types/index.js';

const createTeamBody = z.object({
  name:        z.string().min(1).max(100),
  slug:        z.string().min(1).max(50).regex(/^[a-z0-9-]+$/),
  description: z.string().max(500).optional(),
}).strict();

export default async function teamRoutes(app: FastifyInstance) {
  // List teams
  app.get('/', { preHandler: [requireAuth, requireOrgRole('guest')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const rows = await db.select().from(teams).where(eq(teams.orgId, orgId));
    return reply.send(rows);
  });

  // Create team (admin+)
  app.post('/', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const parsed = createTeamBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }
    const [team] = await db.insert(teams).values({ orgId, ...parsed.data }).returning();
    return reply.status(201).send(team);
  });

  // Get team
  app.get('/:teamId', { preHandler: [requireAuth, requireOrgRole('guest')] }, async (req, reply) => {
    const { orgId, teamId } = req.params as { orgId: string; teamId: string };
    const [team] = await db.select().from(teams)
      .where(and(eq(teams.id, teamId), eq(teams.orgId, orgId))).limit(1);
    if (!team) return reply.status(404).send({ error: 'Team not found' });
    return reply.send(team);
  });

  // Update team (admin+)
  app.patch('/:teamId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId, teamId } = req.params as { orgId: string; teamId: string };
    const parsed = createTeamBody.partial().safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'Validation failed' });
    const [updated] = await db.update(teams)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(and(eq(teams.id, teamId), eq(teams.orgId, orgId)))
      .returning();
    if (!updated) return reply.status(404).send({ error: 'Team not found' });
    return reply.send(updated);
  });

  // Delete team (admin+)
  app.delete('/:teamId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId, teamId } = req.params as { orgId: string; teamId: string };
    await db.delete(teams).where(and(eq(teams.id, teamId), eq(teams.orgId, orgId)));
    return reply.status(204).send();
  });

  // ── Team Members ─────────────────────────────────────────────────────────

  app.get('/:teamId/members', { preHandler: [requireAuth, requireOrgRole('guest')] }, async (req, reply) => {
    const { teamId } = req.params as { teamId: string };
    const members = await db
      .select({ userId: teamMembers.userId, role: teamMembers.role, username: users.username, email: users.email })
      .from(teamMembers)
      .innerJoin(users, eq(users.id, teamMembers.userId))
      .where(eq(teamMembers.teamId, teamId));
    return reply.send(members);
  });

  app.post('/:teamId/members', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { teamId } = req.params as { teamId: string };
    const { username, role = 'member' } = (req.body ?? {}) as { username?: string; role?: string };
    if (!username || !['maintainer', 'member'].includes(role)) {
      return reply.status(400).send({ error: 'username and role (maintainer|member) required' });
    }
    const [target] = await db.select({ id: users.id }).from(users).where(eq(users.username, username)).limit(1);
    if (!target) return reply.status(404).send({ error: 'User not found' });

    await db.insert(teamMembers)
      .values({ teamId, userId: target.id, role })
      .onConflictDoUpdate({ target: [teamMembers.teamId, teamMembers.userId], set: { role } });

    return reply.status(201).send({ userId: target.id, role });
  });

  app.delete('/:teamId/members/:userId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { teamId, userId } = req.params as { teamId: string; userId: string };
    await db.delete(teamMembers).where(and(eq(teamMembers.teamId, teamId), eq(teamMembers.userId, userId)));
    return reply.status(204).send();
  });

  // ── Team Repo Permissions ─────────────────────────────────────────────────

  app.get('/:teamId/repos', { preHandler: [requireAuth, requireOrgRole('guest')] }, async (req, reply) => {
    const { teamId } = req.params as { teamId: string };
    const perms = await db
      .select({
        repoId: teamRepoPermissions.repoId, role: teamRepoPermissions.role,
        slug: repositories.slug, name: repositories.name,
      })
      .from(teamRepoPermissions)
      .innerJoin(repositories, eq(repositories.id, teamRepoPermissions.repoId))
      .where(eq(teamRepoPermissions.teamId, teamId));
    return reply.send(perms);
  });

  app.post('/:teamId/repos', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { teamId } = req.params as { teamId: string };
    const { repoId, role } = (req.body ?? {}) as { repoId?: string; role?: string };
    const validRoles: RepoRole[] = ['admin', 'write', 'read'];
    if (!repoId || !role || !validRoles.includes(role as RepoRole)) {
      return reply.status(400).send({ error: 'repoId and role (admin|write|read) required' });
    }
    await db.insert(teamRepoPermissions)
      .values({ teamId, repoId, role })
      .onConflictDoUpdate({ target: [teamRepoPermissions.teamId, teamRepoPermissions.repoId], set: { role } });
    return reply.status(201).send({ teamId, repoId, role });
  });

  app.delete('/:teamId/repos/:repoId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { teamId, repoId } = req.params as { teamId: string; repoId: string };
    await db.delete(teamRepoPermissions)
      .where(and(eq(teamRepoPermissions.teamId, teamId), eq(teamRepoPermissions.repoId, repoId)));
    return reply.status(204).send();
  });
}
