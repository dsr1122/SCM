import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/client.js';
import { organizations, orgMembers, users } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';
import { requireOrgRole } from '../middleware/rbac.js';
import type { OrgRole } from '../types/index.js';

const createBody = z.object({
  name:        z.string().min(1).max(100),
  slug:        z.string().min(1).max(50).regex(/^[a-z0-9-]+$/),
  description: z.string().max(500).optional(),
}).strict();

const inviteBody = z.object({
  username: z.string(),
  role:     z.enum(['admin', 'member', 'guest']),
}).strict();

export default async function orgRoutes(app: FastifyInstance) {
  // Create org
  app.post('/', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = createBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }

    const existing = await db.select({ id: organizations.id })
      .from(organizations).where(eq(organizations.slug, parsed.data.slug)).limit(1);
    if (existing.length) return reply.status(409).send({ error: 'Slug already taken' });

    const [org] = await db.insert(organizations).values(parsed.data).returning();

    // Creator becomes owner
    await db.insert(orgMembers).values({ orgId: org!.id, userId: req.user!.id, role: 'owner' });

    return reply.status(201).send(org);
  });

  // Get org
  app.get('/:orgId', { preHandler: [requireAuth] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const [org] = await db.select().from(organizations).where(eq(organizations.id, orgId)).limit(1);
    if (!org) return reply.status(404).send({ error: 'Organization not found' });
    return reply.send(org);
  });

  // Update org (admin+)
  app.patch('/:orgId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const parsed = createBody.partial().safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed' });
    }
    const [updated] = await db.update(organizations)
      .set({ ...parsed.data, updatedAt: new Date() })
      .where(eq(organizations.id, orgId))
      .returning();
    return reply.send(updated);
  });

  // Delete org (owner only)
  app.delete('/:orgId', { preHandler: [requireAuth, requireOrgRole('owner')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    await db.delete(organizations).where(eq(organizations.id, orgId));
    return reply.status(204).send();
  });

  // List members
  app.get('/:orgId/members', { preHandler: [requireAuth, requireOrgRole('guest')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const members = await db
      .select({
        userId: orgMembers.userId, role: orgMembers.role,
        username: users.username, email: users.email,
        joinedAt: orgMembers.createdAt,
      })
      .from(orgMembers)
      .innerJoin(users, eq(users.id, orgMembers.userId))
      .where(eq(orgMembers.orgId, orgId));
    return reply.send(members);
  });

  // Invite / add member (admin+)
  app.post('/:orgId/members', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId } = req.params as { orgId: string };
    const parsed = inviteBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed' });
    }

    const [target] = await db.select({ id: users.id })
      .from(users).where(eq(users.username, parsed.data.username)).limit(1);
    if (!target) return reply.status(404).send({ error: 'User not found' });

    await db.insert(orgMembers)
      .values({ orgId, userId: target.id, role: parsed.data.role })
      .onConflictDoUpdate({
        target: [orgMembers.orgId, orgMembers.userId],
        set: { role: parsed.data.role },
      });

    return reply.status(201).send({ userId: target.id, role: parsed.data.role });
  });

  // Update member role (admin+)
  app.patch('/:orgId/members/:userId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId, userId } = req.params as { orgId: string; userId: string };
    const { role } = (req.body ?? {}) as { role?: string };
    const validRoles: OrgRole[] = ['admin', 'member', 'guest'];
    if (!role || !validRoles.includes(role as OrgRole)) {
      return reply.status(400).send({ error: `role must be one of ${validRoles.join(', ')}` });
    }
    await db.update(orgMembers)
      .set({ role })
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));
    return reply.send({ userId, role });
  });

  // Remove member (admin+)
  app.delete('/:orgId/members/:userId', { preHandler: [requireAuth, requireOrgRole('admin')] }, async (req, reply) => {
    const { orgId, userId } = req.params as { orgId: string; userId: string };
    await db.delete(orgMembers)
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));
    return reply.status(204).send();
  });
}
