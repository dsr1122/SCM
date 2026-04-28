import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { db } from '../db/client.js';
import { users } from '../db/schema.js';
import { requireAuth } from '../middleware/auth.js';

const updateBody = z.object({
  email:    z.string().email().max(255).optional(),
  password: z.string().min(10).max(128).optional(),
}).strict();

export default async function userRoutes(app: FastifyInstance) {
  app.get('/me', { preHandler: [requireAuth] }, async (req, reply) => {
    const [user] = await db
      .select({
        id: users.id, username: users.username, email: users.email,
        isSuperadmin: users.isSuperadmin, createdAt: users.createdAt,
      })
      .from(users)
      .where(eq(users.id, req.user!.id))
      .limit(1);

    if (!user) return reply.status(404).send({ error: 'User not found' });
    return reply.send(user);
  });

  app.get('/:username', { preHandler: [requireAuth] }, async (req, reply) => {
    const { username } = req.params as { username: string };
    const [user] = await db
      .select({ id: users.id, username: users.username, createdAt: users.createdAt })
      .from(users)
      .where(eq(users.username, username))
      .limit(1);

    if (!user) return reply.status(404).send({ error: 'User not found' });
    return reply.send(user);
  });

  app.patch('/me', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = updateBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation failed', details: parsed.error.flatten() });
    }
    const updates: Partial<{ email: string; passwordHash: string; updatedAt: Date }> = {
      updatedAt: new Date(),
    };

    if (parsed.data.email) updates.email = parsed.data.email;
    if (parsed.data.password) {
      const { hashPassword } = await import('../services/auth.service.js');
      updates.passwordHash = await hashPassword(parsed.data.password);
    }

    const [updated] = await db
      .update(users)
      .set(updates)
      .where(eq(users.id, req.user!.id))
      .returning({ id: users.id, username: users.username, email: users.email, updatedAt: users.updatedAt });

    return reply.send(updated);
  });
}
