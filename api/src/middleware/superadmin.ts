import type { FastifyRequest, FastifyReply } from 'fastify';

export async function requireSuperadmin(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!req.user) {
    return reply.status(401).send({ error: 'Authentication required' });
  }
  if (!req.user.isSuperadmin) {
    return reply.status(403).send({ error: 'Superadmin access required' });
  }
}
