import type { FastifyRequest, FastifyReply } from 'fastify';

export async function requireSuperadmin(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!req.user) {
    reply.status(401).send({ error: 'Authentication required' });
    return;
  }
  if (!req.user.isSuperadmin) {
    reply.status(403).send({ error: 'Superadmin access required' });
  }
}
