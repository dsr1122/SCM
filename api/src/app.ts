import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import { config } from './config.js';
import { checkDbConnection } from './db/client.js';
import { redis } from './middleware/rateLimiter.js';

import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import orgRoutes from './routes/orgs.js';
import repoRoutes from './routes/repos.js';
import gitRoutes from './routes/git.js';
import prRoutes from './routes/pullRequests.js';
import webhookRoutes from './routes/webhooks.js';

const app = Fastify({
  logger: {
    level: config.nodeEnv === 'production' ? 'warn' : 'info',
    ...(config.nodeEnv !== 'production' && {
      transport: { target: 'pino-pretty', options: { colorize: true } },
    }),
  },
  requestIdHeader: 'x-request-id',
  requestIdLogLabel: 'requestId',
  trustProxy: true,
  bodyLimit: 536_870_912, // 512 MiB — large git pack files come via body
});

await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31_536_000, includeSubDomains: true },
});

await app.register(cors, {
  origin: config.corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
});

// ── Routes ──────────────────────────────────────────────────────────────────
await app.register(authRoutes,    { prefix: '/auth' });
await app.register(userRoutes,    { prefix: '/users' });
await app.register(orgRoutes,     { prefix: '/orgs' });
await app.register(repoRoutes,    { prefix: '/orgs/:orgId/repos' });
await app.register(gitRoutes,     { prefix: '/:orgSlug/:repoSlug.git' });
await app.register(prRoutes,      { prefix: '/repos/:repoId/pulls' });
await app.register(webhookRoutes, { prefix: '/repos/:repoId/hooks' });

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/health', async (_req, reply) => {
  try {
    await checkDbConnection();
    await redis.ping();
    reply.send({ status: 'ok' });
  } catch (err) {
    reply.status(503).send({ status: 'degraded', error: String(err) });
  }
});

// ── Global error handler ────────────────────────────────────────────────────
app.setErrorHandler((err, _req, reply) => {
  app.log.error(err);
  const status = err.statusCode ?? 500;
  reply.status(status).send({
    error: status < 500 ? err.message : 'Internal server error',
  });
});

app.setNotFoundHandler((_req, reply) => {
  reply.status(404).send({ error: 'Not found' });
});

// ── Start ───────────────────────────────────────────────────────────────────
try {
  await app.listen({ port: config.port, host: config.host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
