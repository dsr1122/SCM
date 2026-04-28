import Redis from 'ioredis';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { config } from '../config.js';

export const redis = new Redis(config.redisUrl, {
  maxRetriesPerRequest: 3,
  enableOfflineQueue: false,
  lazyConnect: false,
});

redis.on('error', (err) => {
  console.error('[redis]', err.message);
});

// Sliding window rate limiter using a sorted set per key.
async function slidingWindow(
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const now = Date.now();
  const windowStart = now - windowSeconds * 1000;
  const resetAt = Math.ceil((now + windowSeconds * 1000) / 1000);

  const pipe = redis.pipeline();
  pipe.zremrangebyscore(key, '-inf', windowStart);
  pipe.zadd(key, now, `${now}-${Math.random()}`);
  pipe.zcard(key);
  pipe.expire(key, windowSeconds * 2);

  const results = await pipe.exec();
  const count = (results?.[2]?.[1] as number) ?? limit + 1;
  const allowed = count <= limit;
  const remaining = Math.max(0, limit - count);

  return { allowed, remaining, resetAt };
}

export function ipRateLimit(limitPerMinute: number) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const ip = req.ip;
    const key = `rl:ip:${ip}`;
    const { allowed, remaining, resetAt } = await slidingWindow(key, limitPerMinute, 60);

    reply.header('X-RateLimit-Limit', limitPerMinute);
    reply.header('X-RateLimit-Remaining', remaining);
    reply.header('X-RateLimit-Reset', resetAt);

    if (!allowed) {
      return reply.status(429).send({ error: 'Rate limit exceeded' });
    }
  };
}

export function userRateLimit(limitPerMinute: number) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!req.user) return;
    const key = `rl:user:${req.user.id}`;
    const { allowed, remaining, resetAt } = await slidingWindow(key, limitPerMinute, 60);

    reply.header('X-RateLimit-Limit', limitPerMinute);
    reply.header('X-RateLimit-Remaining', remaining);
    reply.header('X-RateLimit-Reset', resetAt);

    if (!allowed) {
      return reply.status(429).send({ error: 'Rate limit exceeded' });
    }
  };
}
