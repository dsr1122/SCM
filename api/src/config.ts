import { z } from 'zod';

const schema = z.object({
  NODE_ENV:                    z.enum(['development', 'production', 'test']).default('development'),
  PORT:                        z.coerce.number().int().min(1).max(65535).default(3000),
  HOST:                        z.string().default('0.0.0.0'),
  DATABASE_URL:                z.string().url(),
  REDIS_URL:                   z.string().url(),
  JWT_PRIVATE_KEY_B64:         z.string().min(1),
  JWT_PUBLIC_KEY_B64:          z.string().min(1),
  ACCESS_TOKEN_TTL_SECONDS:    z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_SECONDS:   z.coerce.number().int().positive().default(604800),
  CORS_ORIGINS:                z.string().default('http://localhost'),
  GIT_REPOS_ROOT:              z.string().default('/data/repos'),
  WEBHOOK_TIMEOUT_MS:          z.coerce.number().int().positive().default(10000),
  WEBHOOK_MAX_RETRIES:         z.coerce.number().int().min(0).default(3),
  // 2FA: 32-byte hex key for AES-256-GCM encryption of TOTP secrets
  TOTP_ENCRYPTION_KEY:         z.string().length(64).optional(),
  // SSO
  SSO_CALLBACK_BASE_URL:       z.string().url().default('http://localhost'),
  // Email / SMTP
  SMTP_HOST:                   z.string().optional(),
  SMTP_PORT:                   z.coerce.number().int().default(587),
  SMTP_USER:                   z.string().optional(),
  SMTP_PASS:                   z.string().optional(),
  SMTP_FROM:                   z.string().default('noreply@scm.example.com'),
  SMTP_SECURE:                 z.string().default('false'),
  // Secret encryption key for SSO client secrets (32-byte hex)
  SECRET_ENCRYPTION_KEY:       z.string().length(64).optional(),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('[config] invalid environment variables:\n', parsed.error.format());
  process.exit(1);
}

const env = parsed.data;

export const config = {
  nodeEnv:                  env.NODE_ENV,
  port:                     env.PORT,
  host:                     env.HOST,
  databaseUrl:              env.DATABASE_URL,
  redisUrl:                 env.REDIS_URL,
  jwtPrivateKey:            Buffer.from(env.JWT_PRIVATE_KEY_B64, 'base64').toString('utf-8'),
  jwtPublicKey:             Buffer.from(env.JWT_PUBLIC_KEY_B64, 'base64').toString('utf-8'),
  accessTokenTtl:           env.ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtl:          env.REFRESH_TOKEN_TTL_SECONDS,
  corsOrigins:              env.CORS_ORIGINS.split(',').map((o) => o.trim()),
  gitReposRoot:             env.GIT_REPOS_ROOT,
  webhookTimeoutMs:         env.WEBHOOK_TIMEOUT_MS,
  webhookMaxRetries:        env.WEBHOOK_MAX_RETRIES,
  totpEncryptionKey:        env.TOTP_ENCRYPTION_KEY ?? null,
  ssoCallbackBaseUrl:       env.SSO_CALLBACK_BASE_URL,
  smtp: {
    host:    env.SMTP_HOST ?? null,
    port:    env.SMTP_PORT,
    user:    env.SMTP_USER ?? null,
    pass:    env.SMTP_PASS ?? null,
    from:    env.SMTP_FROM,
    secure:  env.SMTP_SECURE === 'true',
  },
  secretEncryptionKey:      env.SECRET_ENCRYPTION_KEY ?? null,
} as const;
