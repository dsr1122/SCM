-- Idempotent schema initialisation (run at container start via Postgres init scripts)
-- Drizzle migrations are the authoritative source; this file is for cold-start bootstrap.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  username      TEXT        NOT NULL UNIQUE,
  email         TEXT        NOT NULL UNIQUE,
  password_hash TEXT        NOT NULL,
  is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
  is_superadmin BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS users_email_idx    ON users(email);
CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);

-- ── Refresh tokens ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT        NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens(user_id);

-- ── Organizations ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT        NOT NULL,
  slug        TEXT        NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Org members ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_members (
  org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('owner','admin','member','guest')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user_idx ON org_members(user_id);

-- ── Repositories ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS repositories (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  owner_id       UUID        NOT NULL REFERENCES users(id),
  name           TEXT        NOT NULL,
  slug           TEXT        NOT NULL,
  description    TEXT,
  is_private     BOOLEAN     NOT NULL DEFAULT TRUE,
  default_branch TEXT        NOT NULL DEFAULT 'main',
  disk_path      TEXT        NOT NULL UNIQUE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, slug)
);
CREATE INDEX IF NOT EXISTS repos_org_slug_idx ON repositories(org_id, slug);

-- ── Repo collaborators ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS repo_collaborators (
  repo_id    UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id)        ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('admin','write','read')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (repo_id, user_id)
);

-- ── Pull requests ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pull_requests (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id          UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  number           INTEGER     NOT NULL,
  author_id        UUID        NOT NULL REFERENCES users(id),
  title            TEXT        NOT NULL,
  body             TEXT        NOT NULL DEFAULT '',
  source_branch    TEXT        NOT NULL,
  target_branch    TEXT        NOT NULL,
  status           TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','merged')),
  merged_commit_sha TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (repo_id, number)
);
CREATE INDEX IF NOT EXISTS pr_repo_idx ON pull_requests(repo_id, number);

-- ── PR reviews ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pr_reviews (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  pr_id        UUID        NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
  reviewer_id  UUID        NOT NULL REFERENCES users(id),
  state        TEXT        NOT NULL CHECK (state IN ('approved','changes_requested','commented')),
  body         TEXT        NOT NULL DEFAULT '',
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS pr_reviews_pr_idx ON pr_reviews(pr_id);

-- ── PR comments ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pr_comments (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  pr_id      UUID        NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
  review_id  UUID        REFERENCES pr_reviews(id) ON DELETE SET NULL,
  author_id  UUID        NOT NULL REFERENCES users(id),
  body       TEXT        NOT NULL,
  commit_sha TEXT,
  path       TEXT,
  line       INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS pr_comments_pr_idx ON pr_comments(pr_id);

-- ── Webhooks ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id     UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  url         TEXT        NOT NULL,
  secret_hash TEXT        NOT NULL,
  events      JSONB       NOT NULL DEFAULT '["push","pull_request"]',
  is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS webhooks_repo_idx ON webhooks(repo_id);

-- ── Webhook deliveries ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id      UUID        NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event           TEXT        NOT NULL,
  payload         JSONB       NOT NULL,
  response_status INTEGER,
  duration_ms     INTEGER,
  error           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_webhook_idx ON webhook_deliveries(webhook_id, created_at DESC);
