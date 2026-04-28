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
  id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id           UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  number            INTEGER     NOT NULL,
  author_id         UUID        NOT NULL REFERENCES users(id),
  title             TEXT        NOT NULL,
  body              TEXT        NOT NULL DEFAULT '',
  source_branch     TEXT        NOT NULL,
  target_branch     TEXT        NOT NULL,
  status            TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','merged')),
  merged_commit_sha TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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

-- ── Audit Log ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id      UUID        REFERENCES users(id) ON DELETE SET NULL,
  actor_username TEXT,
  action        TEXT        NOT NULL,
  resource_type TEXT,
  resource_id   TEXT,
  org_id        UUID        REFERENCES organizations(id) ON DELETE SET NULL,
  repo_id       UUID        REFERENCES repositories(id)  ON DELETE SET NULL,
  metadata      JSONB,
  ip_address    TEXT,
  user_agent    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx   ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS audit_log_action_idx  ON audit_log(action);
CREATE INDEX IF NOT EXISTS audit_log_org_idx     ON audit_log(org_id);
CREATE INDEX IF NOT EXISTS audit_log_repo_idx    ON audit_log(repo_id);
CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log(created_at DESC);

-- ── Branch Protection Rules ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS branch_protection_rules (
  id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id               UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  pattern               TEXT        NOT NULL,
  require_pull_request  BOOLEAN     NOT NULL DEFAULT TRUE,
  required_approvals    INTEGER     NOT NULL DEFAULT 1,
  dismiss_stale_reviews BOOLEAN     NOT NULL DEFAULT FALSE,
  restrict_pushers      BOOLEAN     NOT NULL DEFAULT FALSE,
  allowed_pusher_ids    JSONB       NOT NULL DEFAULT '[]',
  block_force_push      BOOLEAN     NOT NULL DEFAULT TRUE,
  require_linear_history BOOLEAN    NOT NULL DEFAULT FALSE,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS bpr_repo_idx ON branch_protection_rules(repo_id);

-- ── Personal Access Tokens ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS personal_access_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  token_hash  TEXT        NOT NULL UNIQUE,
  prefix      TEXT        NOT NULL,
  scopes      JSONB       NOT NULL DEFAULT '[]',
  expires_at  TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  revoked_at  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS pat_user_idx ON personal_access_tokens(user_id);

-- ── User TOTP (2FA) ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_totp (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  secret      TEXT        NOT NULL,
  is_enabled  BOOLEAN     NOT NULL DEFAULT FALSE,
  backup_codes JSONB      NOT NULL DEFAULT '[]',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── SSH Keys ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_keys (
  id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id               UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title                 TEXT        NOT NULL,
  public_key_fingerprint TEXT       NOT NULL UNIQUE,
  public_key_body       TEXT        NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ssh_keys_user_idx ON ssh_keys(user_id);

-- ── SSO Providers ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sso_providers (
  id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 UUID        REFERENCES organizations(id) ON DELETE CASCADE,
  provider_type          TEXT        NOT NULL CHECK (provider_type IN ('oidc','oauth2')),
  name                   TEXT        NOT NULL,
  slug                   TEXT        NOT NULL UNIQUE,
  client_id              TEXT        NOT NULL,
  client_secret_encrypted TEXT       NOT NULL,
  discovery_url          TEXT,
  auth_url               TEXT,
  token_url              TEXT,
  default_org_role       TEXT        NOT NULL DEFAULT 'member',
  is_enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── User Identities (SSO-linked) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_identities (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id  UUID        NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
  external_id  TEXT        NOT NULL,
  email        TEXT,
  raw_claims   JSONB,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ,
  UNIQUE (provider_id, external_id)
);
CREATE INDEX IF NOT EXISTS user_identities_user_idx ON user_identities(user_id);

-- ── Teams ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS teams (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  slug        TEXT        NOT NULL,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_id, slug)
);
CREATE INDEX IF NOT EXISTS teams_org_idx ON teams(org_id);

CREATE TABLE IF NOT EXISTS team_members (
  team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('maintainer','member')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS team_members_user_idx ON team_members(user_id);

CREATE TABLE IF NOT EXISTS team_repo_permissions (
  team_id    UUID NOT NULL REFERENCES teams(id)         ON DELETE CASCADE,
  repo_id    UUID NOT NULL REFERENCES repositories(id)  ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('admin','write','read')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (team_id, repo_id)
);
CREATE INDEX IF NOT EXISTS team_repo_permissions_repo_idx ON team_repo_permissions(repo_id);

-- ── Notification Preferences ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_preferences (
  id               UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID    NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  notify_pr_review  BOOLEAN NOT NULL DEFAULT TRUE,
  notify_pr_mention BOOLEAN NOT NULL DEFAULT TRUE,
  notify_org_invite BOOLEAN NOT NULL DEFAULT TRUE,
  notify_push       BOOLEAN NOT NULL DEFAULT FALSE,
  email_enabled     BOOLEAN NOT NULL DEFAULT TRUE
);
