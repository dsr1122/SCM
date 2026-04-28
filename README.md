# SCM — Enterprise Source Code Management

A self-hosted, GitHub/GitLab-style source code management platform. Built for security, scalability, and operational simplicity.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Security](#security)
- [RBAC Model](#rbac-model)
- [Webhooks](#webhooks)
- [Development](#development)
- [Production Deployment](#production-deployment)

---

## Features

### Core
- **Git smart-HTTP** — clone, fetch, and push via standard `git` CLI over HTTP
- **Organizations** — multi-tenant org model with member roles
- **Repositories** — private/public repos with per-collaborator role overrides
- **Pull Requests** — open, review, comment, and merge (fast-forward or merge-commit)
- **Code Review** — inline comments tied to commit SHA, path, and line number
- **Webhooks** — HMAC-signed event delivery with exponential-backoff retry and delivery log
- **Auth** — JWT RS256 access tokens + rotating refresh tokens; Argon2id password hashing
- **RBAC** — five-tier permission model from superadmin down to repo-level collaborator
- **Rate limiting** — Redis sliding-window per IP and per user
- **Security headers** — Helmet.js (CSP, HSTS, X-Frame-Options, Referrer-Policy)

### Enterprise
- **Immutable Audit Log** — every user action (login, push, merge, member change, etc.) recorded with actor, IP, and metadata; queryable via admin API
- **Branch Protection Rules** — per-repo glob patterns; block force-push, require PRs, require N approvals, restrict allowed pushers
- **Personal Access Tokens (PATs)** — scoped API tokens for CI/CD service accounts; last-used tracking; revocable
- **Two-Factor Authentication (TOTP)** — RFC 6238 TOTP with QR code setup, 10 single-use backup codes (Argon2id hashed), 2FA challenge on login
- **SSH Key Management** — store and list user SSH public keys with SHA256 fingerprint validation
- **SSO / OIDC** — OIDC provider support with JIT user provisioning, PKCE, org auto-enrollment
- **Teams** — group users within an org; assign repo-level permissions to teams; team membership overrides org baseline
- **Email Notifications** — SMTP-backed notifications for PR reviews, comments, merges, and org invites; per-user preference controls
- **System Admin API** — superadmin endpoints for user/org management, system stats, audit log access

---

## Architecture

```
Browser / Git CLI
       │
  ┌────▼──────────────────────────────────┐
  │              Nginx 1.25               │
  │  TLS termination · rate-limit headers │
  │  streaming proxy for git pack data    │
  └────┬──────────────────────────────────┘
       │
  ┌────▼──────────────────┐     ┌────────────────┐
  │   Fastify API (3000)  │────▶│  PostgreSQL 16  │
  │   TypeScript · Node   │     │  primary data   │
  └────┬──────────────────┘     └────────────────┘
       │
       │                        ┌────────────────┐
       ├──────────────────────▶ │    Redis 7      │
       │                        │  rate limits    │
       │                        │  JWT blocklist  │
       │                        └────────────────┘
       │
  ┌────▼──────────────────┐
  │   Git bare repos      │
  │   /data/repos/<uuid>  │
  │   (Docker volume)     │
  └───────────────────────┘
```

All internal services (API, Postgres, Redis) sit on an isolated `backend` Docker network not reachable from the host. Only Nginx is exposed on port 80.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Docker | 24+ |
| Docker Compose | v2 (included with Docker Desktop) |
| `openssl` | any modern version (for key generation) |
| `git` | 2.x (client-side, for testing clones/pushes) |

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`.

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_*` / `DATABASE_URL` | — | PostgreSQL connection |
| `REDIS_URL` / `REDIS_PASSWORD` | — | Redis connection |
| `JWT_PRIVATE_KEY_B64` / `JWT_PUBLIC_KEY_B64` | — | RS256 key pair — generate with `scripts/gen-keys.sh` |
| `TOTP_ENCRYPTION_KEY` | — | 64-char hex (32 bytes) — AES-256-GCM key for TOTP secrets |
| `SECRET_ENCRYPTION_KEY` | — | 64-char hex (32 bytes) — AES-256-GCM key for SSO client secrets |
| `SSO_CALLBACK_BASE_URL` | `http://localhost` | Base URL for OAuth2 callback redirect |
| `SMTP_HOST` | — | Leave blank to disable email; set to enable notifications |
| `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | — | SMTP credentials |
| `CORS_ORIGINS` | `http://localhost` | Comma-separated allowed origins |
| `GIT_REPOS_ROOT` | `/data/repos` | Bare repo storage root |

Generate encryption keys:
```bash
openssl rand -hex 32   # TOTP_ENCRYPTION_KEY
openssl rand -hex 32   # SECRET_ENCRYPTION_KEY
```

## Quick Start

```bash
# 1. Clone and enter the project
git clone <this-repo> scm && cd scm

# 2. Copy the example env file
cp .env.example .env

# 3. Generate an RS256 key pair (writes JWT_PRIVATE_KEY_B64 / JWT_PUBLIC_KEY_B64 into .env)
bash scripts/gen-keys.sh

# 4. Build and start all services
docker compose up --build

# 5. Register your first user
curl -s -X POST http://localhost/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"supersecret123"}' | jq

# 6. Log in and capture the tokens
TOKEN=$(curl -s -X POST http://localhost/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"alice","password":"supersecret123"}' | jq -r .accessToken)

# 7. Create an org
curl -s -X POST http://localhost/orgs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Acme","slug":"acme"}' | jq

# 8. Create a repo (replace <orgId> with the id from the previous response)
curl -s -X POST http://localhost/orgs/<orgId>/repos \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"My Repo","slug":"my-repo","isPrivate":false}' | jq

# 9. Clone it
git clone http://alice:supersecret123@localhost/acme/my-repo.git
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and fill in the values.

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` | `scm` | PostgreSQL username |
| `POSTGRES_PASSWORD` | — | PostgreSQL password **(required)** |
| `POSTGRES_DB` | `scm` | PostgreSQL database name |
| `DATABASE_URL` | — | Full Postgres connection string |
| `REDIS_URL` | — | Redis connection string |
| `REDIS_PASSWORD` | `redispass` | Redis AUTH password |
| `JWT_PRIVATE_KEY_B64` | — | Base64-encoded RS256 private key PEM **(generated by `gen-keys.sh`)** |
| `JWT_PUBLIC_KEY_B64` | — | Base64-encoded RS256 public key PEM **(generated by `gen-keys.sh`)** |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | Access token lifetime (15 min) |
| `REFRESH_TOKEN_TTL_SECONDS` | `604800` | Refresh token lifetime (7 days) |
| `CORS_ORIGINS` | `http://localhost` | Comma-separated allowed CORS origins |
| `GIT_REPOS_ROOT` | `/data/repos` | Filesystem root for bare git repos |
| `WEBHOOK_TIMEOUT_MS` | `10000` | Per-request webhook delivery timeout |
| `WEBHOOK_MAX_RETRIES` | `3` | Max delivery retries (exponential backoff) |

---

## Project Structure

```
SCM/
├── docker-compose.yml          # All services wired together
├── .env.example                # Environment variable template
├── nginx/
│   └── nginx.conf              # Reverse proxy, rate limiting, streaming config
├── scripts/
│   ├── gen-keys.sh             # Generates RS256 key pair → .env
│   └── init-db.sql             # Idempotent schema bootstrap (run on first Postgres start)
└── api/
    ├── Dockerfile              # Multi-stage build (builder → runtime, non-root user)
    ├── package.json
    ├── tsconfig.json
    └── src/
        ├── app.ts              # Fastify setup, plugin registration, health endpoint
        ├── config.ts           # Zod-validated env config (fail-fast on startup)
        ├── types/
        │   └── index.ts        # Shared types: OrgRole, RepoRole, JwtPayload, etc.
        ├── db/
        │   ├── client.ts       # Drizzle ORM + pg connection pool
        │   └── schema.ts       # All 11 table definitions with indexes
        ├── middleware/
        │   ├── auth.ts         # JWT RS256 verification, Redis blocklist check
        │   ├── rbac.ts         # requireRepoAccess / requireOrgRole guard factories
        │   └── rateLimiter.ts  # Redis sliding-window limiter (IP + per-user)
        ├── routes/
        │   ├── auth.ts         # /auth — register, login, refresh, logout
        │   ├── users.ts        # /users — profile, update
        │   ├── orgs.ts         # /orgs — CRUD + membership management
        │   ├── repos.ts        # /orgs/:orgId/repos — CRUD, branches, tags, commits
        │   ├── git.ts          # /:org/:repo.git — smart-HTTP upload/receive-pack
        │   ├── pullRequests.ts # /repos/:repoId/pulls — PR lifecycle + reviews + comments
        │   └── webhooks.ts     # /repos/:repoId/hooks — CRUD + delivery log
        └── services/
            ├── auth.service.ts     # Argon2id hashing, JWT issuance, token revocation
            ├── git.service.ts      # Spawns git-upload/receive-pack, streams stdin/stdout
            ├── repo.service.ts     # bare repo init/delete, branch/tag/commit queries
            ├── pr.service.ts       # PR number sequencing, merge logic
            └── webhook.service.ts  # HMAC signing, HTTP dispatch, retry, delivery logging
```

---

## API Reference

All endpoints accept and return `application/json`. Authenticated endpoints require:

```
Authorization: Bearer <accessToken>
```

### Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | — | Create a new account |
| `POST` | `/auth/login` | — | Authenticate → `{ accessToken, refreshToken }` |
| `POST` | `/auth/refresh` | — | Rotate refresh token → new token pair |
| `POST` | `/auth/logout` | Required | Revoke access + refresh tokens |

**Register**
```json
{ "username": "alice", "email": "alice@example.com", "password": "supersecret123" }
```

**Login**
```json
{ "login": "alice", "password": "supersecret123" }
```

### Users

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/users/me` | Required | Current user's full profile |
| `GET` | `/users/:username` | Required | Public profile by username |
| `PATCH` | `/users/me` | Required | Update email or password |

### Organizations

| Method | Path | Required Role | Description |
|---|---|---|---|
| `POST` | `/orgs` | Any authenticated | Create org (caller becomes owner) |
| `GET` | `/orgs/:orgId` | Any authenticated | Get org details |
| `PATCH` | `/orgs/:orgId` | Org admin+ | Update name / description |
| `DELETE` | `/orgs/:orgId` | Org owner | Delete org and all repos |
| `GET` | `/orgs/:orgId/members` | Org guest+ | List members |
| `POST` | `/orgs/:orgId/members` | Org admin+ | Add member by username |
| `PATCH` | `/orgs/:orgId/members/:userId` | Org admin+ | Change member role |
| `DELETE` | `/orgs/:orgId/members/:userId` | Org admin+ | Remove member |

### Repositories

| Method | Path | Required Role | Description |
|---|---|---|---|
| `GET` | `/orgs/:orgId/repos` | Any authenticated | List repos in org |
| `POST` | `/orgs/:orgId/repos` | Org member+ | Create repo |
| `GET` | `/orgs/:orgId/repos/:repoId` | Repo read+ | Get repo details |
| `PATCH` | `/orgs/:orgId/repos/:repoId` | Repo admin | Update metadata / visibility |
| `DELETE` | `/orgs/:orgId/repos/:repoId` | Repo admin | Delete repo + bare repo on disk |
| `GET` | `/orgs/:orgId/repos/:repoId/branches` | Repo read | List branches |
| `GET` | `/orgs/:orgId/repos/:repoId/tags` | Repo read | List tags |
| `GET` | `/orgs/:orgId/repos/:repoId/commits?branch=main&limit=30&offset=0` | Repo read | Paginated commit log |
| `POST` | `/orgs/:orgId/repos/:repoId/collaborators` | Repo admin | Add collaborator |
| `DELETE` | `/orgs/:orgId/repos/:repoId/collaborators/:userId` | Repo admin | Remove collaborator |

### Two-Factor Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/2fa/setup` | Required | Generate TOTP secret + QR code |
| `POST` | `/auth/2fa/confirm` | Required | Activate 2FA with first TOTP code — returns backup codes |
| `POST` | `/auth/2fa/verify` | 2fa_pending token | Exchange pending session + TOTP code for full JWT pair |
| `POST` | `/auth/2fa/disable` | Required | Disable 2FA (requires password + TOTP code) |

**Login flow with 2FA enabled:**
```
POST /auth/login → { requiresTwoFactor: true, sessionToken }
POST /auth/2fa/verify  (Authorization: Bearer <sessionToken>)
     → { accessToken, refreshToken }
```

### SSO / OIDC

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/sso/authorize/:slug` | Redirect to IdP authorization page |
| `GET` | `/auth/sso/callback/:slug` | OAuth2 callback — issues JWT pair (JIT provisioning) |
| `GET` | `/auth/sso/providers` | List SSO providers (superadmin) |
| `POST` | `/auth/sso/providers` | Create SSO provider (superadmin) |
| `PATCH` | `/auth/sso/providers/:id` | Update SSO provider (superadmin) |
| `DELETE` | `/auth/sso/providers/:id` | Delete SSO provider (superadmin) |

### Personal Access Tokens

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/users/me/tokens` | Required | List active PATs |
| `POST` | `/users/me/tokens` | Required | Create PAT — returns raw token **once** |
| `DELETE` | `/users/me/tokens/:tokenId` | Required | Revoke PAT |

**Create a PAT:**
```json
{ "name": "CI deploy bot", "scopes": ["repo:read", "repo:write"], "expiresAt": "2027-01-01T00:00:00Z" }
```
Use the returned `token` value as a `Bearer` credential on any API or git HTTP request.

### SSH Keys

| Method | Path | Description |
|---|---|---|
| `GET` | `/users/me/ssh-keys` | List your SSH keys |
| `POST` | `/users/me/ssh-keys` | Add SSH public key |
| `DELETE` | `/users/me/ssh-keys/:keyId` | Remove SSH key |

### Teams

| Method | Path | Required Role | Description |
|---|---|---|---|
| `GET` | `/orgs/:orgId/teams` | Org guest+ | List teams |
| `POST` | `/orgs/:orgId/teams` | Org admin+ | Create team |
| `GET` | `/orgs/:orgId/teams/:teamId` | Org guest+ | Get team |
| `PATCH` | `/orgs/:orgId/teams/:teamId` | Org admin+ | Update team |
| `DELETE` | `/orgs/:orgId/teams/:teamId` | Org admin+ | Delete team |
| `GET` | `/orgs/:orgId/teams/:teamId/members` | Org guest+ | List team members |
| `POST` | `/orgs/:orgId/teams/:teamId/members` | Org admin+ | Add member |
| `DELETE` | `/orgs/:orgId/teams/:teamId/members/:userId` | Org admin+ | Remove member |
| `GET` | `/orgs/:orgId/teams/:teamId/repos` | Org guest+ | List team repos |
| `POST` | `/orgs/:orgId/teams/:teamId/repos` | Org admin+ | Grant repo access to team |
| `DELETE` | `/orgs/:orgId/teams/:teamId/repos/:repoId` | Org admin+ | Revoke repo access |

### Branch Protection

| Method | Path | Required Role | Description |
|---|---|---|---|
| `GET` | `/repos/:repoId/branch-protection` | Repo read | List rules |
| `POST` | `/repos/:repoId/branch-protection` | Repo admin | Create rule |
| `PATCH` | `/repos/:repoId/branch-protection/:ruleId` | Repo admin | Update rule |
| `DELETE` | `/repos/:repoId/branch-protection/:ruleId` | Repo admin | Delete rule |

**Create a rule:**
```json
{
  "pattern": "main",
  "requirePullRequest": true,
  "requiredApprovals": 2,
  "blockForcePush": true,
  "dismissStaleReviews": true
}
```
Patterns support exact match and glob (e.g. `release/*`). More specific patterns take precedence.

### Notification Preferences

| Method | Path | Description |
|---|---|---|
| `GET` | `/users/me/notifications` | Get preferences |
| `PATCH` | `/users/me/notifications` | Update preferences |

### System Admin

All endpoints require `isSuperadmin = true`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/users?q=alice&limit=50` | Search users |
| `GET` | `/admin/users/:userId` | Get user (without password hash) |
| `PATCH` | `/admin/users/:userId` | Set `isActive` / `isSuperadmin` |
| `DELETE` | `/admin/users/:userId` | Hard-delete user |
| `GET` | `/admin/orgs` | List all orgs |
| `DELETE` | `/admin/orgs/:orgId` | Force-delete org |
| `GET` | `/admin/stats` | `{ users, organizations, repositories, pullRequests, storageBytes }` |
| `GET` | `/admin/audit-log?actor=alice&action=pr.merged&since=2026-01-01&limit=100` | Query audit log |

### Git Smart-HTTP

Standard git operations work over HTTP. Credentials are sent as HTTP Basic Auth.

```bash
# Clone
git clone http://<user>:<password>@localhost/<org-slug>/<repo-slug>.git

# Push
git push origin main

# Fetch
git fetch origin
```

Endpoints proxied through Nginx with request buffering disabled for streaming pack data:

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/:org/:repo.git/info/refs?service=git-upload-pack` | Read+ | Fetch/clone ref discovery |
| `POST` | `/:org/:repo.git/git-upload-pack` | Read+ | Pack data for fetch/clone |
| `GET` | `/:org/:repo.git/info/refs?service=git-receive-pack` | Write+ | Push ref discovery |
| `POST` | `/:org/:repo.git/git-receive-pack` | Write+ | Receive pushed pack data |

### Pull Requests

| Method | Path | Required Role | Description |
|---|---|---|---|
| `GET` | `/repos/:repoId/pulls?status=open` | Repo read | List PRs (filter by status) |
| `POST` | `/repos/:repoId/pulls` | Repo read | Open a PR |
| `GET` | `/repos/:repoId/pulls/:prId` | Repo read | Get PR details |
| `PATCH` | `/repos/:repoId/pulls/:prId` | PR author | Edit title / body |
| `POST` | `/repos/:repoId/pulls/:prId/close` | Repo write | Close PR |
| `POST` | `/repos/:repoId/pulls/:prId/merge` | Repo write | Merge PR (auto fast-forward or merge commit) |
| `POST` | `/repos/:repoId/pulls/:prId/reviews` | Repo read | Submit review (approved / changes_requested / commented) |
| `GET` | `/repos/:repoId/pulls/:prId/reviews` | Repo read | List reviews |
| `POST` | `/repos/:repoId/pulls/:prId/comments` | Repo read | Add inline or general comment |
| `GET` | `/repos/:repoId/pulls/:prId/comments` | Repo read | List comments |

**Open a PR**
```json
{
  "title": "Add login page",
  "body": "Implements the login flow described in #42.",
  "sourceBranch": "feature/login",
  "targetBranch": "main"
}
```

### Webhooks

| Method | Path | Required Role | Description |
|---|---|---|---|
| `GET` | `/repos/:repoId/hooks` | Repo admin | List webhooks |
| `POST` | `/repos/:repoId/hooks` | Repo admin | Create webhook |
| `GET` | `/repos/:repoId/hooks/:hookId` | Repo admin | Get webhook |
| `PATCH` | `/repos/:repoId/hooks/:hookId` | Repo admin | Update URL / secret / events |
| `DELETE` | `/repos/:repoId/hooks/:hookId` | Repo admin | Delete webhook |
| `GET` | `/repos/:repoId/hooks/:hookId/deliveries?limit=50` | Repo admin | Delivery log |

**Create a webhook**
```json
{
  "url": "https://ci.example.com/hook",
  "secret": "a-long-random-secret-string",
  "events": ["push", "pull_request"]
}
```

---

## Security

| Concern | Implementation |
|---|---|
| Password storage | Argon2id — memory=64 MiB, time=3, parallelism=4 |
| Authentication | JWT RS256 — access token 15 min, refresh token 7 days |
| Token revocation | Refresh rows in Postgres (SHA-256 hashed) + Redis blocklist for access tokens |
| Transport | Nginx with HSTS; swap self-signed cert for Let's Encrypt in production |
| Rate limiting | Redis sliding window: 100 req/min per IP globally, 20 req/min on `/auth/*` |
| Input validation | Zod on every route — strict mode, unknown fields rejected |
| SQL injection | Drizzle ORM parameterized queries — no raw string interpolation anywhere |
| Path traversal | Git disk paths are UUID-based; user-supplied slugs never touch the filesystem |
| Webhook integrity | `X-SCM-Signature-256: sha256=<hmac>` on every delivery |
| Security headers | Helmet.js — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| CORS | Allowlist-only origins from `CORS_ORIGINS` env var |
| Least privilege | API container runs as non-root `scm` user |
| Network isolation | Postgres and Redis are on an internal Docker network, never exposed to host |
| Timing attacks | Login always runs Argon2id even when the user does not exist |

---

## RBAC Model

Permissions are hierarchical. A higher role always implies all permissions of lower roles. Explicit repo collaborator roles override the org-level baseline.

```
Superadmin  ─── full system access
  └── Org owner    ─── full org + all repos
      └── Org admin    ─── manage members, create/delete repos
          └── Org member   ─── create repos, write to all org repos
              └── Org guest    ─── read public repos
                  └── Repo collaborator override
                        admin | write | read
```

**Effective access resolution order:**
1. Superadmin flag → always admin everywhere
2. Explicit repo collaborator role → use that
3. Org membership role → map to repo role (owner/admin → repo admin, member → write, guest → read on public only)
4. No match + public repo → read
5. No match + private repo → 403

---

## Webhooks

When a push or PR event occurs, SCM:

1. Looks up all active webhooks for the repo that subscribe to the event
2. Signs the JSON payload: `X-SCM-Signature-256: sha256=HMAC-SHA256(secret, body)`
3. POSTs to the configured URL with a `config.webhookTimeoutMs` timeout
4. On 5xx or network error, retries up to `config.webhookMaxRetries` times with exponential backoff (1s, 2s, 4s, …)
5. Records every attempt in `webhook_deliveries` (status code, duration, error)

**Verifying signatures (receiver side)**
```js
const crypto = require('crypto');
const sig = req.headers['x-scm-signature-256'];
const expected = 'sha256=' + crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');
const valid = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
```

---

## Development

```bash
cd api
npm install

# Run with hot-reload (requires a running Postgres + Redis — use docker compose for deps only)
docker compose up -d postgres redis
npm run dev
```

Type-check without building:
```bash
npm run typecheck
```

Build for production:
```bash
npm run build   # outputs to api/dist/
```

---

## Production Deployment

### TLS

Replace Nginx port 80 with 443 + a real certificate. The simplest path:

```nginx
listen 443 ssl;
ssl_certificate     /etc/letsencrypt/live/scm.example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/scm.example.com/privkey.pem;
```

Add a port 80 → 443 redirect block.

### Scaling

- The API is stateless — run multiple replicas behind Nginx `upstream` with `keepalive`.
- Postgres: promote to a managed instance (RDS, Cloud SQL) or add a read replica + PgBouncer.
- Redis: use Redis Sentinel or a managed instance for HA.
- Git repos: mount the `/data/repos` volume on shared network storage (NFS, EFS, GCS Fuse) when running multiple API replicas.

### Secrets

In production never commit `.env`. Inject secrets via:
- Docker secrets / `docker compose` secrets
- Kubernetes Secrets + a CSI secrets driver
- A secrets manager (AWS Secrets Manager, HashiCorp Vault)

### Backups

```bash
# Postgres dump
docker compose exec postgres pg_dump -U scm scm | gzip > scm-$(date +%F).sql.gz

# Git repos volume
tar -czf repos-$(date +%F).tar.gz /var/lib/docker/volumes/scm_git_repos
```
