# SCM — Enterprise Source Code Management

A self-hosted GitHub/GitLab-style SCM platform built with TypeScript, Fastify, PostgreSQL, Redis, and Nginx.

## Stack

| Layer | Technology |
|---|---|
| API | Node.js 20 + Fastify 4 + TypeScript |
| ORM | Drizzle ORM |
| Database | PostgreSQL 16 |
| Cache / Rate-limit | Redis 7 |
| Reverse proxy | Nginx 1.25 |
| Auth | JWT RS256 (jose) + Argon2id passwords |
| Deployment | Docker Compose |

## Quick Start

```bash
# 1. Generate RS256 key pair and write to .env
cp .env.example .env
bash scripts/gen-keys.sh

# 2. Start all services
docker compose up --build

# 3. Register a user
curl -X POST http://localhost/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"supersecret123"}'

# 4. Login
curl -X POST http://localhost/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"alice","password":"supersecret123"}'
```

## API Reference

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Login → JWT pair |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/logout` | Revoke tokens |

### Users
| Method | Path | Description |
|---|---|---|
| GET | `/users/me` | Current user profile |
| GET | `/users/:username` | Public profile |
| PATCH | `/users/me` | Update email/password |

### Organizations
| Method | Path | Description |
|---|---|---|
| POST | `/orgs` | Create org |
| GET | `/orgs/:orgId` | Get org |
| PATCH | `/orgs/:orgId` | Update org (admin+) |
| DELETE | `/orgs/:orgId` | Delete org (owner) |
| GET | `/orgs/:orgId/members` | List members |
| POST | `/orgs/:orgId/members` | Add member (admin+) |
| PATCH | `/orgs/:orgId/members/:userId` | Update role (admin+) |
| DELETE | `/orgs/:orgId/members/:userId` | Remove member (admin+) |

### Repositories
| Method | Path | Description |
|---|---|---|
| GET | `/orgs/:orgId/repos` | List repos |
| POST | `/orgs/:orgId/repos` | Create repo |
| GET | `/orgs/:orgId/repos/:repoId` | Get repo |
| PATCH | `/orgs/:orgId/repos/:repoId` | Update repo (admin+) |
| DELETE | `/orgs/:orgId/repos/:repoId` | Delete repo (admin+) |
| GET | `/orgs/:orgId/repos/:repoId/branches` | List branches |
| GET | `/orgs/:orgId/repos/:repoId/tags` | List tags |
| GET | `/orgs/:orgId/repos/:repoId/commits` | Commit log |
| POST | `/orgs/:orgId/repos/:repoId/collaborators` | Add collaborator |
| DELETE | `/orgs/:orgId/repos/:repoId/collaborators/:userId` | Remove collaborator |

### Git Smart-HTTP
```
git clone http://localhost/<org-slug>/<repo-slug>.git
```

### Pull Requests
| Method | Path | Description |
|---|---|---|
| GET | `/repos/:repoId/pulls` | List PRs |
| POST | `/repos/:repoId/pulls` | Open PR |
| GET | `/repos/:repoId/pulls/:prId` | Get PR |
| PATCH | `/repos/:repoId/pulls/:prId` | Edit PR |
| POST | `/repos/:repoId/pulls/:prId/close` | Close PR |
| POST | `/repos/:repoId/pulls/:prId/merge` | Merge PR |
| POST | `/repos/:repoId/pulls/:prId/reviews` | Submit review |
| GET | `/repos/:repoId/pulls/:prId/reviews` | List reviews |
| POST | `/repos/:repoId/pulls/:prId/comments` | Add comment |
| GET | `/repos/:repoId/pulls/:prId/comments` | List comments |

### Webhooks
| Method | Path | Description |
|---|---|---|
| GET | `/repos/:repoId/hooks` | List hooks |
| POST | `/repos/:repoId/hooks` | Create hook |
| GET | `/repos/:repoId/hooks/:hookId` | Get hook |
| PATCH | `/repos/:repoId/hooks/:hookId` | Update hook |
| DELETE | `/repos/:repoId/hooks/:hookId` | Delete hook |
| GET | `/repos/:repoId/hooks/:hookId/deliveries` | Delivery log |

## Security

- Passwords hashed with **Argon2id** (memory=64 MiB, iterations=3, parallelism=4)
- JWT **RS256** access tokens (15 min) + rotating refresh tokens (7 days, stored as SHA-256 hash)
- Revoked access tokens blocklisted in Redis until expiry
- **Redis sliding-window** rate limiting: 100 req/min per IP, 20 req/min on auth endpoints
- Webhook payloads signed with **HMAC-SHA256** (`X-SCM-Signature-256` header)
- Git repository paths are UUID-based — user input never reaches the filesystem
- All inputs validated with **Zod** schemas; unknown fields rejected
- **Helmet.js** security headers (CSP, HSTS, X-Frame-Options, etc.)
- Nginx: `client_max_body_size 512m`, request buffering off for git streams

## RBAC

```
Superadmin
  └── Org owner  → full org + repo control
      └── Org admin  → manage members, repos
          └── Org member → create repos, write access
              └── Org guest  → read public repos
                  └── Repo collaborator override (admin | write | read)
```
