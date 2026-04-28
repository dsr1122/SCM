import {
  pgTable, uuid, text, boolean, timestamp, integer, jsonb,
  primaryKey, unique, index,
} from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id:           uuid('id').primaryKey().defaultRandom(),
  username:     text('username').notNull().unique(),
  email:        text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  isActive:     boolean('is_active').notNull().default(true),
  isSuperadmin: boolean('is_superadmin').notNull().default(false),
  createdAt:    timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt:    timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  emailIdx:    index('users_email_idx').on(t.email),
  usernameIdx: index('users_username_idx').on(t.username),
}));

export const refreshTokens = pgTable('refresh_tokens', {
  id:        uuid('id').primaryKey().defaultRandom(),
  userId:    uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull().unique(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  userIdx: index('refresh_tokens_user_idx').on(t.userId),
}));

export const organizations = pgTable('organizations', {
  id:          uuid('id').primaryKey().defaultRandom(),
  name:        text('name').notNull(),
  slug:        text('slug').notNull().unique(),
  description: text('description'),
  createdAt:   timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const orgMembers = pgTable('org_members', {
  orgId:     uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  userId:    uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  role:      text('role').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  pk:      primaryKey({ columns: [t.orgId, t.userId] }),
  userIdx: index('org_members_user_idx').on(t.userId),
}));

export const repositories = pgTable('repositories', {
  id:            uuid('id').primaryKey().defaultRandom(),
  orgId:         uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  ownerId:       uuid('owner_id').notNull().references(() => users.id),
  name:          text('name').notNull(),
  slug:          text('slug').notNull(),
  description:   text('description'),
  isPrivate:     boolean('is_private').notNull().default(true),
  defaultBranch: text('default_branch').notNull().default('main'),
  diskPath:      text('disk_path').notNull().unique(),
  createdAt:     timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt:     timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  orgSlugUniq: unique('repos_org_slug_uniq').on(t.orgId, t.slug),
  orgSlugIdx:  index('repos_org_slug_idx').on(t.orgId, t.slug),
}));

export const repoCollaborators = pgTable('repo_collaborators', {
  repoId:    uuid('repo_id').notNull().references(() => repositories.id, { onDelete: 'cascade' }),
  userId:    uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  role:      text('role').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  pk: primaryKey({ columns: [t.repoId, t.userId] }),
}));

export const pullRequests = pgTable('pull_requests', {
  id:              uuid('id').primaryKey().defaultRandom(),
  repoId:          uuid('repo_id').notNull().references(() => repositories.id, { onDelete: 'cascade' }),
  number:          integer('number').notNull(),
  authorId:        uuid('author_id').notNull().references(() => users.id),
  title:           text('title').notNull(),
  body:            text('body').notNull().default(''),
  sourceBranch:    text('source_branch').notNull(),
  targetBranch:    text('target_branch').notNull(),
  status:          text('status').notNull().default('open'),
  mergedCommitSha: text('merged_commit_sha'),
  createdAt:       timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt:       timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  repoNumberUniq: unique('pr_repo_number_uniq').on(t.repoId, t.number),
  repoIdx:        index('pr_repo_idx').on(t.repoId, t.number),
}));

export const prReviews = pgTable('pr_reviews', {
  id:          uuid('id').primaryKey().defaultRandom(),
  prId:        uuid('pr_id').notNull().references(() => pullRequests.id, { onDelete: 'cascade' }),
  reviewerId:  uuid('reviewer_id').notNull().references(() => users.id),
  state:       text('state').notNull(),
  body:        text('body').notNull().default(''),
  submittedAt: timestamp('submitted_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  prIdx: index('pr_reviews_pr_idx').on(t.prId),
}));

export const prComments = pgTable('pr_comments', {
  id:        uuid('id').primaryKey().defaultRandom(),
  prId:      uuid('pr_id').notNull().references(() => pullRequests.id, { onDelete: 'cascade' }),
  reviewId:  uuid('review_id').references(() => prReviews.id, { onDelete: 'set null' }),
  authorId:  uuid('author_id').notNull().references(() => users.id),
  body:      text('body').notNull(),
  commitSha: text('commit_sha'),
  path:      text('path'),
  line:      integer('line'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  prIdx: index('pr_comments_pr_idx').on(t.prId),
}));

export const webhooks = pgTable('webhooks', {
  id:         uuid('id').primaryKey().defaultRandom(),
  repoId:     uuid('repo_id').notNull().references(() => repositories.id, { onDelete: 'cascade' }),
  url:        text('url').notNull(),
  secretHash: text('secret_hash').notNull(),
  events:     jsonb('events').notNull().default(['push', 'pull_request']),
  isActive:   boolean('is_active').notNull().default(true),
  createdAt:  timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  repoIdx: index('webhooks_repo_idx').on(t.repoId),
}));

export const webhookDeliveries = pgTable('webhook_deliveries', {
  id:             uuid('id').primaryKey().defaultRandom(),
  webhookId:      uuid('webhook_id').notNull().references(() => webhooks.id, { onDelete: 'cascade' }),
  event:          text('event').notNull(),
  payload:        jsonb('payload').notNull(),
  responseStatus: integer('response_status'),
  durationMs:     integer('duration_ms'),
  error:          text('error'),
  createdAt:      timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  webhookIdx: index('webhook_deliveries_webhook_idx').on(t.webhookId, t.createdAt),
}));

// ── Audit Log ────────────────────────────────────────────────────────────────
export const auditLog = pgTable('audit_log', {
  id:           uuid('id').primaryKey().defaultRandom(),
  actorId:      uuid('actor_id').references(() => users.id, { onDelete: 'set null' }),
  actorUsername: text('actor_username'),
  action:       text('action').notNull(),
  resourceType: text('resource_type'),
  resourceId:   text('resource_id'),
  orgId:        uuid('org_id').references(() => organizations.id, { onDelete: 'set null' }),
  repoId:       uuid('repo_id').references(() => repositories.id, { onDelete: 'set null' }),
  metadata:     jsonb('metadata'),
  ipAddress:    text('ip_address'),
  userAgent:    text('user_agent'),
  createdAt:    timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  actorIdx:    index('audit_log_actor_idx').on(t.actorId),
  actionIdx:   index('audit_log_action_idx').on(t.action),
  orgIdx:      index('audit_log_org_idx').on(t.orgId),
  repoIdx:     index('audit_log_repo_idx').on(t.repoId),
  createdIdx:  index('audit_log_created_idx').on(t.createdAt),
}));

// ── Branch Protection ────────────────────────────────────────────────────────
export const branchProtectionRules = pgTable('branch_protection_rules', {
  id:                   uuid('id').primaryKey().defaultRandom(),
  repoId:               uuid('repo_id').notNull().references(() => repositories.id, { onDelete: 'cascade' }),
  pattern:              text('pattern').notNull(),
  requirePullRequest:   boolean('require_pull_request').notNull().default(true),
  requiredApprovals:    integer('required_approvals').notNull().default(1),
  dismissStaleReviews:  boolean('dismiss_stale_reviews').notNull().default(false),
  restrictPushers:      boolean('restrict_pushers').notNull().default(false),
  allowedPusherIds:     jsonb('allowed_pusher_ids').notNull().default([]),
  blockForcePush:       boolean('block_force_push').notNull().default(true),
  requireLinearHistory: boolean('require_linear_history').notNull().default(false),
  createdAt:            timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt:            timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  repoIdx: index('bpr_repo_idx').on(t.repoId),
}));

// ── Personal Access Tokens ───────────────────────────────────────────────────
export const personalAccessTokens = pgTable('personal_access_tokens', {
  id:         uuid('id').primaryKey().defaultRandom(),
  userId:     uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name:       text('name').notNull(),
  tokenHash:  text('token_hash').notNull().unique(),
  prefix:     text('prefix').notNull(),
  scopes:     jsonb('scopes').notNull().default([]),
  expiresAt:  timestamp('expires_at', { withTimezone: true }),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  revokedAt:  timestamp('revoked_at', { withTimezone: true }),
  createdAt:  timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  userIdx: index('pat_user_idx').on(t.userId),
}));

// ── User TOTP (2FA) ──────────────────────────────────────────────────────────
export const userTotp = pgTable('user_totp', {
  id:          uuid('id').primaryKey().defaultRandom(),
  userId:      uuid('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  secret:      text('secret').notNull(),
  isEnabled:   boolean('is_enabled').notNull().default(false),
  backupCodes: jsonb('backup_codes').notNull().default([]),
  createdAt:   timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// ── SSH Keys ─────────────────────────────────────────────────────────────────
export const sshKeys = pgTable('ssh_keys', {
  id:          uuid('id').primaryKey().defaultRandom(),
  userId:      uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  title:       text('title').notNull(),
  fingerprint: text('public_key_fingerprint').notNull().unique(),
  publicKey:   text('public_key_body').notNull(),
  createdAt:   timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt:  timestamp('last_used_at', { withTimezone: true }),
}, (t) => ({
  userIdx: index('ssh_keys_user_idx').on(t.userId),
}));

// ── SSO Providers ────────────────────────────────────────────────────────────
export const ssoProviders = pgTable('sso_providers', {
  id:                    uuid('id').primaryKey().defaultRandom(),
  orgId:                 uuid('org_id').references(() => organizations.id, { onDelete: 'cascade' }),
  providerType:          text('provider_type').notNull(),
  name:                  text('name').notNull(),
  slug:                  text('slug').notNull().unique(),
  clientId:              text('client_id').notNull(),
  clientSecretEncrypted: text('client_secret_encrypted').notNull(),
  discoveryUrl:          text('discovery_url'),
  authUrl:               text('auth_url'),
  tokenUrl:              text('token_url'),
  defaultOrgRole:        text('default_org_role').notNull().default('member'),
  isEnabled:             boolean('is_enabled').notNull().default(true),
  createdAt:             timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// ── User Identities (SSO-linked) ─────────────────────────────────────────────
export const userIdentities = pgTable('user_identities', {
  id:          uuid('id').primaryKey().defaultRandom(),
  userId:      uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  providerId:  uuid('provider_id').notNull().references(() => ssoProviders.id, { onDelete: 'cascade' }),
  externalId:  text('external_id').notNull(),
  email:       text('email'),
  rawClaims:   jsonb('raw_claims'),
  createdAt:   timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
}, (t) => ({
  providerExternalUniq: unique('user_identity_provider_external_uniq').on(t.providerId, t.externalId),
  userIdx:              index('user_identities_user_idx').on(t.userId),
}));

// ── Teams ────────────────────────────────────────────────────────────────────
export const teams = pgTable('teams', {
  id:          uuid('id').primaryKey().defaultRandom(),
  orgId:       uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  name:        text('name').notNull(),
  slug:        text('slug').notNull(),
  description: text('description'),
  createdAt:   timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  orgSlugUniq: unique('teams_org_slug_uniq').on(t.orgId, t.slug),
  orgIdx:      index('teams_org_idx').on(t.orgId),
}));

export const teamMembers = pgTable('team_members', {
  teamId:    uuid('team_id').notNull().references(() => teams.id, { onDelete: 'cascade' }),
  userId:    uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  role:      text('role').notNull().default('member'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  pk:      primaryKey({ columns: [t.teamId, t.userId] }),
  userIdx: index('team_members_user_idx').on(t.userId),
}));

export const teamRepoPermissions = pgTable('team_repo_permissions', {
  teamId:    uuid('team_id').notNull().references(() => teams.id, { onDelete: 'cascade' }),
  repoId:    uuid('repo_id').notNull().references(() => repositories.id, { onDelete: 'cascade' }),
  role:      text('role').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  pk:      primaryKey({ columns: [t.teamId, t.repoId] }),
  repoIdx: index('team_repo_permissions_repo_idx').on(t.repoId),
}));

// ── Notification Preferences ─────────────────────────────────────────────────
export const notificationPreferences = pgTable('notification_preferences', {
  id:              uuid('id').primaryKey().defaultRandom(),
  userId:          uuid('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  notifyPrReview:  boolean('notify_pr_review').notNull().default(true),
  notifyPrMention: boolean('notify_pr_mention').notNull().default(true),
  notifyOrgInvite: boolean('notify_org_invite').notNull().default(true),
  notifyPush:      boolean('notify_push').notNull().default(false),
  emailEnabled:    boolean('email_enabled').notNull().default(true),
});
