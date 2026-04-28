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
