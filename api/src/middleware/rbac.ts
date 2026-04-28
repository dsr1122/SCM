import type { FastifyRequest, FastifyReply } from 'fastify';
import { db } from '../db/client.js';
import { repositories, orgMembers, repoCollaborators, teamMembers, teamRepoPermissions, users } from '../db/schema.js';
import { and, eq } from 'drizzle-orm';
import type { OrgRole, RepoRole } from '../types/index.js';

const ORG_ROLE_RANK: Record<OrgRole, number> = {
  owner: 4, admin: 3, member: 2, guest: 1,
};
export const REPO_ROLE_RANK: Record<RepoRole, number> = {
  admin: 3, write: 2, read: 1,
};

// Resolves effective repo access for the authenticated user.
// Resolution order (highest wins):
//   1. Explicit repo collaborator role
//   2. Org membership role (owner/admin → admin, member → write, guest → read on public)
//   3. Team repo permissions (highest team role for user's teams)
//   4. Public repo → read for anyone
export async function resolveRepoAccess(
  userId: string,
  repoId: string,
): Promise<{ role: RepoRole | null; repo: typeof repositories.$inferSelect | null }> {
  const [repo] = await db
    .select()
    .from(repositories)
    .where(eq(repositories.id, repoId))
    .limit(1);

  if (!repo) return { role: null, repo: null };

  // 0. Superadmin bypass
  const [user] = await db.select({ isSuperadmin: users.isSuperadmin }).from(users).where(eq(users.id, userId)).limit(1);
  if (user?.isSuperadmin) return { role: 'admin', repo };

  // 1. Explicit collaborator
  const [collab] = await db
    .select({ role: repoCollaborators.role })
    .from(repoCollaborators)
    .where(and(eq(repoCollaborators.repoId, repoId), eq(repoCollaborators.userId, userId)))
    .limit(1);
  if (collab) return { role: collab.role as RepoRole, repo };

  // 2. Org membership
  const [member] = await db
    .select({ role: orgMembers.role })
    .from(orgMembers)
    .where(and(eq(orgMembers.orgId, repo.orgId), eq(orgMembers.userId, userId)))
    .limit(1);

  let orgDerivedRole: RepoRole | null = null;
  if (member) {
    const orgRole = member.role as OrgRole;
    if (ORG_ROLE_RANK[orgRole] >= ORG_ROLE_RANK['admin']) orgDerivedRole = 'admin';
    else if (ORG_ROLE_RANK[orgRole] >= ORG_ROLE_RANK['member']) orgDerivedRole = 'write';
    else if (!repo.isPrivate) orgDerivedRole = 'read';
  }

  // 3. Team permissions
  const teamPerms = await db
    .select({ role: teamRepoPermissions.role })
    .from(teamRepoPermissions)
    .innerJoin(teamMembers, eq(teamMembers.teamId, teamRepoPermissions.teamId))
    .where(and(eq(teamRepoPermissions.repoId, repoId), eq(teamMembers.userId, userId)));

  let teamDerivedRole: RepoRole | null = null;
  for (const perm of teamPerms) {
    const r = perm.role as RepoRole;
    if (!teamDerivedRole || REPO_ROLE_RANK[r] > REPO_ROLE_RANK[teamDerivedRole]) {
      teamDerivedRole = r;
    }
  }

  // Pick highest of org-derived vs team-derived
  const candidates = [orgDerivedRole, teamDerivedRole].filter(Boolean) as RepoRole[];
  if (candidates.length > 0) {
    const best = candidates.reduce((a, b) => (REPO_ROLE_RANK[a] >= REPO_ROLE_RANK[b] ? a : b));
    return { role: best, repo };
  }

  // 4. Public fallback
  if (!repo.isPrivate) return { role: 'read', repo };
  return { role: null, repo };
}

export function requireRepoAccess(required: RepoRole) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!req.user) {
      reply.status(401).send({ error: 'Authentication required' });
      return;
    }

    const { repoId } = req.params as Record<string, string>;
    if (!repoId) {
      reply.status(400).send({ error: 'Missing repoId' });
      return;
    }

    const { role, repo } = await resolveRepoAccess(req.user.id, repoId);

    if (!repo) {
      reply.status(404).send({ error: 'Repository not found' });
      return;
    }

    if (!role || REPO_ROLE_RANK[role] < REPO_ROLE_RANK[required]) {
      reply.status(403).send({ error: 'Insufficient repository permissions' });
      return;
    }
  };
}

export function requireOrgRole(required: OrgRole) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!req.user) {
      reply.status(401).send({ error: 'Authentication required' });
      return;
    }
    if (req.user.isSuperadmin) return;

    const { orgId } = req.params as Record<string, string>;
    if (!orgId) {
      reply.status(400).send({ error: 'Missing orgId' });
      return;
    }

    const [member] = await db
      .select({ role: orgMembers.role })
      .from(orgMembers)
      .where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, req.user.id)))
      .limit(1);

    if (!member) {
      reply.status(403).send({ error: 'Not a member of this organization' });
      return;
    }

    if (ORG_ROLE_RANK[member.role as OrgRole] < ORG_ROLE_RANK[required]) {
      reply.status(403).send({ error: 'Insufficient organization permissions' });
      return;
    }
  };
}
