import { minimatch } from 'minimatch';
import { db } from '../db/client.js';
import { branchProtectionRules, prReviews, pullRequests, prComments } from '../db/schema.js';
import { eq, and, gt } from 'drizzle-orm';

export type BranchProtectionRule = typeof branchProtectionRules.$inferSelect;

export async function getRulesForRepo(repoId: string): Promise<BranchProtectionRule[]> {
  return db.select().from(branchProtectionRules).where(eq(branchProtectionRules.repoId, repoId));
}

export function matchesPattern(branch: string, pattern: string): boolean {
  if (pattern === branch) return true;
  return minimatch(branch, pattern, { dot: true });
}

export function findMatchingRule(
  branch: string,
  rules: BranchProtectionRule[],
): BranchProtectionRule | null {
  // More specific (longer) patterns take precedence
  const matching = rules
    .filter((r) => matchesPattern(branch, r.pattern))
    .sort((a, b) => b.pattern.length - a.pattern.length);
  return matching[0] ?? null;
}

export interface PushCheckResult {
  allowed: boolean;
  reason?: string;
}

export async function checkPushAllowed(
  repoId: string,
  branch: string,
  userId: string,
  isForcePush: boolean,
): Promise<PushCheckResult> {
  const rules = await getRulesForRepo(repoId);
  const rule = findMatchingRule(branch, rules);
  if (!rule) return { allowed: true };

  if (isForcePush && rule.blockForcePush) {
    return { allowed: false, reason: `Force push to '${branch}' is blocked by branch protection` };
  }

  if (rule.requirePullRequest) {
    return { allowed: false, reason: `Direct push to '${branch}' is not allowed — open a pull request` };
  }

  if (rule.restrictPushers) {
    const allowed = (rule.allowedPusherIds as string[]).includes(userId);
    if (!allowed) {
      return { allowed: false, reason: `You are not in the allowed pushers list for '${branch}'` };
    }
  }

  return { allowed: true };
}

export interface MergeCheckResult {
  allowed: boolean;
  reason?: string;
}

export async function checkMergeAllowed(prId: string): Promise<MergeCheckResult> {
  const [pr] = await db.select().from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
  if (!pr) return { allowed: false, reason: 'PR not found' };

  const rules = await getRulesForRepo(pr.repoId);
  const rule = findMatchingRule(pr.targetBranch, rules);
  if (!rule) return { allowed: true };

  if (rule.requiredApprovals > 0) {
    const reviews = await db
      .select()
      .from(prReviews)
      .where(and(eq(prReviews.prId, prId), eq(prReviews.state, 'approved')));

    let approvals = reviews;

    // If dismissStaleReviews is on, only count approvals that came after the last commit push.
    // We approximate "last push" as the most recent pr_comment with a commitSha, since
    // we don't track force-push timestamps separately.
    if (rule.dismissStaleReviews && approvals.length > 0) {
      const [lastCommitRef] = await db
        .select({ createdAt: prComments.createdAt })
        .from(prComments)
        .where(and(eq(prComments.prId, prId), gt(prComments.commitSha, '')))
        .orderBy(prComments.createdAt)
        .limit(1);
      if (lastCommitRef) {
        approvals = approvals.filter((r) => r.submittedAt > lastCommitRef.createdAt);
      }
    }

    const uniqueApprovers = new Set(approvals.map((r) => r.reviewerId));

    if (uniqueApprovers.size < rule.requiredApprovals) {
      return {
        allowed: false,
        reason: `Branch '${pr.targetBranch}' requires ${rule.requiredApprovals} approval(s); found ${uniqueApprovers.size}`,
      };
    }
  }

  return { allowed: true };
}
