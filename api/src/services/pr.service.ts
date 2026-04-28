import { db } from '../db/client.js';
import { pullRequests, repositories } from '../db/schema.js';
import { eq, sql } from 'drizzle-orm';
import { mergeBase, fastForwardMerge, mergeCommit, revParse } from './repo.service.js';
import { checkMergeAllowed } from './branchProtection.service.js';

// Use a DB-level advisory lock per repo to make PR number assignment atomic.
// Without this, concurrent inserts race on MAX(number)+1 and produce duplicates.
export async function nextPrNumber(repoId: string): Promise<number> {
  // pg_advisory_xact_lock takes a bigint; hash the UUID into one.
  const [row] = await db.execute(sql`
    SELECT pg_advisory_xact_lock(abs(hashtext(${repoId}::text))),
           COALESCE(MAX(number), 0) + 1 AS next_number
    FROM pull_requests
    WHERE repo_id = ${repoId}::uuid
  `);
  return (row as unknown as { next_number: number }).next_number;
}

export type MergeResult = { sha: string; strategy: 'fast-forward' | 'merge-commit' };

export async function mergePullRequest(
  prId: string,
  authorName: string,
  authorEmail: string,
): Promise<MergeResult> {
  const [pr] = await db.select().from(pullRequests).where(eq(pullRequests.id, prId)).limit(1);
  if (!pr) throw new Error('PR not found');
  if (pr.status !== 'open') throw new Error(`PR is already ${pr.status}`);

  // Branch protection enforcement
  const mergeCheck = await checkMergeAllowed(prId);
  if (!mergeCheck.allowed) throw new Error(mergeCheck.reason ?? 'Merge blocked by branch protection');

  const [repo] = await db
    .select({ diskPath: repositories.diskPath })
    .from(repositories)
    .where(eq(repositories.id, pr.repoId))
    .limit(1);
  if (!repo) throw new Error('Repository not found');

  // Fast-forward is only possible when the target's tip IS the merge-base
  // (i.e., target has not diverged from source's history).
  const targetTip = await revParse(repo.diskPath, pr.targetBranch);
  const base = await mergeBase(repo.diskPath, pr.sourceBranch, pr.targetBranch);

  let sha: string;
  let strategy: MergeResult['strategy'];

  if (base && base === targetTip) {
    sha = await fastForwardMerge(repo.diskPath, pr.sourceBranch, pr.targetBranch);
    strategy = 'fast-forward';
  } else {
    sha = await mergeCommit(repo.diskPath, pr.sourceBranch, pr.targetBranch, authorName, authorEmail);
    strategy = 'merge-commit';
  }

  await db.update(pullRequests)
    .set({ status: 'merged', mergedCommitSha: sha, updatedAt: new Date() })
    .where(eq(pullRequests.id, prId));

  return { sha, strategy };
}
