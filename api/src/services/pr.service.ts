import { db } from '../db/client.js';
import { pullRequests, repositories } from '../db/schema.js';
import { eq, sql } from 'drizzle-orm';
import { mergeBase, fastForwardMerge, mergeCommit } from './repo.service.js';
import { checkMergeAllowed } from './branchProtection.service.js';

export async function nextPrNumber(repoId: string): Promise<number> {
  const [row] = await db
    .select({ max: sql<number>`COALESCE(MAX(${pullRequests.number}), 0)` })
    .from(pullRequests)
    .where(eq(pullRequests.repoId, repoId));
  return (row?.max ?? 0) + 1;
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

  const base = await mergeBase(repo.diskPath, pr.sourceBranch, pr.targetBranch);
  let sha: string;
  let strategy: MergeResult['strategy'];

  if (base) {
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
