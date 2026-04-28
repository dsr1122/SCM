import { execFile } from 'child_process';
import { promisify } from 'util';
import { rm, mkdir, copyFile, chmod } from 'fs/promises';
import path from 'path';
import { config } from '../config.js';
import { fileURLToPath } from 'url';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// UUID-based disk path prevents path traversal — user input never touches the filesystem path.
export function repoDiskPath(repoId: string): string {
  // e.g. /data/repos/ab/cd1234-...uuid.git
  const shard = repoId.slice(0, 2);
  return path.join(config.gitReposRoot, shard, `${repoId}.git`);
}

export async function initBareRepo(repoId: string, diskPath: string): Promise<void> {
  const dir = path.dirname(diskPath);
  await mkdir(dir, { recursive: true });
  await execFileAsync('git', ['init', '--bare', diskPath]);

  // Set safe defaults
  await execFileAsync('git', ['-C', diskPath, 'config', 'receive.denyNonFastForwards', 'false']);
  await execFileAsync('git', ['-C', diskPath, 'config', 'receive.denyDeleteCurrent', 'true']);

  // Install pre-receive hook
  const hookSource = path.join(__dirname, '../hooks/pre-receive.js');
  const hookDest = path.join(diskPath, 'hooks', 'pre-receive');
  try {
    await copyFile(hookSource, hookDest);
    await chmod(hookDest, 0o755);
  } catch (err) {
    console.error(`[repo] failed to install pre-receive hook for ${repoId}:`, err);
  }
}

export async function deleteBareRepo(diskPath: string): Promise<void> {
  await rm(diskPath, { recursive: true, force: true });
}

export async function listBranches(diskPath: string): Promise<string[]> {
  const { stdout } = await execFileAsync('git', ['-C', diskPath, 'branch', '--format=%(refname:short)']);
  return stdout.split('\n').filter(Boolean);
}

export async function listTags(diskPath: string): Promise<string[]> {
  const { stdout } = await execFileAsync('git', ['-C', diskPath, 'tag']);
  return stdout.split('\n').filter(Boolean);
}

export async function getCommits(
  diskPath: string,
  branch: string,
  limit = 30,
  offset = 0,
): Promise<Array<{ sha: string; message: string; author: string; date: string }>> {
  const format = '%H%x1f%s%x1f%an%x1f%aI';
  const { stdout } = await execFileAsync('git', [
    '-C', diskPath, 'log',
    `--format=${format}`,
    `--skip=${offset}`,
    `-n`, String(limit),
    branch,
  ]);
  return stdout
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [sha = '', message = '', author = '', date = ''] = line.split('\x1f');
      return { sha, message, author, date };
    });
}

// Returns the merge-base commit SHA of two branches, or null if unrelated.
export async function mergeBase(diskPath: string, a: string, b: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('git', ['-C', diskPath, 'merge-base', a, b]);
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

// Fast-forward merge of sourceBranch into targetBranch. Returns merged commit SHA.
export async function fastForwardMerge(
  diskPath: string,
  sourceBranch: string,
  targetBranch: string,
): Promise<string> {
  // In a bare repo we operate on refs directly.
  const { stdout: sourceSha } = await execFileAsync('git', [
    '-C', diskPath, 'rev-parse', sourceBranch,
  ]);
  const sha = sourceSha.trim();
  await execFileAsync('git', ['-C', diskPath, 'update-ref', `refs/heads/${targetBranch}`, sha]);
  return sha;
}

// Create a true merge commit (non-fast-forward).
export async function mergeCommit(
  diskPath: string,
  sourceBranch: string,
  targetBranch: string,
  authorName: string,
  authorEmail: string,
): Promise<string> {
  const { stdout: targetSha } = await execFileAsync('git', ['-C', diskPath, 'rev-parse', targetBranch]);
  const { stdout: sourceSha } = await execFileAsync('git', ['-C', diskPath, 'rev-parse', sourceBranch]);
  const { stdout: treesha }   = await execFileAsync('git', ['-C', diskPath, 'rev-parse', `${sourceBranch}^{tree}`]);

  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: authorName,
    GIT_AUTHOR_EMAIL: authorEmail,
    GIT_COMMITTER_NAME: authorName,
    GIT_COMMITTER_EMAIL: authorEmail,
  };

  const message = `Merge branch '${sourceBranch}' into ${targetBranch}`;
  const { stdout: commitSha } = await execFileAsync(
    'git',
    ['-C', diskPath, 'commit-tree', treesha.trim(), '-p', targetSha.trim(), '-p', sourceSha.trim(), '-m', message],
    { env },
  );

  const sha = commitSha.trim();
  await execFileAsync('git', ['-C', diskPath, 'update-ref', `refs/heads/${targetBranch}`, sha]);
  return sha;
}
