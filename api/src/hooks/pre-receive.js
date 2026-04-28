#!/usr/bin/env node
const REPO_ID = process.env['SCM_REPO_ID'];
const USER_ID = process.env['SCM_USER_ID'];
const API_URL = process.env['SCM_INTERNAL_API_URL'] || 'http://localhost:3000';

if (!REPO_ID || !USER_ID) {
  // Missing env means the hook was invoked outside SCM — deny.
  process.stderr.write('\n[SCM] Push rejected: hook environment not configured\n\n');
  process.exit(1);
}

const SHA_RE = /^[0-9a-f]{40}$/i;

function parseUpdates(input) {
  return input
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(' ');
      if (parts.length !== 3) return null;
      const [oldSha, newSha, ref] = parts;
      // Validate SHA format to prevent injection into downstream JSON
      if (!SHA_RE.test(oldSha) || !SHA_RE.test(newSha)) return null;
      if (!ref || !ref.startsWith('refs/')) return null;
      return { oldSha, newSha, ref };
    })
    .filter(Boolean);
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = Buffer.concat(chunks).toString('utf8');
  const updates = parseUpdates(input);

  if (updates.length === 0) process.exit(0);

  let res;
  try {
    res = await fetch(`${API_URL}/admin/internal/check-push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoId: REPO_ID, userId: USER_ID, updates }),
    });
  } catch (err) {
    process.stderr.write(`\n[SCM] Internal error validating push: ${err}\n\n`);
    process.exit(1);
  }

  if (!res.ok) {
    let msg = 'Unknown error';
    try { msg = (await res.json()).error ?? msg; } catch { /* ignore */ }
    process.stderr.write(`\n[SCM] Push rejected: ${msg}\n\n`);
    process.exit(1);
  }

  process.exit(0);
}

main();
