#!/usr/bin/env node
import { lookup } from 'dns/promises';
import { readFileSync } from 'fs';

// This script is intended to be used as a git pre-receive hook.
// It reads commands from stdin and calls the SCM API to validate the push.

const REPO_ID = process.env['SCM_REPO_ID'];
const USER_ID = process.env['SCM_USER_ID'];
const API_URL = process.env['SCM_INTERNAL_API_URL'] || 'http://localhost:3000';

if (!REPO_ID || !USER_ID) {
  process.exit(0); // If not configured, allow push (fail-open for safety, or fail-closed?)
}

async function main() {
  const input = readFileSync(0, 'utf8');
  const lines = input.split('\n').filter(Boolean);
  const updates = lines.map(line => {
    const [oldSha, newSha, ref] = line.split(' ');
    return { oldSha, newSha, ref };
  });

  try {
    const res = await fetch(`${API_URL}/admin/internal/check-push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoId: REPO_ID, userId: USER_ID, updates }),
    });

    if (!res.ok) {
      const data = await res.json();
      console.error(`\n[SCM] Push rejected: ${data.error || 'Unknown error'}\n`);
      process.exit(1);
    }
  } catch (err) {
    console.error(`\n[SCM] Internal error validating push: ${err}\n`);
    process.exit(1);
  }
}

main();
