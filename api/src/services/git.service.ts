import { spawn } from 'child_process';
import type { FastifyRequest, FastifyReply } from 'fastify';

// Proxy a git smart-HTTP request to the local git process.
// cmd is either 'git-upload-pack' or 'git-receive-pack'.
export async function runGitProcess(
  req: FastifyRequest,
  reply: FastifyReply,
  cmd: 'git-upload-pack' | 'git-receive-pack',
  repoPath: string,
  stateless: boolean,
): Promise<void> {
  const args = stateless ? ['--stateless-rpc', repoPath] : [repoPath];
  const contentType = `application/x-${cmd}-result`;

  reply.raw.setHeader('Content-Type', contentType);
  reply.raw.setHeader('Cache-Control', 'no-cache');
  reply.raw.setHeader('Pragma', 'no-cache');
  reply.raw.setHeader('Expires', 'Fri, 01 Jan 1980 00:00:00 GMT');

  await new Promise<void>((resolve, reject) => {
    const proc = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    proc.stderr.on('data', (chunk: Buffer) => {
      req.log.warn(`[git] stderr: ${chunk.toString()}`);
    });

    proc.stdout.pipe(reply.raw, { end: false });

    proc.on('close', (code) => {
      reply.raw.end();
      if (code !== 0) reject(new Error(`${cmd} exited with code ${code}`));
      else resolve();
    });

    proc.on('error', reject);

    // Pipe request body to git stdin
    req.raw.pipe(proc.stdin);
    req.raw.on('error', () => proc.stdin.destroy());
  });
}

// Build the info/refs pkt-line response for stateless discovery.
export async function infoRefs(
  req: FastifyRequest,
  reply: FastifyReply,
  service: 'git-upload-pack' | 'git-receive-pack',
  repoPath: string,
): Promise<void> {
  const contentType = `application/x-${service}-advertisement`;
  reply.raw.setHeader('Content-Type', contentType);
  reply.raw.setHeader('Cache-Control', 'no-cache');

  // pkt-line header
  const header = `# service=${service}\n`;
  const headerLen = (header.length + 4).toString(16).padStart(4, '0');
  reply.raw.write(`${headerLen}${header}0000`);

  await runGitProcess(req, reply, service, repoPath, true);
}
