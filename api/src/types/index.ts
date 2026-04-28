export type OrgRole = 'owner' | 'admin' | 'member' | 'guest';
export type RepoRole = 'admin' | 'write' | 'read';
export type PrStatus = 'open' | 'closed' | 'merged';
export type ReviewState = 'approved' | 'changes_requested' | 'commented';
export type WebhookEvent = 'push' | 'pull_request';

export interface JwtPayload {
  sub: string;       // user id
  username: string;
  iat: number;
  exp: number;
}

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  isSuperadmin: boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
  }
}
