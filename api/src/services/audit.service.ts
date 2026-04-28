import { db } from '../db/client.js';
import { auditLog } from '../db/schema.js';

export type AuditAction =
  | 'user.register' | 'user.login' | 'user.login_failed' | 'user.logout'
  | 'user.password_changed' | 'user.2fa_enabled' | 'user.2fa_disabled'
  | 'org.created' | 'org.deleted' | 'org.member_added' | 'org.member_removed' | 'org.member_role_changed'
  | 'repo.created' | 'repo.deleted' | 'repo.visibility_changed'
  | 'repo.collaborator_added' | 'repo.collaborator_removed' | 'repo.pushed'
  | 'pr.opened' | 'pr.merged' | 'pr.closed'
  | 'webhook.created' | 'webhook.deleted'
  | 'branch_protection.created' | 'branch_protection.deleted'
  | 'pat.created' | 'pat.revoked'
  | 'ssh_key.added' | 'ssh_key.removed'
  | 'sso.login';

export interface AuditEventInput {
  actorId?:      string | null;
  actorUsername?: string | null;
  action:        AuditAction;
  resourceType?: string;
  resourceId?:   string;
  orgId?:        string | null;
  repoId?:       string | null;
  metadata?:     Record<string, unknown>;
  ipAddress?:    string;
  userAgent?:    string;
}

// Fire-and-forget — audit failures must never break the main request.
export function logAuditEvent(event: AuditEventInput): void {
  setImmediate(() => {
    db.insert(auditLog).values({
      actorId:      event.actorId ?? null,
      actorUsername: event.actorUsername ?? null,
      action:       event.action,
      resourceType: event.resourceType ?? null,
      resourceId:   event.resourceId ?? null,
      orgId:        event.orgId ?? null,
      repoId:       event.repoId ?? null,
      metadata:     event.metadata ?? null,
      ipAddress:    event.ipAddress ?? null,
      userAgent:    event.userAgent ?? null,
    }).catch((err) => {
      console.error('[audit] failed to write audit log entry:', err);
    });
  });
}
