import { config } from '../config.js';
import { db } from '../db/client.js';
import { users, notificationPreferences } from '../db/schema.js';
import { eq } from 'drizzle-orm';

type Transporter = import('nodemailer').Transporter;
let _transporter: Transporter | null = null;

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function getTransporter(): Promise<Transporter | null> {
  if (!config.smtp.host) return null;
  if (_transporter) return _transporter;

  const nodemailer = await import('nodemailer');
  _transporter = nodemailer.createTransport({
    host:   config.smtp.host,
    port:   config.smtp.port,
    secure: config.smtp.secure,
    auth:   config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass ?? '' } : undefined,
  });
  return _transporter;
}

async function getUserEmailPrefs(userId: string): Promise<{ email: string; emailEnabled: boolean; notifyPrReview: boolean; notifyOrgInvite: boolean } | null> {
  const [row] = await db
    .select({ email: users.email, userId: notificationPreferences.userId, emailEnabled: notificationPreferences.emailEnabled, notifyPrReview: notificationPreferences.notifyPrReview, notifyOrgInvite: notificationPreferences.notifyOrgInvite })
    .from(users)
    .leftJoin(notificationPreferences, eq(notificationPreferences.userId, users.id))
    .where(eq(users.id, userId))
    .limit(1);
  if (!row) return null;
  return { email: row.email, emailEnabled: row.emailEnabled ?? true, notifyPrReview: row.notifyPrReview ?? true, notifyOrgInvite: row.notifyOrgInvite ?? true };
}

async function sendMail(to: string, subject: string, text: string, html: string): Promise<void> {
  const transporter = await getTransporter();
  if (!transporter) {
    console.log(`[email] SMTP not configured — skipping: ${subject} → ${to}`);
    return;
  }
  await transporter.sendMail({ from: config.smtp.from, to, subject, text, html });
}

export function notifyPrReviewSubmitted(prAuthorId: string, reviewerUsername: string, prTitle: string, prUrl: string): void {
  setImmediate(async () => {
    const prefs = await getUserEmailPrefs(prAuthorId);
    if (!prefs?.emailEnabled || !prefs.notifyPrReview) return;

    const subject = `[SCM] ${reviewerUsername} reviewed your PR: ${prTitle}`;
    const text = `${reviewerUsername} submitted a review on your pull request "${prTitle}".\n\nView it at: ${prUrl}`;
    const html = `<p><strong>${esc(reviewerUsername)}</strong> submitted a review on your pull request <strong>${esc(prTitle)}</strong>.</p><p><a href="${esc(prUrl)}">View pull request</a></p>`;
    await sendMail(prefs.email, subject, text, html).catch((e) => console.error('[email]', e));
  });
}

export function notifyPrCommentAdded(prAuthorId: string, commenterUsername: string, prTitle: string, prUrl: string): void {
  setImmediate(async () => {
    const prefs = await getUserEmailPrefs(prAuthorId);
    if (!prefs?.emailEnabled || !prefs.notifyPrReview) return;

    const subject = `[SCM] ${commenterUsername} commented on your PR: ${prTitle}`;
    const text = `${commenterUsername} commented on your pull request "${prTitle}".\n\nView it at: ${prUrl}`;
    const html = `<p><strong>${esc(commenterUsername)}</strong> commented on your pull request <strong>${esc(prTitle)}</strong>.</p><p><a href="${esc(prUrl)}">View pull request</a></p>`;
    await sendMail(prefs.email, subject, text, html).catch((e) => console.error('[email]', e));
  });
}

export function notifyPrMergedOrClosed(prAuthorId: string, actorUsername: string, prTitle: string, prUrl: string, action: 'merged' | 'closed'): void {
  setImmediate(async () => {
    const prefs = await getUserEmailPrefs(prAuthorId);
    if (!prefs?.emailEnabled || !prefs.notifyPrReview) return;

    const subject = `[SCM] Your PR was ${action}: ${prTitle}`;
    const text = `${actorUsername} ${action} your pull request "${prTitle}".\n\nView it at: ${prUrl}`;
    const html = `<p><strong>${esc(actorUsername)}</strong> ${action} your pull request <strong>${esc(prTitle)}</strong>.</p><p><a href="${esc(prUrl)}">View pull request</a></p>`;
    await sendMail(prefs.email, subject, text, html).catch((e) => console.error('[email]', e));
  });
}

export function notifyOrgInvite(inviteeId: string, orgName: string, inviterUsername: string): void {
  setImmediate(async () => {
    const prefs = await getUserEmailPrefs(inviteeId);
    if (!prefs?.emailEnabled || !prefs.notifyOrgInvite) return;

    const subject = `[SCM] You've been invited to ${orgName}`;
    const text = `${inviterUsername} has added you to the organization "${orgName}".`;
    const html = `<p><strong>${esc(inviterUsername)}</strong> has added you to the organization <strong>${esc(orgName)}</strong>.</p>`;
    await sendMail(prefs.email, subject, text, html).catch((e) => console.error('[email]', e));
  });
}
