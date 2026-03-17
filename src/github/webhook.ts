import { createHmac, timingSafeEqual } from 'node:crypto';
import { createCheckRun, completeCheckRun } from './checks.js';
import { scanPullRequest } from './scanner.js';

export interface WebhookEvent {
  action: string;
  pull_request: {
    number: number;
    head: { sha: string; ref: string };
    base: { sha: string; ref: string };
  };
  repository: {
    full_name: string;
    clone_url: string;
  };
  installation: { id: number };
}

/**
 * Verify a GitHub webhook signature using HMAC-SHA256.
 * Compares the computed signature against the provided one using timing-safe comparison.
 */
export function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string,
): boolean {
  const computed = 'sha256=' + createHmac('sha256', secret).update(payload).digest('hex');

  // Both must have the same length for timingSafeEqual
  if (computed.length !== signature.length) {
    return false;
  }

  try {
    return timingSafeEqual(Buffer.from(computed), Buffer.from(signature));
  } catch {
    return false;
  }
}

/**
 * Process a GitHub webhook event.
 *
 * Flow:
 * 1. Verify webhook signature
 * 2. If action is 'opened' or 'synchronize':
 *    a. Create a pending check run via GitHub Checks API
 *    b. Scan the PR diff
 *    c. Post check run result (pass/fail with findings summary)
 * 3. Ignore other actions
 */
export async function handleWebhook(
  event: WebhookEvent,
  signature: string,
  secret: string,
): Promise<void> {
  // 1. Verify signature
  const payload = JSON.stringify(event);
  if (!verifyWebhookSignature(payload, signature, secret)) {
    throw new Error('Invalid webhook signature');
  }

  // 2. Only process PR opened and synchronize events
  if (event.action !== 'opened' && event.action !== 'synchronize') {
    return;
  }

  const { pull_request: pr, repository, installation } = event;

  // 2a. Create a pending check run
  const checkRunId = await createCheckRun({
    repoFullName: repository.full_name,
    headSha: pr.head.sha,
    installationId: installation.id,
  });

  try {
    // 2b. Scan the PR diff
    const scanResult = await scanPullRequest({
      repoFullName: repository.full_name,
      prNumber: pr.number,
      headSha: pr.head.sha,
      baseSha: pr.base.sha,
      installationId: installation.id,
    });

    // 2c. Determine conclusion and post result
    const conclusion = scanResult.status === 'fail' ? 'failure' : 'success';

    await completeCheckRun({
      repoFullName: repository.full_name,
      checkRunId,
      installationId: installation.id,
      conclusion,
      findings: scanResult.findings,
    });
  } catch (err) {
    // If scanning fails, mark the check as neutral with an error message
    await completeCheckRun({
      repoFullName: repository.full_name,
      checkRunId,
      installationId: installation.id,
      conclusion: 'neutral',
      findings: [],
    });

    throw err;
  }
}
