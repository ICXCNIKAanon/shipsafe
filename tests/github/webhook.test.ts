import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHmac } from 'node:crypto';

// Mock checks and scanner before importing webhook
vi.mock('../../src/github/checks.js', () => ({
  createCheckRun: vi.fn(),
  completeCheckRun: vi.fn(),
}));

vi.mock('../../src/github/scanner.js', () => ({
  scanPullRequest: vi.fn(),
}));

import { verifyWebhookSignature, handleWebhook, type WebhookEvent } from '../../src/github/webhook.js';
import { createCheckRun, completeCheckRun } from '../../src/github/checks.js';
import { scanPullRequest } from '../../src/github/scanner.js';

const mockedCreateCheckRun = vi.mocked(createCheckRun);
const mockedCompleteCheckRun = vi.mocked(completeCheckRun);
const mockedScanPullRequest = vi.mocked(scanPullRequest);

function makeEvent(action: string): WebhookEvent {
  return {
    action,
    pull_request: {
      number: 42,
      head: { sha: 'abc123', ref: 'feature-branch' },
      base: { sha: 'def456', ref: 'main' },
    },
    repository: {
      full_name: 'owner/repo',
      clone_url: 'https://github.com/owner/repo.git',
    },
    installation: { id: 12345 },
  };
}

function signPayload(payload: string, secret: string): string {
  return 'sha256=' + createHmac('sha256', secret).update(payload).digest('hex');
}

describe('verifyWebhookSignature', () => {
  const secret = 'test-webhook-secret';

  it('accepts a valid HMAC-SHA256 signature', () => {
    const payload = '{"hello":"world"}';
    const signature = signPayload(payload, secret);

    expect(verifyWebhookSignature(payload, signature, secret)).toBe(true);
  });

  it('rejects an invalid signature', () => {
    const payload = '{"hello":"world"}';
    const signature = 'sha256=invalid0000000000000000000000000000000000000000000000000000000000';

    expect(verifyWebhookSignature(payload, signature, secret)).toBe(false);
  });

  it('rejects a signature with wrong length', () => {
    const payload = '{"hello":"world"}';
    const signature = 'sha256=tooshort';

    expect(verifyWebhookSignature(payload, signature, secret)).toBe(false);
  });

  it('rejects signature computed with wrong secret', () => {
    const payload = '{"hello":"world"}';
    const signature = signPayload(payload, 'wrong-secret');

    expect(verifyWebhookSignature(payload, signature, secret)).toBe(false);
  });

  it('handles empty payload', () => {
    const payload = '';
    const signature = signPayload(payload, secret);

    expect(verifyWebhookSignature(payload, signature, secret)).toBe(true);
  });
});

describe('handleWebhook', () => {
  const secret = 'test-webhook-secret';

  beforeEach(() => {
    vi.clearAllMocks();

    mockedCreateCheckRun.mockResolvedValue(99);
    mockedScanPullRequest.mockResolvedValue({
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: 100,
    });
    mockedCompleteCheckRun.mockResolvedValue(undefined);
  });

  it('processes PR opened events', async () => {
    const event = makeEvent('opened');
    const payload = JSON.stringify(event);
    const signature = signPayload(payload, secret);

    await handleWebhook(event, signature, secret);

    expect(mockedCreateCheckRun).toHaveBeenCalledWith({
      repoFullName: 'owner/repo',
      headSha: 'abc123',
      installationId: 12345,
    });
    expect(mockedScanPullRequest).toHaveBeenCalledWith({
      repoFullName: 'owner/repo',
      prNumber: 42,
      headSha: 'abc123',
      baseSha: 'def456',
      installationId: 12345,
    });
    expect(mockedCompleteCheckRun).toHaveBeenCalledWith({
      repoFullName: 'owner/repo',
      checkRunId: 99,
      installationId: 12345,
      conclusion: 'success',
      findings: [],
    });
  });

  it('processes PR synchronize events', async () => {
    const event = makeEvent('synchronize');
    const payload = JSON.stringify(event);
    const signature = signPayload(payload, secret);

    await handleWebhook(event, signature, secret);

    expect(mockedCreateCheckRun).toHaveBeenCalled();
    expect(mockedScanPullRequest).toHaveBeenCalled();
    expect(mockedCompleteCheckRun).toHaveBeenCalled();
  });

  it('ignores non-PR events (e.g., closed)', async () => {
    const event = makeEvent('closed');
    const payload = JSON.stringify(event);
    const signature = signPayload(payload, secret);

    await handleWebhook(event, signature, secret);

    expect(mockedCreateCheckRun).not.toHaveBeenCalled();
    expect(mockedScanPullRequest).not.toHaveBeenCalled();
    expect(mockedCompleteCheckRun).not.toHaveBeenCalled();
  });

  it('ignores labeled events', async () => {
    const event = makeEvent('labeled');
    const payload = JSON.stringify(event);
    const signature = signPayload(payload, secret);

    await handleWebhook(event, signature, secret);

    expect(mockedCreateCheckRun).not.toHaveBeenCalled();
  });

  it('throws on invalid signature', async () => {
    const event = makeEvent('opened');

    await expect(
      handleWebhook(event, 'sha256=bad', secret),
    ).rejects.toThrow('Invalid webhook signature');
  });

  it('creates check run and completes it with failure on findings', async () => {
    mockedScanPullRequest.mockResolvedValue({
      status: 'fail',
      score: 'D',
      findings: [
        {
          id: 'finding-1',
          engine: 'pattern',
          severity: 'high',
          type: 'hardcoded-secret',
          file: 'config.ts',
          line: 10,
          description: 'Hardcoded API key detected',
          fix_suggestion: 'Use environment variables instead',
          auto_fixable: false,
        },
      ],
      scan_duration_ms: 200,
    });

    const event = makeEvent('opened');
    const payload = JSON.stringify(event);
    const signature = signPayload(payload, secret);

    await handleWebhook(event, signature, secret);

    expect(mockedCompleteCheckRun).toHaveBeenCalledWith(
      expect.objectContaining({
        conclusion: 'failure',
        findings: expect.arrayContaining([
          expect.objectContaining({ severity: 'high' }),
        ]),
      }),
    );
  });

  it('marks check as neutral if scanning throws', async () => {
    mockedScanPullRequest.mockRejectedValue(new Error('Scan exploded'));

    const event = makeEvent('opened');
    const payload = JSON.stringify(event);
    const signature = signPayload(payload, secret);

    await expect(handleWebhook(event, signature, secret)).rejects.toThrow('Scan exploded');

    // Check should have been completed as neutral
    expect(mockedCompleteCheckRun).toHaveBeenCalledWith(
      expect.objectContaining({
        conclusion: 'neutral',
        findings: [],
      }),
    );
  });
});
