import { createSign } from 'node:crypto';

/**
 * Generate a JWT for GitHub App authentication.
 * Uses RS256 signing with the App's private key.
 */
export function generateJwt(appId: string, privateKey: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      iat: now - 60, // issued 60s ago to account for clock drift
      exp: now + 600, // expires in 10 minutes
      iss: appId,
    }),
  ).toString('base64url');

  const unsigned = `${header}.${payload}`;
  const signer = createSign('RSA-SHA256');
  signer.update(unsigned);
  const signature = signer.sign(privateKey, 'base64url');

  return `${unsigned}.${signature}`;
}

/**
 * Get an installation access token for GitHub API calls.
 * Requires SHIPSAFE_GITHUB_APP_ID and SHIPSAFE_GITHUB_PRIVATE_KEY env vars.
 */
export async function getInstallationToken(installationId: number): Promise<string> {
  const appId = process.env.SHIPSAFE_GITHUB_APP_ID;
  const privateKey = process.env.SHIPSAFE_GITHUB_PRIVATE_KEY;

  if (!appId || !privateKey) {
    throw new Error(
      'Missing SHIPSAFE_GITHUB_APP_ID or SHIPSAFE_GITHUB_PRIVATE_KEY environment variables',
    );
  }

  const jwt = generateJwt(appId, privateKey);

  const response = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
  );

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Failed to get installation token: ${response.status} ${body}`);
  }

  const data = (await response.json()) as { token: string };
  return data.token;
}

/**
 * Make an authenticated GitHub API request.
 */
export async function githubApi(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    token: string;
  },
): Promise<unknown> {
  const url = path.startsWith('https://') ? path : `https://api.github.com${path}`;

  const headers: Record<string, string> = {
    Authorization: `token ${options.token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };

  const fetchOptions: RequestInit = {
    method: options.method ?? 'GET',
    headers,
  };

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    fetchOptions.body = JSON.stringify(options.body);
  }

  const response = await fetch(url, fetchOptions);

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub API error: ${response.status} ${body}`);
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  return response.text();
}
