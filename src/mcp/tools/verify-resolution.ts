import { loadConfig, getApiEndpoint } from '../../config/manager.js';

export interface VerifyResolutionParams {
  error_id: string;
}

export interface VerifyResolutionResult {
  error_id: string;
  status: 'resolved' | 'recurring' | 'unknown';
  last_occurrence?: string;
  hours_since_last?: number;
  confidence: number;
}

export async function handleVerifyResolution(
  params: VerifyResolutionParams,
): Promise<VerifyResolutionResult> {
  const { error_id } = params;
  const projectDir = process.cwd();
  const config = await loadConfig(projectDir);

  if (!config.projectId) {
    return {
      error_id,
      status: 'unknown',
      confidence: 0,
    };
  }

  const apiEndpoint = getApiEndpoint(config);
  const url = new URL(
    `/v1/errors/${config.projectId}/${error_id}/status`,
    apiEndpoint,
  );

  try {
    const response = await fetch(url.toString(), {
      headers: {
        ...(config.licenseKey ? { Authorization: `Bearer ${config.licenseKey}` } : {}),
      },
    });

    if (!response.ok) {
      return {
        error_id,
        status: 'unknown',
        confidence: 0,
      };
    }

    const data = (await response.json()) as {
      status: 'resolved' | 'recurring';
      last_occurrence: string;
      hours_since_last: number;
      confidence: number;
    };

    return {
      error_id,
      status: data.status,
      last_occurrence: data.last_occurrence,
      hours_since_last: data.hours_since_last,
      confidence: data.confidence,
    };
  } catch {
    return {
      error_id,
      status: 'unknown',
      confidence: 0,
    };
  }
}
