import { loadConfig } from '../../config/manager.js';

export interface ProductionErrorsParams {
  severity?: 'all' | 'critical' | 'high' | 'medium' | 'low';
  status?: 'open' | 'resolved' | 'all';
}

export interface ProductionError {
  id: string;
  message: string;
  severity: string;
  status: string;
  stack_trace?: string;
  root_cause?: string;
  suggested_fix?: string;
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface ProductionErrorsResult {
  errors: ProductionError[];
  total: number;
  warning?: string;
}

export async function handleProductionErrors(
  params: ProductionErrorsParams,
): Promise<ProductionErrorsResult> {
  const projectDir = process.cwd();
  const config = await loadConfig(projectDir);

  if (!config.projectId) {
    return {
      errors: [],
      total: 0,
      warning: 'No project ID configured. Run `shipsafe setup` to connect this project.',
    };
  }

  if (!config.apiEndpoint) {
    return {
      errors: [],
      total: 0,
      warning: 'No API endpoint configured. Set apiEndpoint in shipsafe.config.json.',
    };
  }

  const severity = params.severity ?? 'all';
  const status = params.status ?? 'open';

  const url = new URL(`/v1/errors/${config.projectId}`, config.apiEndpoint);
  url.searchParams.set('severity', severity);
  url.searchParams.set('status', status);

  try {
    const response = await fetch(url.toString(), {
      headers: {
        ...(config.licenseKey ? { Authorization: `Bearer ${config.licenseKey}` } : {}),
      },
    });

    if (!response.ok) {
      return {
        errors: [],
        total: 0,
        warning: `API returned ${response.status}: ${response.statusText}`,
      };
    }

    const data = (await response.json()) as { errors: ProductionError[]; count: number };

    return {
      errors: data.errors,
      total: data.count,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      errors: [],
      total: 0,
      warning: `Failed to fetch production errors: ${message}`,
    };
  }
}
