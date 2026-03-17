// Incoming event types from @shipsafe/monitor

export interface ShipSafeEvent {
  type: 'error' | 'performance' | 'api_error';
  timestamp: string;
  project_id: string;
  environment: string;
  release?: string;
  session_id: string;
}

export interface ErrorEvent extends ShipSafeEvent {
  type: 'error';
  error: {
    name: string;
    message: string;
    stack?: string;
    handled: boolean;
  };
  context: {
    url?: string;
    method?: string;
    status_code?: number;
    user_agent?: string;
  };
}

export interface PerformanceEvent extends ShipSafeEvent {
  type: 'performance';
  metrics: {
    page_load_ms?: number;
    first_contentful_paint_ms?: number;
    largest_contentful_paint_ms?: number;
    cumulative_layout_shift?: number;
    interaction_to_next_paint_ms?: number;
    time_to_first_byte_ms?: number;
  };
  url: string;
}

export interface ApiErrorEvent extends ShipSafeEvent {
  type: 'api_error';
  request: {
    method: string;
    path: string;
    status_code: number;
    duration_ms: number;
  };
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

export type IncomingEvent = ErrorEvent | PerformanceEvent | ApiErrorEvent;

// Ingest request body (matches what the monitor client sends)
export interface IngestBody {
  project_id: string;
  events: IncomingEvent[];
}

// Processed error stored in the API
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface ProcessedError {
  id: string;
  project_id: string;
  severity: Severity;
  title: string;
  file: string;
  line: number;
  root_cause: string;
  suggested_fix: string;
  users_affected: number;
  occurrences: number;
  first_seen: string;
  last_seen: string;
  status: 'open' | 'resolved';
  stack_trace: string;
}

export interface RootCauseAnalysis {
  root_cause: string;
  originating_function: string;
  originating_file: string;
  suggested_fix: string;
}

// Hono context variables (for c.set / c.get)
export interface AppVariables {
  projectId: string;
  parsedBody: IngestBody;
}

// License types
export type LicenseTier = 'free' | 'pro' | 'team' | 'agency';

export interface LicenseInfo {
  valid: boolean;
  tier: LicenseTier;
  expires_at: string;
  project_limit: number;
}
