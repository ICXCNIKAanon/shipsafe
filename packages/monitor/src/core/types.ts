export interface ShipSafeConfig {
  projectId: string;
  endpoint?: string;
  environment?: string;
  release?: string;
  sampleRate?: number;
  performanceSampleRate?: number;
  debug?: boolean;
  beforeSend?: (event: ShipSafeEvent) => ShipSafeEvent | null;
}

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
