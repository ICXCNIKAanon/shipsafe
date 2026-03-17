import type { ShipSafeConfig, ShipSafeEvent } from './types.js';
import { scrubEvent } from './scrubber.js';

const DEFAULT_ENDPOINT = 'https://shipsafe-m9nc6.ondigitalocean.app/v1/ingest';
const FLUSH_INTERVAL_MS = 5000;
const BATCH_SIZE = 10;
const MAX_QUEUE_SIZE = 100;
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY_MS = 1000;

interface ResolvedConfig {
  projectId: string;
  endpoint: string;
  environment: string;
  release: string | undefined;
  sampleRate: number;
  performanceSampleRate: number;
  debug: boolean;
  beforeSend: ((event: ShipSafeEvent) => ShipSafeEvent | null) | undefined;
}

function detectEnvironment(): string {
  if (typeof process !== 'undefined' && process.env) {
    return (
      process.env.NODE_ENV ??
      process.env.VERCEL_ENV ??
      process.env.ENVIRONMENT ??
      'production'
    );
  }
  return 'production';
}

function generateSessionId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback for older environments
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

const SELF_ERROR_THRESHOLD = 3;

export class ShipSafeClient {
  private queue: ShipSafeEvent[] = [];
  private config: ResolvedConfig;
  private sessionId: string;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private destroyed = false;
  private _selfErrorCount: number = 0;
  private _disabled: boolean = false;

  constructor(config: ShipSafeConfig) {
    this.config = {
      projectId: config.projectId,
      endpoint: config.endpoint ?? DEFAULT_ENDPOINT,
      environment: config.environment ?? detectEnvironment(),
      release: config.release,
      sampleRate: config.sampleRate ?? 1.0,
      performanceSampleRate: config.performanceSampleRate ?? 1.0,
      debug: config.debug ?? false,
      beforeSend: config.beforeSend,
    };
    this.sessionId = generateSessionId();
    this.flushTimer = setInterval(() => {
      void this.flush();
    }, FLUSH_INTERVAL_MS);

    // Allow the timer to not keep the process alive
    if (this.flushTimer && typeof this.flushTimer === 'object' && 'unref' in this.flushTimer) {
      (this.flushTimer as NodeJS.Timeout).unref();
    }
  }

  capture(event: Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>): void {
    if (this.destroyed) return;
    if (this._disabled) return;

    // Apply sampling
    if (event.type === 'performance') {
      if (Math.random() > this.config.performanceSampleRate) return;
    } else {
      if (Math.random() > this.config.sampleRate) return;
    }

    const fullEvent: ShipSafeEvent = {
      ...event,
      project_id: this.config.projectId,
      session_id: this.sessionId,
      timestamp: new Date().toISOString(),
      environment: this.config.environment,
      ...(this.config.release ? { release: this.config.release } : {}),
    };

    // Apply PII scrubbing
    const scrubbed = scrubEvent(fullEvent);

    // Apply beforeSend hook
    let finalEvent: ShipSafeEvent | null = scrubbed;
    if (this.config.beforeSend) {
      finalEvent = this.config.beforeSend(scrubbed);
      if (!finalEvent) {
        if (this.config.debug) {
          console.log('[ShipSafe] Event dropped by beforeSend hook');
        }
        return;
      }
    }

    // Enforce max queue size
    if (this.queue.length >= MAX_QUEUE_SIZE) {
      if (this.config.debug) {
        console.warn('[ShipSafe] Queue full, dropping oldest event');
      }
      this.queue.shift();
    }

    this.queue.push(finalEvent);

    if (this.config.debug) {
      console.log('[ShipSafe] Event captured:', finalEvent.type);
    }

    // Auto-flush when batch size reached
    if (this.queue.length >= BATCH_SIZE) {
      void this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    const events = this.queue.splice(0);

    if (this.config.debug) {
      console.log(`[ShipSafe] Flushing ${events.length} events`);
    }

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const response = await fetch(this.config.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            project_id: this.config.projectId,
            events,
          }),
        });

        if (response.ok) {
          if (this.config.debug) {
            console.log('[ShipSafe] Flush successful');
          }
          return;
        }

        // Server error — retry
        if (response.status >= 500) {
          if (this.config.debug) {
            console.warn(`[ShipSafe] Server error ${response.status}, retrying (${attempt + 1}/${MAX_RETRIES})`);
          }
          if (attempt < MAX_RETRIES - 1) {
            await this.delay(BASE_RETRY_DELAY_MS * Math.pow(2, attempt));
            continue;
          }
        }

        // Client error — do not retry
        if (this.config.debug) {
          console.error(`[ShipSafe] Flush failed with status ${response.status}`);
        }
        return;
      } catch (err) {
        if (this.config.debug) {
          console.warn(`[ShipSafe] Flush error, retrying (${attempt + 1}/${MAX_RETRIES}):`, err);
        }
        if (attempt < MAX_RETRIES - 1) {
          await this.delay(BASE_RETRY_DELAY_MS * Math.pow(2, attempt));
        }
      }
    }

    if (this.config.debug) {
      console.error('[ShipSafe] Flush failed after all retries');
    }

    this._selfErrorCount++;
    if (this._selfErrorCount >= SELF_ERROR_THRESHOLD) {
      this._disabled = true;
      console.warn('[ShipSafe] Monitor auto-disabled after repeated errors. Events will not be captured.');
    }
  }

  getSessionId(): string {
    return this.sessionId;
  }

  getQueueLength(): number {
    return this.queue.length;
  }

  isDisabled(): boolean {
    return this._disabled;
  }

  disable(): void {
    this._disabled = true;
  }

  enable(): void {
    this._disabled = false;
  }

  destroy(): void {
    this.destroyed = true;
    if (this.flushTimer !== null) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
