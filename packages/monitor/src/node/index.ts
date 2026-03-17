// Node.js entry point — re-exports everything from main plus Node.js-specific setup
export { ShipSafe, getClient, ShipSafeClient, scrubEvent } from '../index.js';
export { errorHandler } from '../adapters/express.js';
export { setupNextjs } from '../adapters/nextjs.js';
export { createErrorHandler } from '../adapters/react.js';
export { setupErrorCapture } from '../capture/errors.js';

export type {
  ShipSafeConfig,
  ShipSafeEvent,
  ErrorEvent,
  PerformanceEvent,
  ApiErrorEvent,
} from '../core/types.js';
