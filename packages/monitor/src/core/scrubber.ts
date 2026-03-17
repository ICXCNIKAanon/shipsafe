import type { ShipSafeEvent } from './types.js';

const patterns: Array<{ regex: RegExp; replacement: string }> = [
  // Email addresses
  { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[email]' },
  // SSN (must come before phone to avoid overlap)
  { regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[ssn]' },
  // Credit card numbers (13-19 digits, optionally separated by spaces or dashes)
  { regex: /\b\d[\d -]{12,22}\d\b/g, replacement: '[card]' },
  // Phone numbers (various formats)
  { regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[phone]' },
  // IPv4 addresses
  { regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, replacement: '[ip]' },
  // JWT tokens (three base64url parts separated by dots)
  { regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, replacement: '[token]' },
];

function scrubString(value: string): string {
  let result = value;
  for (const { regex, replacement } of patterns) {
    // Reset lastIndex since we reuse the regex objects
    regex.lastIndex = 0;
    result = result.replace(regex, replacement);
  }
  return result;
}

function scrubValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return scrubString(value);
  }
  if (Array.isArray(value)) {
    return value.map(scrubValue);
  }
  if (value !== null && typeof value === 'object') {
    const scrubbed: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      scrubbed[key] = scrubValue(val);
    }
    return scrubbed;
  }
  return value;
}

export function scrubEvent<T extends ShipSafeEvent>(event: T): T {
  return scrubValue(event) as T;
}
