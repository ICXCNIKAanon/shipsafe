import type { ShipSafeClient } from '../core/client.js';
import type { PerformanceEvent } from '../core/types.js';

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof PerformanceObserver !== 'undefined';
}

export function setupPerformanceCapture(client: ShipSafeClient): () => void {
  if (!isBrowser()) {
    return () => {};
  }

  const observers: PerformanceObserver[] = [];

  const metrics: PerformanceEvent['metrics'] = {};

  // Observe paint entries (FCP)
  try {
    const paintObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name === 'first-contentful-paint') {
          metrics.first_contentful_paint_ms = Math.round(entry.startTime);
        }
      }
    });
    paintObserver.observe({ type: 'paint', buffered: true });
    observers.push(paintObserver);
  } catch {
    // Paint observer not supported
  }

  // Observe LCP
  try {
    const lcpObserver = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      if (entries.length > 0) {
        const lastEntry = entries[entries.length - 1];
        metrics.largest_contentful_paint_ms = Math.round(lastEntry.startTime);
      }
    });
    lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
    observers.push(lcpObserver);
  } catch {
    // LCP observer not supported
  }

  // Observe CLS
  try {
    let clsValue = 0;
    const clsObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (!(entry as PerformanceEntry & { hadRecentInput?: boolean }).hadRecentInput) {
          clsValue += (entry as PerformanceEntry & { value?: number }).value ?? 0;
          metrics.cumulative_layout_shift = Math.round(clsValue * 1000) / 1000;
        }
      }
    });
    clsObserver.observe({ type: 'layout-shift', buffered: true });
    observers.push(clsObserver);
  } catch {
    // CLS observer not supported
  }

  // Observe navigation timing for page load + TTFB
  try {
    const navObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const navEntry = entry as PerformanceNavigationTiming;
        if (navEntry.loadEventEnd > 0) {
          metrics.page_load_ms = Math.round(navEntry.loadEventEnd - navEntry.startTime);
        }
        if (navEntry.responseStart > 0) {
          metrics.time_to_first_byte_ms = Math.round(navEntry.responseStart - navEntry.startTime);
        }
      }
    });
    navObserver.observe({ type: 'navigation', buffered: true });
    observers.push(navObserver);
  } catch {
    // Navigation observer not supported
  }

  // Send performance event when page is about to unload
  const sendMetrics = () => {
    const hasMetrics = Object.keys(metrics).length > 0;
    if (hasMetrics) {
      const perfEvent: Omit<PerformanceEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
        type: 'performance',
        metrics: { ...metrics },
        url: typeof location !== 'undefined' ? location.href : '',
      };
      client.capture(perfEvent);
    }
  };

  // Use visibilitychange as the primary trigger (more reliable than unload)
  const onVisibilityChange = () => {
    if (document.visibilityState === 'hidden') {
      sendMetrics();
    }
  };

  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', onVisibilityChange);
  }

  return () => {
    for (const observer of observers) {
      observer.disconnect();
    }
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', onVisibilityChange);
    }
  };
}
