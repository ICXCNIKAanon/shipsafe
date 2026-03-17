import { SourceMapConsumer } from 'source-map';
import { dbGetSourceMap } from '../db/sourcemap-repo.js';

interface ResolvedFrame {
  file: string;
  line: number;
  column?: number;
  name?: string;
}

export async function resolveStackFrame(
  projectId: string,
  release: string,
  file: string,
  line: number,
  column?: number,
): Promise<ResolvedFrame> {
  // Try to find source map
  const mapContent =
    dbGetSourceMap(projectId, release, file + '.map') ??
    dbGetSourceMap(projectId, release, file);

  if (!mapContent) {
    return { file, line };
  }

  try {
    const rawMap = JSON.parse(mapContent);

    // If no mappings or no column info, fall back to source extraction
    if (!rawMap.mappings || column === undefined) {
      return extractSourceFallback(rawMap, file, line);
    }

    const consumer = await new SourceMapConsumer(rawMap);
    try {
      const pos = consumer.originalPositionFor({ line, column });

      if (pos.source && !pos.source.includes('node_modules')) {
        const cleanPath = pos.source.replace(/^(\.\.\/)+/, '');
        return {
          file: cleanPath,
          line: pos.line ?? line,
          column: pos.column ?? undefined,
          name: pos.name ?? undefined,
        };
      }
    } finally {
      consumer.destroy();
    }

    // VLQ lookup returned no source — fall back to source array extraction
    return extractSourceFallback(rawMap, file, line);
  } catch {
    // Fall through to fallback
  }

  return { file, line };
}

// Fallback when we don't have column info or VLQ fails
function extractSourceFallback(
  map: { sources?: string[] },
  file: string,
  line: number,
): ResolvedFrame {
  if (map.sources && map.sources.length > 0) {
    const originalSource = map.sources.find((s: string) => !s.includes('node_modules'));
    if (!originalSource) {
      return { file, line };
    }
    const cleanPath = originalSource.replace(/^(\.\.\/)+/, '');
    return { file: cleanPath, line };
  }
  return { file, line };
}
