/**
 * In-memory source map store. Source maps are keyed by projectId + release + filePath.
 * Phase 6 will add a PostgreSQL adapter.
 */
const store = new Map<string, string>();

function makeKey(projectId: string, release: string, filePath: string): string {
  return `${projectId}::${release}::${filePath}`;
}

function parseKey(key: string): { projectId: string; release: string; filePath: string } {
  const [projectId, release, ...rest] = key.split('::');
  return { projectId, release, filePath: rest.join('::') };
}

export function storeSourceMap(
  projectId: string,
  release: string,
  filePath: string,
  content: string,
): void {
  store.set(makeKey(projectId, release, filePath), content);
}

export function getSourceMap(
  projectId: string,
  release: string,
  filePath: string,
): string | undefined {
  return store.get(makeKey(projectId, release, filePath));
}

export function listSourceMaps(projectId: string, release: string): string[] {
  const prefix = `${projectId}::${release}::`;
  const filePaths: string[] = [];

  for (const key of store.keys()) {
    if (key.startsWith(prefix)) {
      const { filePath } = parseKey(key);
      filePaths.push(filePath);
    }
  }

  return filePaths.sort();
}

export function clearSourceMapStore(): void {
  store.clear();
}
