import { getDatabase } from './database.js';

export function dbStoreSourceMap(
  projectId: string,
  release: string,
  filePath: string,
  content: string
): void {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO source_maps (project_id, release_version, file_path, content)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(project_id, release_version, file_path) DO UPDATE SET
      content = excluded.content
  `).run(projectId, release, filePath, content);
}

export function dbGetSourceMap(
  projectId: string,
  release: string,
  filePath: string
): string | undefined {
  const db = getDatabase();
  const row = db
    .prepare(
      `SELECT content FROM source_maps WHERE project_id = ? AND release_version = ? AND file_path = ?`
    )
    .get(projectId, release, filePath) as { content: string } | undefined;
  return row?.content;
}

export function dbListSourceMaps(projectId: string, release: string): string[] {
  const db = getDatabase();
  const rows = db
    .prepare(
      `SELECT file_path FROM source_maps WHERE project_id = ? AND release_version = ? ORDER BY file_path ASC`
    )
    .all(projectId, release) as { file_path: string }[];
  return rows.map((r) => r.file_path);
}
