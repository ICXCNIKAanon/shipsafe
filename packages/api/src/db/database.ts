import Database from 'better-sqlite3';

let instance: Database.Database | null = null;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS errors (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'low',
  title TEXT NOT NULL,
  file TEXT NOT NULL DEFAULT 'unknown',
  line INTEGER NOT NULL DEFAULT 0,
  root_cause TEXT NOT NULL DEFAULT '',
  suggested_fix TEXT NOT NULL DEFAULT '',
  users_affected INTEGER NOT NULL DEFAULT 1,
  occurrences INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  stack_trace TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_errors_project ON errors(project_id);
CREATE INDEX IF NOT EXISTS idx_errors_status ON errors(project_id, status);

CREATE TABLE IF NOT EXISTS source_maps (
  project_id TEXT NOT NULL,
  release_version TEXT NOT NULL,
  file_path TEXT NOT NULL,
  content TEXT NOT NULL,
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (project_id, release_version, file_path)
);
`;

export function createDatabase(path: string = ':memory:'): Database.Database {
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  instance = db;
  return db;
}

export function getDatabase(): Database.Database {
  if (!instance) {
    throw new Error('Database has not been initialized. Call createDatabase() first.');
  }
  return instance;
}

export function closeDatabase(): void {
  if (instance) {
    instance.close();
    instance = null;
  }
}
