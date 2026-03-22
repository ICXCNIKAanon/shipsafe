// Simulated Express-like handler with a vulnerability:
// handleUserSearch calls db.query without any validation or sanitization.

import { query } from './database';
import { checkAuth } from './auth';

export async function handleUserSearch(req: any, res: any) {
  const searchTerm = req.query.q;
  // VULNERABILITY: raw user input goes directly to SQL query
  const results = query(`SELECT * FROM users WHERE name = '${searchTerm}'`);
  res.json(results);
}

export async function handleDeleteUser(req: any, res: any) {
  // No auth check! Directly calls dangerous operation.
  const userId = req.params.id;
  query(`DELETE FROM users WHERE id = ${userId}`);
  res.json({ success: true });
}

export async function handleSecureUpdate(req: any, res: any) {
  checkAuth(req);
  const data = sanitize(req.body);
  query('UPDATE users SET name = $1 WHERE id = $2');
  res.json({ success: true });
}

function sanitize(input: any): any {
  // Placeholder sanitizer
  return input;
}
