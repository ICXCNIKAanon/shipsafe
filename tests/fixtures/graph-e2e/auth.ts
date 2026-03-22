// Simulated auth middleware

export function checkAuth(req: any): void {
  if (!req.headers.authorization) {
    throw new Error('Unauthorized');
  }
}

export function requireAdmin(req: any): void {
  checkAuth(req);
  if (!req.user?.isAdmin) {
    throw new Error('Forbidden');
  }
}
