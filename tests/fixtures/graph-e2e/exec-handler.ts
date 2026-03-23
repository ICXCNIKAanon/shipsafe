// A handler that calls shell execSync — critical severity vulnerability

import { execSync } from 'child_process';

export async function handleDeploy(req: any, res: any) {
  const branch = req.body.branch;
  // CRITICAL: User input goes to shell execSync
  const output = execSync(`git checkout ${branch} && npm run build`);
  res.json({ output: output.toString() });
}
