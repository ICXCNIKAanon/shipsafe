// A handler that calls shell exec — critical severity vulnerability

import { exec } from 'child_process';

export async function handleDeploy(req: any, res: any) {
  const branch = req.body.branch;
  // CRITICAL: User input goes to shell exec
  exec(`git checkout ${branch} && npm run build`, (err, stdout) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ output: stdout });
  });
}
