import { Request, Response } from 'express';
import { db } from './database';

export class UserController {
  async getUser(req: Request, res: Response) {
    const user = await db.findUser(req.params.id);
    res.json(user);
  }

  async deleteUser(req: Request, res: Response) {
    await db.deleteUser(req.params.id);
    res.status(204).send();
  }
}

export function validateInput(data: unknown): boolean {
  return typeof data === 'string' && data.length > 0;
}

const helper = (x: number) => x * 2;
