import { IMiddleware } from './middleware.interface';
import { Request, Response, NextFunction } from 'express';

export class AuthGuard implements IMiddleware {
	execute({ user }: Request, res: Response, next: NextFunction): void {
		if (!user) {
			res.status(401).send({ error: 'Вы не авторизован' });
		} else {
			next();
		}
	}
}
