import { App } from '../src/app';
import { boot } from '../src/main';
import request from 'supertest';

let application: App;

beforeAll(async () => {
	const { app } = await boot;
	application = app;
});

describe('Users e2e', () => {
	it('Register - error', async () => {
		const res = await request(application.app).post('/users/register').send({
			email: 'a@a.com',
			password: '1',
		});
		expect(res.statusCode).toBe(422);
	});
	it('Login - success', async () => {
		const res = await request(application.app).post('/users/login').send({
			email: 'zakablukov777@gmail.com',
			password: '12345678',
		});
		expect(res.body.jwt).not.toBeUndefined();
	});
	it('Login - error', async () => {
		const res = await request(application.app).post('/users/login').send({
			email: 'a@a.com',
			password: '5',
		});
		expect(res.statusCode).toBe(401);
	});
	it('Info - success', async () => {
		const login = await request(application.app).post('/users/login').send({
			email: 'zakablukov777@gmail.com',
			password: '12345678',
		});
		const res = await request(application.app)
			.get('/users/info')
			.auth(login.body.jwt, { type: 'bearer' });
		expect(res.body.email).toBe('zakablukov777@gmail.com');
	});
	it('Info - error', async () => {
		const res = await request(application.app).get('/users/info').auth('', { type: 'bearer' });
		expect(res.statusCode).toBe(401);
	});
});

afterAll(() => {
	application.close();
});
