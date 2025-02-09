import { Hono } from 'hono';
import { env } from 'hono/adapter';
import { sign, verify } from 'hono/jwt';

const app = new Hono();

app.post('/token', async (c) => {
    const { username, password } = await c.req.json();
    const { USERNAME, PASSWORD, SECRET } = env<{ USERNAME: string, PASSWORD: string, SECRET: string }>(c);
    if (username === USERNAME && password === PASSWORD) {
        const payload = {
            sub: username,
            role: 'admin',
            iss: 'authenticator',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 60 * 60 // Token expires in 1 hour
        }
        const token = await sign(payload, SECRET, 'HS256'); // Sign the payload with the secret key
        return c.json({ token });
    }
    return c.json({ error: 'Unauthorize' }, 401);
})

app.use(
    "/api/*",
    async (c, next) => {
        const { SECRET } = env<{ SECRET: string }>(c);
        const token = c.req.header('Authorization')?.split(' ')[1];
        if (!token) return c.json({ error: 'Unauthorized' }, 401);
        const decoded = await verify(token, SECRET, 'HS256')?.catch(() => null);
        if (!decoded) return c.json({ error: 'Unauthorized' }, 401);
        await next();
    }
)

app.get('/api/user', async (c) => {
    return c.json({ message: 'Hey, Admin!' });
})

export default app;
