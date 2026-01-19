import app from '../hono/hono';
import { dbInit } from '../init/init';
import { initForward } from "../init/forward";

app.get('/init/:secret', (c) => {
	return dbInit.init(c);
})

app.post('/initForward', async (c) => {
	return initForward(c, await c.req.json());
})
