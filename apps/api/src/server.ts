import Fastify from 'fastify';

const app = Fastify({ logger: true });
app.get('/health', async () => ({ ok: true }));

const port = Number(process.env['PORT'] ?? 3001);
app.listen({ port, host: '0.0.0.0' }).catch((e: unknown) => {
  app.log.error(e);
  process.exit(1);
});
