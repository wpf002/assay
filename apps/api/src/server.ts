import { buildApp } from './app.js';
import { MemoryScanStore } from './store/memory.js';
import { PrismaScanStore } from './store/prisma.js';
import type { ScanStore } from './store/types.js';

const url = process.env['DATABASE_URL'];
const store: ScanStore =
  url === undefined || url === ''
    ? new MemoryScanStore()
    : PrismaScanStore.fromUrl(url);

const app = await buildApp({ store, logger: true });
const port = Number(process.env['PORT'] ?? 3001);

app.log.info(
  store.kind === 'memory'
    ? 'no DATABASE_URL: running with an in-memory store, scans will not survive a restart'
    : 'using the Postgres store',
);

try {
  await app.listen({ port, host: '0.0.0.0' });
} catch (e) {
  app.log.error(e);
  process.exit(1);
}
