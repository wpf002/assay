import { bootstrapAdminToken, buildApp } from './app.js';
import { MemoryScanStore } from './store/memory.js';
import { PrismaScanStore } from './store/prisma.js';
import type { ScanStore } from './store/types.js';

const url = process.env['DATABASE_URL'];
const store: ScanStore =
  url === undefined || url === ''
    ? new MemoryScanStore()
    : PrismaScanStore.fromUrl(url);

const app = await buildApp({ store, logger: true });

/**
 * Mint the first admin token if the table is empty, and print it once.
 *
 * There is no default credential and no way to disable authentication. An
 * operator who loses this mints another with it and revokes it; an operator
 * who loses it with no other admin token re-bootstraps against an empty table.
 */
if ((await store.countUsableTokens(new Date().toISOString())) === 0) {
  const { token, id } = await bootstrapAdminToken(store, 'bootstrap');
  process.stderr.write(
    '\n' +
      '  No usable API token exists, so one admin token has been created.\n' +
      `  id:    ${id}\n` +
      `  token: ${token}\n` +
      '  This is the only time it is shown. It is not recoverable.\n\n',
  );
}
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
