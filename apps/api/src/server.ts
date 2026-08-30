import { readFileSync } from 'node:fs';
import { bootstrapAdminToken, buildApp } from './app.js';
import { MemoryScanStore } from './store/memory.js';
import { PrismaScanStore } from './store/prisma.js';
import type { ScanStore } from './store/types.js';

const url = process.env['DATABASE_URL'];
const store: ScanStore =
  url === undefined || url === ''
    ? new MemoryScanStore()
    : PrismaScanStore.fromUrl(url);

/**
 * The coverage signing key, if this deployment has one.
 *
 * Accepts the PEM itself or a path to it, because the first is what a secrets
 * manager injects and the second is what a person does. Absent is a supported
 * state: attestations come back marked unsigned rather than silently unsigned.
 */
function coverageKey(): string | undefined {
  const value = process.env['ASSAY_COVERAGE_KEY'];
  if (value === undefined || value === '') return undefined;
  if (value.includes('-----BEGIN')) return value;
  try {
    return readFileSync(value, 'utf8');
  } catch {
    process.stderr.write(`ASSAY_COVERAGE_KEY points at ${value}, which could not be read\n`);
    return undefined;
  }
}

const key = coverageKey();
const app = await buildApp({
  store,
  logger: true,
  ...(key === undefined ? {} : { coverageKeyPem: key }),
});

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

/**
 * Loopback by default.
 *
 * This binds 0.0.0.0 no longer. What the API serves is an inventory of an
 * organization's weakest cryptography, which is also a map of where to attack
 * it, and a developer starting it on a laptop is not deciding to publish that
 * to every device on the coffee-shop wifi. The default here was doing exactly
 * that, and the logs from one afternoon on a home network show an ONVIF probe
 * and a log4shell-style JNDI callback attempt arriving from a neighbouring
 * device.
 *
 * Authentication held - every one of those got a 401 - but a token check is the
 * last line, not the first, and an unauthenticated attacker should not be able
 * to reach the router at all. Binding wider is still possible and is now a
 * decision somebody makes on purpose.
 */
const host = process.env['ASSAY_BIND'] ?? '127.0.0.1';
if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') {
  process.stderr.write(
    `\n  ASSAY_BIND=${host}: this API is reachable from outside this machine.\n` +
      '  It serves an inventory of your weakest cryptography. Put it behind TLS\n' +
      '  and something that limits who can reach the port.\n\n',
  );
}

app.log.info(
  store.kind === 'memory'
    ? 'no DATABASE_URL: running with an in-memory store, scans will not survive a restart'
    : 'using the Postgres store',
);

try {
  await app.listen({ port, host });
  app.log.info(`listening on ${host}:${port}`);
} catch (e) {
  app.log.error(e);
  process.exit(1);
}
