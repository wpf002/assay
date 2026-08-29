import type { FastifyInstance, InjectOptions } from 'fastify';
import { bootstrapAdminToken, buildApp } from '../src/app.js';
import { MemoryScanStore } from '../src/store/memory.js';
import type { ScanStore } from '../src/store/types.js';

/**
 * An app with a token, because there is no way to run one without.
 *
 * Authentication cannot be disabled — no flag, no environment variable, no
 * test-only bypass. A bypass is the thing that ends up shipping, and the whole
 * point of this phase was that the API served an estate's cryptography to
 * anyone who asked. So the tests hold a real token and exercise the real path.
 *
 * `inject` here attaches the Authorization header unless the caller supplies
 * their own, which is how the unauthenticated and wrong-role cases are written.
 */
export interface AuthedApp {
  readonly app: FastifyInstance;
  readonly store: ScanStore;
  readonly auth: { authorization: string };
  inject(opts: InjectOptions): ReturnType<FastifyInstance['inject']>;
  close(): Promise<void>;
}

export async function authedApp(store: ScanStore = new MemoryScanStore()): Promise<AuthedApp> {
  const app = await buildApp({ store });
  const { token } = await bootstrapAdminToken(store);
  const auth = { authorization: `Bearer ${token}` };

  return {
    app,
    store,
    auth,
    inject: (opts) => app.inject({ ...opts, headers: { ...auth, ...(opts.headers ?? {}) } }),
    close: () => app.close(),
  };
}

/** A token with a narrower role or a system scope, for the authorization tests. */
export async function issueToken(
  authed: AuthedApp,
  body: { name: string; role: 'admin' | 'operator' | 'viewer'; systems?: string[]; expiresAt?: string | null },
): Promise<{ authorization: string; id: string }> {
  const r = await authed.inject({
    method: 'POST',
    url: '/tokens',
    payload: { systems: [], expiresAt: null, ...body },
  });
  const json = r.json<{ token: string; id: string }>();
  return { authorization: `Bearer ${json.token}`, id: json.id };
}
