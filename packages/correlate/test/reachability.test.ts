import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanSource } from '@assay/detect-source';
import { analyzeReachability, assemble } from '../src/index.js';

const COLLECTED = '2026-08-28T00:00:00.000Z';

async function tree(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'assay-reach-'));
  for (const [name, content] of Object.entries(files)) {
    const path = join(dir, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, content, 'utf8');
  }
  return dir;
}

async function analyze(files: Record<string, string>) {
  const root = await tree(files);
  const source = await scanSource({ root, systemId: 's', collectedAt: COLLECTED });
  const { occurrences, assets } = assemble(source.findings);
  const result = analyzeReachability(occurrences, source.graph);
  const byId = new Map(assets.map((a) => [a.id, a]));
  return {
    ...result,
    named: result.occurrences.map((o) => ({
      primitive: byId.get(o.assetId)?.primitive,
      reachable: o.reachability?.reachable ?? null,
      path: o.reachability?.path ?? [],
      entryPoint: o.reachability?.entryPoint ?? null,
      locators: o.evidence.map((e) => e.locator),
    })),
  };
}

const SERVER = `
import express from 'express';
import { sign } from './service.js';
const app = express();
app.post('/sign', (req, res) => res.json({ s: sign(req.body) }));
app.listen(3000);
`;

const SERVICE = `
import crypto from 'node:crypto';
function helperNobodyCalls(d) {
  return crypto.createHash('md5').update(d).digest('hex');
}
export function sign(d) {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
`;

const DEAD = `
import crypto from 'node:crypto';
export function neverImported(k, iv) {
  return crypto.createCipheriv('des-ede3-cbc', k, iv);
}
`;

const TEST = `
import crypto from 'node:crypto';
it('x', () => { crypto.createCipheriv('rc4', k, iv); });
`;

describe('the Phase 3 exit gate: a known dev/prod split', () => {
  it('marks every test-only finding unreached', async () => {
    const r = await analyze({
      'src/server.ts': SERVER,
      'src/service.ts': SERVICE,
      'tests/service.test.ts': TEST,
    });
    const rc4 = r.named.find((n) => n.primitive === 'RC4');
    expect(rc4?.reachable).toBe(false);
  });

  it('marks a module nothing imports as unreached', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE, 'src/dead.ts': DEAD });
    expect(r.named.find((n) => n.primitive === '3DES')?.reachable).toBe(false);
  });

  it('marks a helper nobody exports or calls unreached, inside a live file', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE });
    // service.ts is imported from the entry point, but helperNobodyCalls is
    // dead inside it. Import-only analysis gets exactly this case wrong.
    expect(r.named.find((n) => n.primitive === 'MD5')?.reachable).toBe(false);
  });

  it('reaches the production call site and ships the path', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE });
    const rsa = r.named.find((n) => n.primitive === 'RSA');
    expect(rsa?.reachable).toBe(true);
    expect(rsa?.path.map((f) => f.fullFilename)).toEqual(['src/server.ts', 'src/service.ts']);
    expect(rsa?.path[rsa.path.length - 1]?.function).toContain('generateKeyPairSync');
  });

  it('produces zero false reached on a mixed tree', async () => {
    const r = await analyze({
      'src/server.ts': SERVER,
      'src/service.ts': SERVICE,
      'src/dead.ts': DEAD,
      'tests/service.test.ts': TEST,
      '__tests__/other.test.ts': TEST,
    });
    const reachedFromTestOrDead = r.named.filter(
      (n) =>
        n.reachable === true &&
        n.locators.every((l) => /tests?|__tests__|dead\.ts/.test(l)),
    );
    expect(reachedFromTestOrDead).toEqual([]);
  });
});

describe('entry-point detection', () => {
  it('finds an http server', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE });
    expect(r.entryPoints).toEqual(['src/server.ts']);
  });

  it('finds a python main', async () => {
    const r = await analyze({
      'app.py': `import hashlib\ndef go():\n    return hashlib.md5(b'x')\nif __name__ == "__main__":\n    go()\n`,
    });
    expect(r.entryPoints).toEqual(['app.py']);
    expect(r.named.find((n) => n.primitive === 'MD5')?.reachable).toBe(true);
  });

  it('never treats a test file as an entry point', async () => {
    const r = await analyze({
      'tests/server.test.ts': SERVER,
      'src/service.ts': SERVICE,
    });
    expect(r.entryPoints).toEqual([]);
  });
});

describe('honesty about what was not analyzed', () => {
  it('claims nothing when the tree has no entry point', async () => {
    const r = await analyze({ 'src/lib.ts': SERVICE });
    expect(r.analyzed).toBe(false);
    expect(r.occurrences.every((o) => o.reachability === null)).toBe(true);
  });

  it('states the over-approximation in the derivation rather than hiding it', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE });
    const rsa = r.occurrences.find((o) => o.reachability?.reachable === true);
    const s = JSON.stringify(rsa?.reachability?.factor);
    expect(s).toContain('ASSUMPTION');
    expect(s).toContain('over-approximates');
  });

  it('explains why something was judged dead', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE, 'src/dead.ts': DEAD });
    const byId = new Map(r.named.map((n) => [n.primitive, n]));
    expect(byId.get('3DES')?.reachable).toBe(false);
    const dead = r.occurrences.find(
      (o) => JSON.stringify(o.reachability?.factor ?? {}).includes('dead.ts'),
    );
    expect(JSON.stringify(dead?.reachability?.factor)).toContain('not imported from any entry point');
  });
});

describe('modalities without a call site', () => {
  it('treats a config file as deployed rather than as dead code', async () => {
    const r = await analyze({
      'src/server.ts': SERVER,
      'conf/nginx.conf': 'server {\n  ssl_ciphers DES-CBC3-SHA;\n}\n',
    });
    const tdes = r.named.find((n) => n.primitive === '3DES');
    expect(tdes?.reachable).toBe(true);
    expect(tdes?.entryPoint).toContain('nginx.conf');
  });

  it('does not treat an example config as deployed', async () => {
    const r = await analyze({
      'src/server.ts': SERVER,
      'examples/nginx.conf': 'server {\n  ssl_ciphers DES-CBC3-SHA;\n}\n',
    });
    expect(r.named.find((n) => n.primitive === '3DES')?.reachable).toBe(false);
  });
});

describe('module resolution', () => {
  it('follows a NodeNext ./x.js specifier to x.ts', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE });
    expect(r.reachableFiles.has('src/service.ts')).toBe(true);
  });

  it('follows a directory import to its index file', async () => {
    const r = await analyze({
      'src/server.ts': SERVER.replace("'./service.js'", "'./crypto'"),
      'src/crypto/index.ts': SERVICE,
    });
    expect(r.reachableFiles.has('src/crypto/index.ts')).toBe(true);
  });
});

describe('how the conclusion was reached, not just whether', () => {
  it('labels a static path from a server as ENTRY_POINT', async () => {
    const r = await analyze({ 'src/server.ts': SERVER, 'src/service.ts': SERVICE });
    const rsa = r.occurrences.find((o) => o.reachability?.via === 'ENTRY_POINT');
    expect(rsa?.reachability?.path.length).toBeGreaterThan(0);
  });

  it('labels a config file as DEPLOYED_CONFIG', async () => {
    const r = await analyze({
      'src/server.ts': SERVER,
      'conf/nginx.conf': 'server {\n  ssl_ciphers DES-CBC3-SHA;\n}\n',
    });
    expect(r.occurrences.some((o) => o.reachability?.via === 'DEPLOYED_CONFIG')).toBe(true);
  });

  it('uses LIBRARY_SURFACE only when the manifest declares a public surface', async () => {
    const lib = await analyze({
      'package.json': JSON.stringify({ name: 'lib', main: 'src/index.js' }),
      'src/index.ts': "export const version = '1';",
      'src/orphan.ts': DEAD,
    });
    // Published: an orphaned module is still reachable by a consumer we cannot see.
    expect(lib.named.find((n) => n.primitive === '3DES')?.reachable).toBe(true);
    expect(
      lib.occurrences.find((o) => o.reachability?.via === 'LIBRARY_SURFACE'),
    ).toBeDefined();

    const service = await analyze({
      // No main/module/exports/bin: this is a service, not a library.
      'package.json': JSON.stringify({ name: 'svc', private: true, scripts: { start: 'node .' } }),
      'src/server.ts': SERVER,
      'src/service.ts': SERVICE,
      'src/orphan.ts': DEAD,
    });
    expect(service.named.find((n) => n.primitive === '3DES')?.reachable).toBe(false);
  });

  it('never treats a test file as published surface', async () => {
    const r = await analyze({
      'package.json': JSON.stringify({ name: 'lib', main: 'src/index.js' }),
      'src/index.ts': "export const version = '1';",
      'tests/thing.test.ts': TEST,
    });
    expect(r.named.find((n) => n.primitive === 'RC4')?.reachable).toBe(false);
  });

  it('says out loud that a published-surface conclusion is an assumption', async () => {
    const r = await analyze({
      'package.json': JSON.stringify({ name: 'lib', main: 'src/index.js' }),
      'src/index.ts': "export const version = '1';",
      'src/orphan.ts': DEAD,
    });
    const surface = r.occurrences.find((o) => o.reachability?.via === 'LIBRARY_SURFACE');
    expect(JSON.stringify(surface?.reachability?.factor)).toContain('ASSUMPTION');
    expect(JSON.stringify(surface?.reachability?.factor)).toContain('consumers are not in scope');
  });
});

describe('non-relative imports inside the tree', () => {
  it('follows a workspace package name', async () => {
    const r = await analyze({
      'package.json': JSON.stringify({ name: 'root', private: true }),
      'packages/api/package.json': JSON.stringify({ name: '@acme/api' }),
      'packages/api/src/server.ts': SERVER.replace("'./service.js'", "'@acme/crypto'"),
      'packages/crypto/package.json': JSON.stringify({ name: '@acme/crypto' }),
      'packages/crypto/index.ts': SERVICE,
    });
    expect(r.reachableFiles.has('packages/crypto/index.ts')).toBe(true);
  });

  it('does not confuse @acme/core-utils with @acme/core', async () => {
    const r = await analyze({
      'packages/a/package.json': JSON.stringify({ name: '@acme/core' }),
      'packages/a/index.ts': "export const a = 1;",
      'packages/b/package.json': JSON.stringify({ name: '@acme/core-utils' }),
      'packages/b/index.ts': SERVICE,
      'packages/api/package.json': JSON.stringify({ name: '@acme/api' }),
      'packages/api/server.ts': SERVER.replace("'./service.js'", "'@acme/core-utils'"),
    });
    expect(r.reachableFiles.has('packages/b/index.ts')).toBe(true);
    expect(r.reachableFiles.has('packages/a/index.ts')).toBe(false);
  });

  it('follows a python absolute module path', async () => {
    const r = await analyze({
      'app.py': 'from myapp.crypto import digest\nif __name__ == "__main__":\n    digest(b"x")\n',
      'myapp/__init__.py': '',
      'myapp/crypto.py': 'import hashlib\ndef digest(d):\n    return hashlib.md5(d).hexdigest()\n',
    });
    expect(r.reachableFiles.has('myapp/crypto.py')).toBe(true);
    expect(r.named.find((n) => n.primitive === 'MD5')?.reachable).toBe(true);
  });

  it('refuses an ambiguous alias rather than inventing an edge', async () => {
    const r = await analyze({
      'packages/a/package.json': JSON.stringify({ name: 'a' }),
      'packages/a/src/utils/crypto.ts': SERVICE,
      'packages/b/package.json': JSON.stringify({ name: 'b' }),
      'packages/b/src/utils/crypto.ts': DEAD,
      'packages/c/package.json': JSON.stringify({ name: 'c' }),
      'packages/c/src/server.ts': SERVER.replace("'./service.js'", "'@/utils/crypto'"),
    });
    // Two files end with src/utils/crypto.ts and neither is in package c, so
    // no edge is created. A wrong edge marks unrelated code reachable.
    expect(r.reachableFiles.has('packages/a/src/utils/crypto.ts')).toBe(false);
    expect(r.reachableFiles.has('packages/b/src/utils/crypto.ts')).toBe(false);
  });

  it('resolves an alias unambiguously when only one file matches', async () => {
    const r = await analyze({
      'package.json': JSON.stringify({ name: 'svc', private: true }),
      'src/server.ts': SERVER.replace("'./service.js'", "'@/crypto/signer'"),
      'src/crypto/signer.ts': SERVICE,
    });
    expect(r.reachableFiles.has('src/crypto/signer.ts')).toBe(true);
  });
});
