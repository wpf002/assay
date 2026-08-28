import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { lookup, scanDependencies } from '../src/index.js';

async function fixture(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'assay-deps-'));
  for (const [name, content] of Object.entries(files)) {
    const path = join(dir, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, content, 'utf8');
  }
  return dir;
}

const OPTS = { systemId: 'svc', collectedAt: '2026-08-28T00:00:00.000Z' };

describe('catalog lookup', () => {
  it('normalizes PyPI naming rules', () => {
    expect(lookup('PyJWT', 'pypi')).not.toBeNull();
    expect(lookup('argon2_cffi', 'pypi')).not.toBeNull();
  });
  it('does not cross ecosystems', () => {
    expect(lookup('cryptography', 'npm')).toBeNull();
  });
});

describe('package.json', () => {
  it('emits DEPENDENCY evidence that cannot confirm on its own', async () => {
    const dir = await fixture({
      'package.json': JSON.stringify({ dependencies: { 'node-forge': '^1.3.1' } }),
    });
    const { findings } = await scanDependencies({ root: dir, ...OPTS });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.evidence.modality === 'DEPENDENCY')).toBe(true);
  });

  it('states the implements-vs-uses distinction on every observation', async () => {
    const dir = await fixture({
      'package.json': JSON.stringify({ dependencies: { 'node-forge': '1.3.1' } }),
    });
    const { findings } = await scanDependencies({ root: dir, ...OPTS });
    expect(findings.every((f) => f.evidence.raw.includes('IMPLEMENTS this primitive'))).toBe(true);
    expect(findings.every((f) => f.evidence.raw.includes('not that the application USES it'))).toBe(
      true,
    );
  });

  it('excludes devDependencies unless asked - dev tooling is not the estate', async () => {
    const dir = await fixture({
      'package.json': JSON.stringify({ devDependencies: { 'crypto-js': '^4.2.0' } }),
    });
    expect((await scanDependencies({ root: dir, ...OPTS })).findings).toHaveLength(0);
    const withDev = await scanDependencies({ root: dir, ...OPTS, includeDev: true });
    expect(withDev.findings.length).toBeGreaterThan(0);
    expect(withDev.findings[0]?.evidence.raw).toContain('scope=dev');
  });

  it('marks an abandoned library as a procurement problem, not an upgrade', async () => {
    const dir = await fixture({ 'requirements.txt': 'pycrypto==2.6.1\n' });
    const { findings } = await scanDependencies({ root: dir, ...OPTS });
    expect(findings[0]?.controlClass).toBe('VENDOR_LOCKED');
  });

  it('reports crypto-looking dependencies missing from the catalog', async () => {
    const dir = await fixture({
      'package.json': JSON.stringify({ dependencies: { 'some-crypto-thing': '1.0.0', lodash: '4' } }),
    });
    const { uncatalogued } = await scanDependencies({ root: dir, ...OPTS });
    expect(uncatalogued).toEqual(['npm:some-crypto-thing']);
  });
});

describe('python manifests', () => {
  it('parses requirements.txt with version pins and extras', async () => {
    const dir = await fixture({
      'requirements.txt': '# comment\ncryptography[ssh]==42.0.5\nPyJWT>=2.8.0\nrequests\n-r other.txt\n',
    });
    const { findings } = await scanDependencies({ root: dir, ...OPTS });
    const names = new Set(findings.map((f) => f.evidence.raw.split(' ')[0]));
    expect([...names].some((n) => n?.includes('cryptography'))).toBe(true);
    expect([...names].some((n) => n?.includes('PyJWT'))).toBe(true);
  });

  it('parses poetry.lock packages and their groups', async () => {
    const dir = await fixture({
      'poetry.lock': `
[[package]]
name = "cryptography"
version = "42.0.5"
category = "main"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"
`,
    });
    const { findings } = await scanDependencies({ root: dir, ...OPTS });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.evidence.raw.includes('scope=prod'))).toBe(true);
  });
});

describe('coverage-gap reporting is tight enough to be useful', () => {
  it('does not flag packages that merely contain sign / key / crypt as substrings', async () => {
    const dir = await fixture({
      'package.json': JSON.stringify({
        dependencies: {
          '@n8n/design-system': '1',
          'ajv-keywords': '1',
          'alien-signals': '1',
          'browserify-rsa': '1',
        },
      }),
    });
    const { uncatalogued } = await scanDependencies({ root: dir, ...OPTS });
    expect(uncatalogued).toEqual(['npm:browserify-rsa']);
  });
});
