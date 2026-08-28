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

describe('a manifest name that no ecosystem uses can never be looked up', () => {
  it('finds the PyPI bcrypt distribution under the name a requirements file writes', async () => {
    expect(lookup('bcrypt', 'pypi')).not.toBeNull();
    expect(lookup('bcrypt', 'npm')?.ecosystem).toBe('npm');
    const dir = await fixture({ 'requirements.txt': 'bcrypt==4.1.2\n' });
    const { findings, uncatalogued } = await scanDependencies({ root: dir, ...OPTS });
    expect(uncatalogued).toEqual([]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('requirements.txt scope comes from the filename, not the directory it sits in', () => {
  it('keeps a production manifest under a directory whose name contains dev or test', async () => {
    const dir = await fixture({
      'packages/dev-portal/requirements.txt': 'pycryptodome==3.19.0\n',
      'services/attestation-service/requirements.txt': 'cryptography==42.0.5\n',
    });
    const { findings } = await scanDependencies({ root: dir, ...OPTS });
    expect(findings.every((f) => f.evidence.raw.includes('scope=prod'))).toBe(true);
    expect(findings.some((f) => f.evidence.raw.includes('pycryptodome'))).toBe(true);
    expect(findings.some((f) => f.evidence.raw.includes('cryptography'))).toBe(true);
  });

  it('still treats a dev requirements file as dev tooling', async () => {
    const dir = await fixture({ 'requirements-dev.txt': 'pycryptodome==3.19.0\n' });
    expect((await scanDependencies({ root: dir, ...OPTS })).findings).toHaveLength(0);
  });
});

describe('Pipfile', () => {
  const PIPFILE = `[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[dev-packages]
pytest = "*"

[packages]
cryptography = "*"

[requires]
python_version = "3.11"
`;

  it('reads the two package tables and nothing else', async () => {
    const dir = await fixture({ Pipfile: PIPFILE });
    const { findings, uncatalogued } = await scanDependencies({ root: dir, ...OPTS });
    // verify_ssl matches the crypto-token pattern, so a stray TOML key would
    // show up here as a package nobody can catalogue.
    expect(uncatalogued).toEqual([]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.evidence.raw.includes('cryptography'))).toBe(true);
  });

  it('does not leak the previous table scope into a later one', async () => {
    const dir = await fixture({ Pipfile: PIPFILE });
    const { findings } = await scanDependencies({ root: dir, ...OPTS, includeDev: true });
    const names = findings.map((f) => f.evidence.raw.split(' ')[0]);
    expect(names.some((n) => n?.includes('python_version'))).toBe(false);
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
