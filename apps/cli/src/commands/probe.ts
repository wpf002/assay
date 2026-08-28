import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { rank, toCycloneDX, type ExportProfile, type Finding } from '@assay/core';
import { assemble } from '@assay/correlate';
import { authorize, verifyGrant, ScopeError } from '@assay/scope';
import { probeTarget } from '@assay/detect-network';
import { lifetimeBreaches, parseCertificates, toFindings as pkiFindings } from '@assay/detect-pki';
import { decimalYear, loadPack } from '@assay/policy';
import { nowOption, numberOption } from '../options.js';

export interface ProbeCommandOptions {
  readonly grant: string;
  readonly pubkey?: string;
  readonly policy: string;
  readonly out: string;
  readonly profile: string;
  readonly system?: string;
  readonly secrecyYears: string;
  readonly timeoutMs: string;
  readonly clockSkewSeconds?: string;
  readonly json?: boolean;
  readonly now?: string;
}

export async function runProbe(targets: string[], options: ProbeCommandOptions): Promise<void> {
  const pubkeyPath = options.pubkey ?? process.env['ASSAY_SCOPE_PUBKEY_FILE'];
  if (pubkeyPath === undefined || pubkeyPath === '') {
    throw new Error(
      'no verification key: pass --pubkey, or set ASSAY_SCOPE_PUBKEY_FILE.\n' +
        'The key is not authority - the signed grant is - but without it a grant cannot be checked.',
    );
  }

  const grantJson: unknown = JSON.parse(await readFile(resolve(options.grant), 'utf8'));
  const grant = verifyGrant(grantJson, await readFile(resolve(pubkeyPath), 'utf8'));

  const now = nowOption(options.now);
  const collectedAt = now.toISOString();
  const pack = loadPack(options.policy);
  const systemId = options.system ?? 'probed-estate';
  const timeoutMs = numberOption('--timeout-ms', options.timeoutMs, { min: 1 });
  const secrecyYears = numberOption('--secrecy-years', options.secrecyYears, { min: 0, max: 100 });
  // NaN is not a wide skew allowance, it is no allowance at all: every
  // comparison against it is false, so both ends of the grant window stop
  // being checked and an expired grant probes anyway.
  const skew =
    options.clockSkewSeconds === undefined
      ? undefined
      : numberOption('--clock-skew-seconds', options.clockSkewSeconds);

  const findings: Finding[] = [];
  const certificates: ReturnType<typeof parseCertificates> = [];
  const refused: { target: string; reason: string; code: string }[] = [];
  const probed: { target: string; reachable: boolean; detail: string }[] = [];

  for (const raw of targets) {
    const { host, port } = splitTarget(raw);

    // The gate. Nothing below this line can run for an out-of-scope host,
    // because probeTarget accepts only an AuthorizedTarget and the only way to
    // get one is through here.
    let authorized;
    try {
      authorized = authorize(grant, host, port, now, skew === undefined ? {} : { clockSkewSeconds: skew });
    } catch (e) {
      refused.push({
        target: raw,
        reason: e instanceof Error ? e.message : String(e),
        code: e instanceof ScopeError ? e.code : 'UNKNOWN',
      });
      continue;
    }

    const report = await probeTarget(authorized, {
      systemId,
      collectedAt,
      timeoutMs,
    });
    findings.push(...report.findings);
    probed.push({
      target: `${host}:${port}`,
      reachable: report.tls?.reachable ?? report.ssh?.reachable ?? false,
      detail:
        report.ssh !== null
          ? (report.ssh.banner ?? report.ssh.error ?? '-')
          : `${report.tls?.selected?.protocol ?? '-'} ${report.tls?.selected?.cipher ?? report.tls?.selected?.error ?? '-'}`,
    });

    for (const pem of report.peerChainPem) {
      certificates.push(...parseCertificates(Buffer.from(pem), `${host}:${port}`));
    }
  }

  if (certificates.length > 0) {
    findings.push(...pkiFindings(certificates, { root: '.', systemId, collectedAt }));
  }

  const { occurrences, assets } = assemble(findings);
  const worklists = rank(occurrences, assets, {
    policy: pack,
    currentYear: decimalYear(now),
    secrecyLifetime: () => ({ years: secrecyYears, assumed: true }),
  });

  const cbom = toCycloneDX(occurrences, assets, {
    profile: options.profile as ExportProfile,
    policyPackId: pack.packId,
    policyPackVersion: pack.packVersion,
    timestamp: collectedAt,
    toolVersion: '0.1.0',
    includeFactorTrees: true,
  });
  await writeFile(resolve(options.out), `${JSON.stringify(cbom, null, 2)}\n`, 'utf8');

  const breaches = lifetimeBreaches(
    certificates,
    pack.regulatoryDeadlines.AUTHENTICITY,
    `${pack.packId}@${pack.packVersion}`,
  );

  if (options.json === true) {
    process.stdout.write(
      `${JSON.stringify({ worklists, probed, refused, breaches, cbomPath: options.out }, null, 2)}\n`,
    );
    return;
  }

  const line = (s = ''): void => {
    process.stdout.write(`${s}\n`);
  };

  line();
  line(`assay probe  grant ${grant.grantId} issued by ${grant.issuedBy}`);
  line(`  window ${grant.notBefore} .. ${grant.notAfter}`);
  line();
  for (const p of probed) {
    line(`  ${p.reachable ? 'up  ' : 'down'} ${p.target.padEnd(28)} ${p.detail}`);
  }
  for (const r of refused) {
    line(`  SKIP ${r.target.padEnd(28)} ${r.code}: ${r.reason}`);
  }
  line();
  line(
    `  ${assets.length} asset(s), ${occurrences.length} occurrence(s), ` +
      `${certificates.length} certificate(s)`,
  );
  line(
    `  worklists: ${worklists.confidentiality.length} confidentiality, ` +
      `${worklists.authenticity.length} authenticity`,
  );

  if (breaches.length > 0) {
    line();
    line('certificates valid past the migration deadline - a dated finding, today:');
    for (const b of breaches.slice(0, 10)) {
      line(
        `  +${b.overhangYears.toFixed(1)}y past ${b.deadlineYear}  ` +
          `${b.certificate.publicKey.primitive} ${b.certificate.subject} ` +
          `(expires ${b.certificate.notAfter.slice(0, 10)}${b.certificate.isCA ? ', CA' : ''})`,
      );
    }
  }
  line();
  line(`cbom  ${resolve(options.out)}`);
  line();
}

function splitTarget(raw: string): { host: string; port: number } {
  const trimmed = raw.trim();
  // [::1]:443
  const bracketed = /^\[(.+)\]:(\d+)$/.exec(trimmed);
  if (bracketed?.[1] && bracketed[2]) return { host: bracketed[1], port: Number(bracketed[2]) };
  const idx = trimmed.lastIndexOf(':');
  if (idx > 0 && !trimmed.slice(idx + 1).includes(':')) {
    const port = Number(trimmed.slice(idx + 1));
    if (Number.isInteger(port) && port > 0 && port <= 65535) {
      return { host: trimmed.slice(0, idx), port };
    }
  }
  return { host: trimmed, port: 443 };
}
