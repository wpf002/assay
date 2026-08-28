import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import fg from 'fast-glob';
import { makeAsset, type ControlClass, type Evidence, type Finding, type Modality } from '@assay/core';
import { languageFor, parseSource } from './parsers/index.js';
import { ruleIndex } from './rules/index.js';
import { configKindFor, parseConfig } from './config/index.js';
import type { Detection } from './types.js';

export * from './types.js';

export { languageFor, parseSource } from './parsers/index.js';
export { RULES, ruleIndex, TYPESCRIPT_RULES, PYTHON_RULES } from './rules/index.js';
export { configKindFor, parseConfig } from './config/index.js';

export const COLLECTOR_VERSION = 'detect-source/0.1.0';

/** Directories that are never the estate. Scanning them manufactures noise. */
export const DEFAULT_IGNORE: readonly string[] = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/.next/**',
  '**/target/**',
  '**/vendor/**',
  '**/.venv/**',
  '**/venv/**',
  '**/__pycache__/**',
  '**/site-packages/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.bundle.js',
];

export interface SourceScanOptions {
  readonly root: string;
  readonly systemId: string;
  /** ISO8601. Supplied by the caller so a scan is reproducible. */
  readonly collectedAt: string;
  readonly ignore?: readonly string[];
  readonly controlClass?: ControlClass;
  readonly maxFileBytes?: number;
}

export interface SourceScanResult {
  readonly findings: readonly Finding[];
  readonly filesScanned: number;
  readonly filesSkipped: readonly { readonly file: string; readonly reason: string }[];
}

export async function scanSource(opts: SourceScanOptions): Promise<SourceScanResult> {
  const root = resolve(opts.root);
  const ignore = [...(opts.ignore ?? DEFAULT_IGNORE)];
  const maxBytes = opts.maxFileBytes ?? 2_000_000;
  const controlClass = opts.controlClass ?? 'SELF';

  const files = await fg(
    [
      '**/*.{ts,tsx,mts,cts,js,mjs,cjs,jsx,py,pyi}',
      '**/nginx.conf',
      '**/*nginx*.conf',
      '**/openssl.cnf',
      '**/openssl.conf',
      '**/java.security',
      '**/sshd_config',
      '**/ssh_config',
    ],
    { cwd: root, ignore, absolute: true, dot: false, followSymbolicLinks: false, suppressErrors: true },
  );

  const findings: Finding[] = [];
  const skipped: { file: string; reason: string }[] = [];
  let scanned = 0;

  // Sorted so a scan of the same tree produces evidence in the same order.
  for (const abs of files.sort()) {
    const rel = relative(root, abs);
    let source: string;
    try {
      const buf = await readFile(abs);
      if (buf.byteLength > maxBytes) {
        skipped.push({ file: rel, reason: `larger than ${maxBytes} bytes` });
        continue;
      }
      source = buf.toString('utf8');
    } catch (e) {
      skipped.push({ file: rel, reason: `unreadable: ${String(e)}` });
      continue;
    }

    scanned++;
    const configKind = configKindFor(abs);
    if (configKind !== null) {
      // TLS and SSH algorithm lists are PROTOCOL_BILATERAL, not SELF: you can
      // edit the file today and still not migrate, because the peer has to
      // move too. That is a five-year Y, and mislabelling it as SELF is how a
      // ranking quietly promises a six-month fix for the slowest thing in the
      // estate.
      const configControl: ControlClass =
        configKind === 'nginx' || configKind === 'sshd' || configKind === 'ssh'
          ? 'PROTOCOL_BILATERAL'
          : controlClass;
      for (const finding of parseConfig(configKind, source)) {
        for (const d of finding.detections) {
          findings.push(
            toFinding(d, 'SOURCE_CONFIG', rel, finding.line, finding.raw, opts, configControl, {
              location: rel,
              line: finding.line,
              symbol: finding.directive,
            }),
          );
        }
      }
      continue;
    }

    const lang = languageFor(abs);
    if (lang === null) continue;

    let parsed;
    try {
      parsed = parseSource(rel, source, lang);
    } catch (e) {
      skipped.push({ file: rel, reason: `parse failed: ${String(e)}` });
      continue;
    }

    const index = ruleIndex(lang);
    for (const call of parsed.calls) {
      const rules = index.get(call.method);
      if (rules === undefined) continue;
      for (const rule of rules) {
        if (rule.requiresImport && !rule.requiresImport.some((m) => hasImport(parsed.context.imports, m))) {
          continue;
        }
        for (const d of rule.detect(call, parsed.context)) {
          findings.push(
            toFinding(d, 'SOURCE_AST', rel, call.line, call.text, opts, controlClass, {
              location: rel,
              line: call.line,
              offset: call.column,
              symbol: call.callee,
            }),
          );
        }
      }
    }
  }

  return { findings, filesScanned: scanned, filesSkipped: skipped };
}

function hasImport(imports: ReadonlySet<string>, module: string): boolean {
  if (imports.has(module)) return true;
  for (const seen of imports) {
    if (seen === module || seen.startsWith(`${module}.`) || seen.startsWith(`${module}/`)) return true;
  }
  return false;
}

function toFinding(
  d: Detection,
  modality: Modality,
  file: string,
  line: number,
  raw: string,
  opts: SourceScanOptions,
  controlClass: ControlClass,
  occurrence: Evidence['occurrence'],
): Finding {
  return {
    asset: makeAsset(d.primitive, d.parameters, d.purpose),
    systemId: opts.systemId,
    controlClass,
    ...(d.assumptions === undefined ? {} : { assumptions: d.assumptions }),
    evidence: {
      modality,
      locator: `${file}:${line}`,
      // The rule id and the purpose provenance travel with the observation, so
      // a reviewer chasing a false positive lands on the rule that fired and
      // can see whether the purpose was read off the API or defaulted.
      raw: `${d.ruleId} purpose=${d.purpose}(${d.purposeSource})${d.note ? ` note=${d.note}` : ''} :: ${raw.replace(/\s+/g, ' ').slice(0, 240)}`,
      collectedAt: opts.collectedAt,
      collectorVersion: COLLECTOR_VERSION,
      ...(occurrence === undefined ? {} : { occurrence }),
    },
  };
}
