/**
 * Coverage breakdown for a scanned tree: how many files, which rules fired,
 * which primitives came back, and which crypto-looking dependencies are missing
 * from the catalog. Used to run the Phase 1 exit gate. See VALIDATION.md.
 *
 *   node apps/cli/tools/analyze.mjs /path/to/repo
 */
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { assemble } from '@assay/correlate';

const root = process.argv[2];
const collectedAt = '2026-08-28T00:00:00.000Z';
const src = await scanSource({ root, systemId: 'x', collectedAt });
const deps = await scanDependencies({ root, systemId: 'x', collectedAt });
const { occurrences, assets } = assemble([...src.findings, ...deps.findings]);

const byRule = {};
for (const f of src.findings) {
  const rule = f.evidence.raw.split(' ')[0];
  byRule[rule] = (byRule[rule] ?? 0) + 1;
}
const byPrim = {};
for (const f of src.findings) byPrim[f.asset.primitive] = (byPrim[f.asset.primitive] ?? 0) + 1;

console.log(JSON.stringify({
  files: src.filesScanned,
  skipped: src.filesSkipped.length,
  sourceFindings: src.findings.length,
  depFindings: deps.findings.length,
  occurrences: occurrences.length,
  assets: assets.length,
  vulnerable: assets.filter(a => a.quantumVulnerable).length,
  byRule, byPrim,
  uncatalogued: deps.uncatalogued.slice(0, 10),
}, null, 2));
