/**
 * Draws a deterministic, stratified sample of CONFIRMED evidence records for
 * hand verification. OFFSET shifts the stride so a second sample is disjoint
 * from the first - which is how you check you did not tune to the sample.
 *
 *   node apps/cli/tools/sample.mjs /path/to/repo [more repos...]
 *   OFFSET=7 node apps/cli/tools/sample.mjs /path/to/repo
 */
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { assemble } from '@assay/correlate';
import { gate } from '@assay/core';

const offset = Number(process.env.OFFSET ?? 0);
const roots = process.argv.slice(2);
const collectedAt = '2026-08-28T00:00:00.000Z';
const rows = [];
for (const root of roots) {
  const name = root.split('/').pop();
  const src = await scanSource({ root, systemId: name, collectedAt });
  const deps = await scanDependencies({ root, systemId: name, collectedAt });
  const { occurrences, assets } = assemble([...src.findings, ...deps.findings]);
  const byId = new Map(assets.map(a => [a.id, a]));
  for (const o of occurrences) {
    if (gate(o).assertionLevel !== 'CONFIRMED') continue;
    const a = byId.get(o.assetId);
    for (const e of o.evidence) {
      rows.push({ repo: name, locator: e.locator, primitive: a.primitive,
        params: JSON.stringify(a.parameters), purpose: a.purpose,
        rule: e.raw.split(' ')[0], raw: e.raw.slice(0, 200) });
    }
  }
}
// Deterministic stratified sample: every Nth row, so no repo or rule dominates.
rows.sort((x, y) => (x.repo + x.rule + x.locator).localeCompare(y.repo + y.rule + y.locator));
const step = Math.max(1, Math.floor(rows.length / 30));
const sample = [];
for (let i = offset; i < rows.length && sample.length < 30; i += step) sample.push(rows[i]);
console.log(`# population ${rows.length} CONFIRMED evidence records; sampling every ${step}\n`);
sample.forEach((r, i) => {
  console.log(`${String(i + 1).padStart(2)}. ${r.repo}  ${r.locator}`);
  console.log(`    -> ${r.primitive}${r.params === '{}' ? '' : r.params} / ${r.purpose}   [${r.rule}]`);
});
