/** Why is a finding unreached? Prints the graph's view of one tree. */
import { scanSource } from '@assay/detect-source';
import { assemble, analyzeReachability } from '@assay/correlate';

const root = process.argv[2];
const src = await scanSource({ root, systemId: 'x', collectedAt: '2026-08-28T00:00:00.000Z' });
const { occurrences, assets } = assemble(src.findings);
const r = analyzeReachability(occurrences, src.graph);
const byId = new Map(assets.map((a) => [a.id, a]));

console.log('nodes', src.graph.nodes.size, 'packages', src.graph.packages.size,
  'packageEntries', src.graph.packageEntries.length, 'entryPoints', r.entryPoints.length,
  'reachableFiles', r.reachableFiles.size);
for (const o of r.occurrences) {
  const a = byId.get(o.assetId);
  const st = o.reachability === null ? 'null' : o.reachability.reachable ? o.reachability.via : 'dead';
  console.log(`${st.padEnd(16)} ${a.primitive.padEnd(8)} ${o.evidence[0].locator.slice(0, 70)}`);
  if (st === 'dead') {
    for (const s of o.reachability.factor.sources.slice(0, 2)) console.log('           why:', s.label.slice(0, 110));
  }
}
