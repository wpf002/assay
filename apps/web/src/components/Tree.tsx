'use client';

import type { ExplainNode } from '@/lib/api';

/**
 * A derivation, rendered as what it is: a tree with a kind on every node.
 *
 * ASSUMPTION nodes are coloured like a failure because that is what they are -
 * the reason a finding cannot be CONFIRMED. Burying them at the same weight as
 * the rest is how a guess ends up looking like a fact.
 */
export function Tree({ node }: { node: ExplainNode }) {
  return (
    <div className="tree">
      <Node node={node} />
    </div>
  );
}

function Node({ node }: { node: ExplainNode }) {
  return (
    <>
      <div className="node" style={{ paddingLeft: `${node.depth * 18}px` }}>
        <span className={`kind ${node.kind}`}>{node.kind}</span>
        <span>{node.label}</span>{' '}
        <span className="val">= {String(node.value)}</span>
      </div>
      {node.children.map((c) => (
        <Node key={c.id} node={c} />
      ))}
    </>
  );
}
