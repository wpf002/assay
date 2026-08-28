import type { Lang, Rule } from '../types.js';
import { TYPESCRIPT_RULES } from './typescript.js';
import { PYTHON_RULES } from './python.js';

export const RULES: readonly Rule[] = [...TYPESCRIPT_RULES, ...PYTHON_RULES];

/** Method-name index. Dispatch is O(1) per call site rather than O(rules). */
export function ruleIndex(lang: Lang): ReadonlyMap<string, readonly Rule[]> {
  const index = new Map<string, Rule[]>();
  for (const rule of RULES) {
    if (!rule.languages.includes(lang)) continue;
    for (const method of rule.methods) {
      const list = index.get(method);
      if (list) list.push(rule);
      else index.set(method, [rule]);
    }
  }
  return index;
}

export { TYPESCRIPT_RULES, PYTHON_RULES };
export type { Rule };
