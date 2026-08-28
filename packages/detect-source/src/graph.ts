import Parser from 'tree-sitter';
import { dirname, join, normalize, relative } from 'node:path';
import type { Lang } from './types.js';

/**
 * Module graph and within-file liveness.
 *
 * WHAT THIS IS: an import graph from detected entry points, refined by a
 * within-file call graph. A crypto site counts as reached when its file is
 * transitively imported from an entry point AND its enclosing function is
 * exported, or reachable from an exported function, or the site sits at module
 * top level.
 *
 * WHAT THIS IS NOT: interprocedural analysis across files. Without type
 * information you cannot resolve `svc.sign()` to a definition, so the file
 * edge is an over-approximation - importing a module does not prove you call
 * every function in it. The direction of that error matters: it can report
 * something as reached that is not, and it will not report something as
 * unreached that is. For a migration worklist that is the right way round, and
 * it is stated rather than hidden.
 *
 * It also stops at the network edge. A service that calls a signing service
 * over gRPC looks unreached from here, which is why distributed-trace ingest
 * is an open question rather than a claim.
 */

export type EntryKind =
  | 'http-server'
  | 'framework-route'
  | 'package-main'
  | 'package-bin'
  | 'python-main'
  | 'python-wsgi';

export interface CryptoSite {
  readonly line: number;
  /** Enclosing function chain, outermost first. Empty means module top level. */
  readonly functions: readonly string[];
}

export interface ModuleNode {
  readonly file: string;
  readonly lang: Lang;
  /** Relative-import specifiers resolved to files inside the tree. */
  readonly localImports: readonly string[];
  readonly externalImports: readonly string[];
  readonly isTest: boolean;
  readonly entryKind: EntryKind | null;
  /** Top-level function names this module exports. */
  readonly exported: ReadonlySet<string>;
  /** caller -> callees, within this file only. */
  readonly callEdges: ReadonlyMap<string, ReadonlySet<string>>;
}

export interface ModuleGraph {
  readonly nodes: ReadonlyMap<string, ModuleNode>;
  /**
   * Workspace package name -> directory, from every package.json in the tree.
   *
   * Without this a monorepo has no edges at all: `import { x } from
   * '@acme/core'` is a bare specifier, indistinguishable from `express`, so
   * every package looks like an island and almost everything reports as
   * unreached. That error runs in the dangerous direction - it retires real
   * production crypto - so resolving workspace names is not an optimization.
   */
  readonly packages: ReadonlyMap<string, string>;
  /**
   * Files named as a package entry point (main / module / exports / bin).
   * A published package's public surface is reachable by definition; there is
   * no server to start, and refusing to say so marks a whole library dead.
   */
  readonly packageEntries: readonly string[];
  /**
   * Directories whose manifest actually declares a public surface - a
   * package.json with main/module/exports/bin, or any Python package manifest.
   *
   * A repo whose package.json declares none of those is a service, not a
   * library: it has an entry point and everything else is reachable from it or
   * is dead. Treating such a tree as a published surface would mark orphaned
   * modules alive and defeat the whole point of the analysis.
   */
  readonly publishedDirs: ReadonlySet<string>;
}

const TEST_PATH =
  /(^|\/)(tests?|__tests__|__test__|spec|e2e|fixtures?|testdata|mocks?|__mocks__)(\/|$)/i;
const TEST_FILE =
  /(\.|_)(test|spec)\.[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.py$|(^|\/)conftest\.py$/i;

export function isTestPath(file: string): boolean {
  const f = file.replace(/\\/g, '/');
  return TEST_PATH.test(f) || TEST_FILE.test(f);
}

/* ------------------------------------------------------------- node building */

export interface BuildNodeInput {
  readonly file: string;
  readonly lang: Lang;
  readonly root: Parser.SyntaxNode;
  readonly source: string;
}

export function buildModuleNode(input: BuildNodeInput): ModuleNode {
  const { file, lang, root, source } = input;
  const localImports: string[] = [];
  const externalImports: string[] = [];
  const exported = new Set<string>();
  const callEdges = new Map<string, Set<string>>();

  const visit = (node: Parser.SyntaxNode, fnStack: string[], exportedHere: boolean): void => {
    const type = node.type;

    if (lang === 'python') {
      if (type === 'import_from_statement' || type === 'import_statement') {
        for (const spec of moduleSpecifiers(node)) classify(spec, file, localImports, externalImports);
      }
    } else if (type === 'import_statement') {
      const src = node.childForFieldName('source');
      if (src) classify(literal(src), file, localImports, externalImports);
    } else if (type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn?.text === 'require') {
        const first = node.childForFieldName('arguments')?.namedChild(0);
        if (first) classify(literal(first), file, localImports, externalImports);
      }
    }

    // Function definitions and the export marker above them.
    const name = functionName(node, lang);
    if (name !== null) {
      const nowExported =
        exportedHere ||
        isExported(node, lang) ||
        // Python has no export keyword: a module-level def is public unless
        // it is underscore-prefixed by convention.
        (lang === 'python' && fnStack.length === 0 && !name.startsWith('_'));
      if (nowExported && fnStack.length === 0) exported.add(name);
      const nextStack = [...fnStack, name];
      for (let i = 0; i < node.namedChildCount; i++) {
        const c = node.namedChild(i);
        if (c) visit(c, nextStack, false);
      }
      return;
    }

    if ((type === 'call_expression' || type === 'call') && fnStack.length > 0) {
      const callee = calleeRoot(node);
      if (callee !== null) {
        const caller = fnStack[fnStack.length - 1] as string;
        const set = callEdges.get(caller) ?? new Set<string>();
        set.add(callee);
        callEdges.set(caller, set);
      }
    }

    const propagateExport =
      exportedHere ||
      type === 'export_statement' ||
      (lang !== 'python' && type === 'export_clause');

    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i);
      if (c) visit(c, fnStack, propagateExport);
    }
  };

  visit(root, [], false);

  return {
    file,
    lang,
    localImports: [...new Set(localImports)].sort(),
    externalImports: [...new Set(externalImports)].sort(),
    isTest: isTestPath(file),
    entryKind: detectEntry(file, source, lang),
    exported,
    callEdges,
  };
}

/** Enclosing function chain for a line, used to name a CallFrame. */
export function functionsAt(root: Parser.SyntaxNode, lang: Lang, line: number): string[] {
  const chain: string[] = [];
  const walk = (node: Parser.SyntaxNode, stack: string[]): void => {
    const startLine = node.startPosition.row + 1;
    const endLine = node.endPosition.row + 1;
    if (line < startLine || line > endLine) return;
    const name = functionName(node, lang);
    const next = name === null ? stack : [...stack, name];
    if (next.length > chain.length) chain.length = 0, chain.push(...next);
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i);
      if (c) walk(c, next);
    }
  };
  walk(root, []);
  return chain;
}

/* ------------------------------------------------------------------ helpers */

function functionName(node: Parser.SyntaxNode, lang: Lang): string | null {
  if (lang === 'python') {
    if (node.type === 'function_definition') return node.childForFieldName('name')?.text ?? null;
    if (node.type === 'class_definition') return node.childForFieldName('name')?.text ?? null;
    return null;
  }
  switch (node.type) {
    case 'function_declaration':
    case 'generator_function_declaration':
    case 'class_declaration':
      return node.childForFieldName('name')?.text ?? null;
    case 'method_definition':
      return node.childForFieldName('name')?.text ?? null;
    case 'variable_declarator': {
      const value = node.childForFieldName('value');
      if (
        value &&
        (value.type === 'arrow_function' ||
          value.type === 'function' ||
          value.type === 'function_expression')
      ) {
        return node.childForFieldName('name')?.text ?? null;
      }
      return null;
    }
    default:
      return null;
  }
}

function isExported(node: Parser.SyntaxNode, lang: Lang): boolean {
  if (lang === 'python') return false;
  let p: Parser.SyntaxNode | null = node.parent;
  for (let depth = 0; p !== null && depth < 4; depth++, p = p.parent) {
    if (p.type === 'export_statement') return true;
  }
  return false;
}

function calleeRoot(node: Parser.SyntaxNode): string | null {
  const fn = node.childForFieldName('function');
  if (!fn) return null;
  if (fn.type === 'identifier') return fn.text;
  if (fn.type === 'member_expression' || fn.type === 'attribute') {
    const prop = fn.childForFieldName('property') ?? fn.childForFieldName('attribute');
    return prop?.text ?? null;
  }
  return null;
}

function literal(node: Parser.SyntaxNode): string {
  return node.text.replace(/^[a-zA-Z]*['"`]/, '').replace(/['"`]$/, '');
}

function moduleSpecifiers(node: Parser.SyntaxNode): string[] {
  const out: string[] = [];
  const moduleName = node.childForFieldName('module_name');
  if (moduleName) out.push(moduleName.text);
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c && c.type === 'dotted_name' && c !== moduleName && moduleName === null) out.push(c.text);
    if (c && c.type === 'relative_import') out.push(c.text);
  }
  return out;
}

function classify(spec: string, from: string, local: string[], external: string[]): void {
  if (spec === '') return;
  if (spec.startsWith('.')) {
    local.push(normalize(join(dirname(from), spec)).replace(/\\/g, '/'));
    return;
  }
  external.push(spec);
}

const HTTP_SERVER =
  /\.listen\s*\(|createServer\s*\(|app\.(get|post|put|delete|patch|use)\s*\(|new\s+Hono\s*\(|fastify\s*\(/;
const PY_APP = /Flask\s*\(|FastAPI\s*\(|urlpatterns\s*=|application\s*=\s*get_[wa]sgi_application/;

function detectEntry(file: string, source: string, lang: Lang): EntryKind | null {
  const f = file.replace(/\\/g, '/');
  if (lang === 'python') {
    if (/(^|\/)(wsgi|asgi|manage)\.py$/.test(f)) return 'python-wsgi';
    if (/if\s+__name__\s*==\s*['"]__main__['"]/.test(source)) return 'python-main';
    if (PY_APP.test(source)) return 'framework-route';
    return null;
  }
  if (/(^|\/)(app|pages)\/.*\/(route|page|layout)\.[jt]sx?$/.test(f)) return 'framework-route';
  if (/(^|\/)pages\/api\//.test(f)) return 'framework-route';
  if (HTTP_SERVER.test(source)) return 'http-server';
  if (/(^|\/)(server|main|index|cli|bin)\.[jt]sx?$/.test(f) && /^#!|process\.argv/.test(source)) {
    return 'package-bin';
  }
  return null;
}
