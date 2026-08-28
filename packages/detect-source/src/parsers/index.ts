import Parser from 'tree-sitter';
import TypeScript from 'tree-sitter-typescript';
import JavaScript from 'tree-sitter-javascript';
import Python from 'tree-sitter-python';
import Go from 'tree-sitter-go';
import Java from 'tree-sitter-java';
import C from 'tree-sitter-c';
import Cpp from 'tree-sitter-cpp';
import Rust from 'tree-sitter-rust';
import CSharp from 'tree-sitter-c-sharp';
import type { Arg, CallSite, FileContext, Lang } from '../types.js';

/**
 * AST extraction. The output of this file is the difference between "RSA
 * appears in this repo" and "RSA/2048 for key establishment at src/keys.ts:41".
 *
 * Arguments are resolved only when they are literals. A variable-valued
 * argument comes back `unresolved` rather than guessed - a rule that cannot
 * see the modulus must say so, because a fabricated parameter changes the
 * asset identity and silently splits or merges work items.
 */

const GRAMMARS: Readonly<Record<Lang, unknown>> = {
  typescript: TypeScript.typescript,
  tsx: TypeScript.tsx,
  javascript: JavaScript,
  python: Python,
  go: Go,
  java: Java,
  c: C,
  cpp: Cpp,
  rust: Rust,
  csharp: CSharp,
};

/**
 * Call-expression node types across ten grammars.
 *
 * Each language names the same idea differently, and a rule set that only
 * knows `call_expression` silently finds nothing in Java or C#. Keeping the
 * set in one place is what lets one walker serve all of them.
 */
const CALL_NODES = new Set([
  'call_expression', // ts/js, go, c, cpp, rust
  'call', // python
  'method_invocation', // java
  'object_creation_expression', // java: new Cipher(...)
  'invocation_expression', // c#
  'macro_invocation', // rust
]);

const parsers = new Map<Lang, Parser>();

function parserFor(lang: Lang): Parser {
  const existing = parsers.get(lang);
  if (existing) return existing;
  const p = new Parser();
  p.setLanguage(GRAMMARS[lang] as never);
  parsers.set(lang, p);
  return p;
}

const EXTENSIONS: Readonly<Record<string, Lang>> = {
  '.ts': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.tsx': 'tsx',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.py': 'python',
  '.pyi': 'python',
  '.go': 'go',
  '.java': 'java',
  '.c': 'c',
  '.h': 'c',
  '.cc': 'cpp',
  '.cpp': 'cpp',
  '.cxx': 'cpp',
  '.hpp': 'cpp',
  '.hh': 'cpp',
  '.rs': 'rust',
  '.cs': 'csharp',
};

export function languageFor(file: string): Lang | null {
  const dot = file.lastIndexOf('.');
  if (dot < 0) return null;
  return EXTENSIONS[file.slice(dot).toLowerCase()] ?? null;
}

export interface ParsedFile {
  readonly context: FileContext;
  readonly calls: readonly CallSite[];
  /** Retained so the module graph can be built without re-parsing. */
  readonly root: Parser.SyntaxNode;
}

export function parseSource(file: string, source: string, lang: Lang): ParsedFile {
  const tree = parserFor(lang).parse(source);
  const imports = new Set<string>();
  const aliases = new Map<string, string>();
  const calls: CallSite[] = [];

  const stack: Parser.SyntaxNode[] = [tree.rootNode];
  while (stack.length > 0) {
    const node = stack.pop() as Parser.SyntaxNode;

    if (lang === 'python') collectPythonImports(node, imports, aliases);
    else if (lang === 'typescript' || lang === 'tsx' || lang === 'javascript') {
      collectJsImports(node, imports, aliases);
    } else collectOtherImports(node, imports, aliases);

    if (CALL_NODES.has(node.type)) {
      const call = toCallSite(node, file, lang);
      if (call) calls.push(call);
    }
    for (let i = node.namedChildCount - 1; i >= 0; i--) {
      const child = node.namedChild(i);
      if (child) stack.push(child);
    }
  }

  return { context: { file, lang, imports, aliases }, calls, root: tree.rootNode };
}

/* --------------------------------------------------------------- callee names */

function dottedName(node: Parser.SyntaxNode | null): string | null {
  if (!node) return null;
  switch (node.type) {
    case 'identifier':
    case 'property_identifier':
    case 'shorthand_property_identifier':
    case 'field_identifier':
    case 'type_identifier':
    case 'package_identifier':
      return node.text;
    case 'member_expression':
    case 'attribute':
    case 'selector_expression': // go
    case 'field_expression': // c, cpp, rust
    case 'scoped_identifier': // rust, java
    case 'qualified_identifier': // cpp
    case 'member_access_expression': // c#
    case 'scoped_type_identifier': {
      const object =
        node.childForFieldName('object') ??
        node.childForFieldName('operand') ??
        node.childForFieldName('argument') ??
        node.childForFieldName('path') ??
        node.childForFieldName('scope') ??
        node.childForFieldName('expression');
      const property =
        node.childForFieldName('property') ??
        node.childForFieldName('attribute') ??
        node.childForFieldName('field') ??
        node.childForFieldName('name');
      const left = dottedName(object);
      const right = property ? property.text : null;
      return left && right ? `${left}.${right}` : (right ?? left);
    }
    case 'call_expression':
    case 'call':
    case 'method_invocation':
    case 'invocation_expression':
    case 'macro_invocation': {
      // `require('crypto').createHash` - keep the tail, drop the call.
      return dottedName(
        node.childForFieldName('function') ??
          node.childForFieldName('macro') ??
          node.childForFieldName('name'),
      );
    }
    default:
      return null;
  }
}

function toCallSite(node: Parser.SyntaxNode, file: string, lang: Lang): CallSite | null {
  // Java splits the receiver and the method into separate fields; C# and Rust
  // use different names again. Reconstruct the dotted callee from whichever
  // this grammar provides.
  let callee: string | null;
  if (node.type === 'method_invocation') {
    const object = dottedName(node.childForFieldName('object'));
    const name = node.childForFieldName('name')?.text ?? null;
    callee = object && name ? `${object}.${name}` : name;
  } else if (node.type === 'object_creation_expression') {
    const type = dottedName(node.childForFieldName('type'));
    callee = type === null ? null : `new.${type}`;
  } else {
    callee = dottedName(
      node.childForFieldName('function') ??
        node.childForFieldName('macro') ??
        node.childForFieldName('name'),
    );
  }
  if (!callee) return null;

  const argsNode = node.childForFieldName('arguments') ?? node.childForFieldName('argument_list');
  const positional: Arg[] = [];
  const kwargs: Record<string, Arg> = {};

  if (argsNode) {
    for (let i = 0; i < argsNode.namedChildCount; i++) {
      const child = argsNode.namedChild(i);
      if (!child) continue;
      if (child.type === 'comment') continue;
      // C# wraps each argument in an `argument` node; Rust and Java do not.
      // Unwrapping here keeps every rule free of grammar trivia.
      if (child.type === 'argument') {
        const inner = child.namedChild(0);
        positional.push(inner === null ? toArg(child) : toArg(inner));
        continue;
      }
      if (lang === 'python' && child.type === 'keyword_argument') {
        const name = child.childForFieldName('name');
        const value = child.childForFieldName('value');
        if (name && value) kwargs[name.text] = toArg(value, name.text);
        continue;
      }
      positional.push(toArg(child));
    }
  }

  const parts = callee.split('.');
  return {
    callee,
    calleeParts: parts,
    method: parts[parts.length - 1] as string,
    args: positional,
    kwargs,
    file,
    line: node.startPosition.row + 1,
    column: node.startPosition.column,
    text: node.text.length > 300 ? `${node.text.slice(0, 300)}...` : node.text,
  };
}

/* ----------------------------------------------------------------- arguments */

function toArg(node: Parser.SyntaxNode, keyword?: string): Arg {
  const base = { text: node.text.length > 200 ? `${node.text.slice(0, 200)}...` : node.text };
  const kw = keyword === undefined ? {} : { keyword };

  switch (node.type) {
    case 'string':
    case 'template_string':
    case 'string_literal':
    case 'interpreted_string_literal':
    case 'raw_string_literal':
    case 'char_literal':
    case 'verbatim_string_literal': {
      const s = stringValue(node);
      return s === null
        ? { kind: 'unresolved', ...base, ...kw }
        : { kind: 'string', string: s, ...base, ...kw };
    }
    case 'number':
    case 'integer':
    case 'float':
    case 'int_literal':
    case 'float_literal':
    case 'number_literal':
    case 'integer_literal':
    case 'decimal_integer_literal':
    case 'hex_integer_literal': {
      const n = Number(node.text.replace(/_/g, ''));
      return Number.isFinite(n)
        ? { kind: 'number', number: n, ...base, ...kw }
        : { kind: 'unresolved', ...base, ...kw };
    }
    case 'true':
    case 'true_literal':
      return { kind: 'boolean', boolean: true, ...base, ...kw };
    case 'false':
    case 'false_literal':
      return { kind: 'boolean', boolean: false, ...base, ...kw };
    case 'unary_expression': {
      const inner = node.namedChild(0);
      if (inner && (inner.type === 'number' || inner.type === 'integer')) {
        return { kind: 'number', number: -Number(inner.text), ...base, ...kw };
      }
      return { kind: 'unresolved', ...base, ...kw };
    }
    case 'object':
    case 'dictionary':
      return { kind: 'object', object: objectValue(node), ...base, ...kw };
    case 'array':
    case 'list': {
      const items: Arg[] = [];
      for (let i = 0; i < node.namedChildCount; i++) {
        const c = node.namedChild(i);
        if (c) items.push(toArg(c));
      }
      return { kind: 'array', array: items, ...base, ...kw };
    }
    case 'call_expression':
    case 'call':
    case 'method_invocation':
    case 'invocation_expression':
    case 'macro_invocation': {
      const callee = dottedName(
        node.childForFieldName('function') ??
          node.childForFieldName('macro') ??
          node.childForFieldName('name'),
      );
      const inner = node.childForFieldName('arguments') ?? node.childForFieldName('argument_list');
      const items: Arg[] = [];
      if (inner) {
        for (let i = 0; i < inner.namedChildCount; i++) {
          const c = inner.namedChild(i);
          if (c) items.push(toArg(c));
        }
      }
      return {
        kind: 'call',
        ...(callee === null ? {} : { callee }),
        array: items,
        ...base,
        ...kw,
      };
    }
    // An identifier or member expression is a value we cannot see. Saying so is
    // the whole point; a rule may still fire on the primitive and omit the
    // parameter rather than inventing one.
    default:
      return { kind: 'unresolved', ...base, ...kw };
  }
}

function stringValue(node: Parser.SyntaxNode): string | null {
  const raw = node.text;
  // Template literals with interpolation are not constants.
  if (node.type === 'template_string' && raw.includes('${')) return null;
  if (/^[a-zA-Z]*['"`]/.test(raw)) {
    const quote = raw.replace(/^[a-zA-Z]*/, '')[0];
    if (quote === undefined) return null;
    const body = raw.replace(/^[a-zA-Z]*/, '');
    const inner = body.slice(1, body.lastIndexOf(quote));
    return inner;
  }
  return null;
}

function objectValue(node: Parser.SyntaxNode): Record<string, Arg> {
  const out: Record<string, Arg> = {};
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (!child) continue;
    if (child.type === 'pair') {
      const key = child.childForFieldName('key');
      const value = child.childForFieldName('value');
      if (!key || !value) continue;
      const name =
        key.type === 'string' ? (stringValue(key) ?? key.text) : key.text.replace(/^["']|["']$/g, '');
      out[name] = toArg(value);
    } else if (child.type === 'shorthand_property_identifier') {
      out[child.text] = { kind: 'unresolved', text: child.text };
    }
  }
  return out;
}

/* ------------------------------------------------------------------- imports */

function collectJsImports(
  node: Parser.SyntaxNode,
  imports: Set<string>,
  aliases: Map<string, string>,
): void {
  if (node.type === 'import_statement') {
    const source = node.childForFieldName('source');
    const mod = source ? stringValue(source) : null;
    if (!mod) return;
    imports.add(mod);
    imports.add(mod.replace(/^node:/, ''));
    for (let i = 0; i < node.namedChildCount; i++) {
      const clause = node.namedChild(i);
      if (!clause || clause.type !== 'import_clause') continue;
      bindImportClause(clause, mod, aliases);
    }
    return;
  }
  // const crypto = require('crypto')  /  const { createHash } = require('crypto')
  if (node.type === 'variable_declarator') {
    const value = node.childForFieldName('value');
    if (!value || (value.type !== 'call_expression' && value.type !== 'call')) return;
    const fn = value.childForFieldName('function');
    if (!fn || fn.text !== 'require') return;
    const argsNode = value.childForFieldName('arguments');
    const first = argsNode?.namedChild(0);
    const mod = first ? stringValue(first) : null;
    if (!mod) return;
    imports.add(mod);
    imports.add(mod.replace(/^node:/, ''));
    const name = node.childForFieldName('name');
    if (!name) return;
    if (name.type === 'identifier') aliases.set(name.text, mod);
    else bindPattern(name, mod, aliases);
  }
}

function bindImportClause(clause: Parser.SyntaxNode, mod: string, aliases: Map<string, string>): void {
  for (let i = 0; i < clause.namedChildCount; i++) {
    const c = clause.namedChild(i);
    if (!c) continue;
    if (c.type === 'identifier') aliases.set(c.text, mod);
    else if (c.type === 'namespace_import') {
      const id = c.namedChild(c.namedChildCount - 1);
      if (id) aliases.set(id.text, mod);
    } else if (c.type === 'named_imports') {
      for (let j = 0; j < c.namedChildCount; j++) {
        const spec = c.namedChild(j);
        if (!spec || spec.type !== 'import_specifier') continue;
        const alias = spec.childForFieldName('alias');
        const name = spec.childForFieldName('name');
        const local = alias ?? name;
        if (local) aliases.set(local.text, mod);
      }
    }
  }
}

function bindPattern(node: Parser.SyntaxNode, mod: string, aliases: Map<string, string>): void {
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (!c) continue;
    if (c.type === 'shorthand_property_identifier_pattern' || c.type === 'identifier') {
      aliases.set(c.text, mod);
    } else {
      bindPattern(c, mod, aliases);
    }
  }
}

/**
 * Go, Java, C/C++, Rust and C# imports.
 *
 * Import gating is the single largest lever on precision in every language:
 * `Cipher.getInstance("DES")` is a finding only when javax.crypto is in
 * scope, and a local class called Cipher is not.
 */
function collectOtherImports(
  node: Parser.SyntaxNode,
  imports: Set<string>,
  aliases: Map<string, string>,
): void {
  const record = (spec: string): void => {
    const clean = spec.replace(/^["'<]|[">']$/g, '').trim();
    if (clean === '') return;
    imports.add(clean);
    const last = clean.split(/[/.:]/).filter(Boolean).pop();
    if (last !== undefined) aliases.set(last.replace(/\.[ch]pp?$/, ''), clean);
  };

  switch (node.type) {
    case 'import_spec': // go
    case 'import_declaration': // go, java
    case 'use_declaration': // rust
    case 'using_directive': { // c#
      record(node.text.replace(/^(import|use|using)\s+/, '').replace(/;$/, ''));
      // A Go import spec may be aliased: `crypto "crypto/rsa"`.
      const name = node.childForFieldName('name');
      const path = node.childForFieldName('path');
      if (name && path) aliases.set(name.text, path.text.replace(/^"|"$/g, ''));
      return;
    }
    case 'preproc_include': { // c, cpp
      const path = node.childForFieldName('path');
      if (path) record(path.text);
      return;
    }
    default:
      return;
  }
}

function collectPythonImports(
  node: Parser.SyntaxNode,
  imports: Set<string>,
  aliases: Map<string, string>,
): void {
  if (node.type === 'import_statement') {
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i);
      if (!c) continue;
      if (c.type === 'dotted_name') {
        imports.add(c.text);
        aliases.set(c.text.split('.')[0] as string, c.text);
      } else if (c.type === 'aliased_import') {
        const name = c.childForFieldName('name');
        const alias = c.childForFieldName('alias');
        if (name) imports.add(name.text);
        if (name && alias) aliases.set(alias.text, name.text);
      }
    }
    return;
  }
  if (node.type === 'import_from_statement') {
    const moduleName = node.childForFieldName('module_name');
    const mod = moduleName ? moduleName.text : null;
    if (!mod) return;
    imports.add(mod);
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i);
      if (!c || c === moduleName) continue;
      if (c.type === 'dotted_name') {
        imports.add(`${mod}.${c.text}`);
        aliases.set(c.text, `${mod}.${c.text}`);
      } else if (c.type === 'aliased_import') {
        const name = c.childForFieldName('name');
        const alias = c.childForFieldName('alias');
        if (name) imports.add(`${mod}.${name.text}`);
        if (name && alias) aliases.set(alias.text, `${mod}.${name.text}`);
      }
    }
  }
}
