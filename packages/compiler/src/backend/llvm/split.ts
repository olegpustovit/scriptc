/** Native-library LLVM IR sharding.
 *
 * The public `.ll` remains the emitter's single canonical module. Native dev
 * builds may compile this equivalent set of smaller modules in parallel, then
 * relocatably merge their objects before archive assembly:
 *
 * - the first shard owns every module-scope global and the first function
 *   group; later shards own only function groups;
 * - the shared preamble carries types and declarations into every shard;
 * - generated internal functions/globals are promoted to hidden linkage so
 *   references can cross object files; the post-compile relocatable link turns
 *   those hidden definitions back into local symbols on every supported object
 *   format;
 * - declarations synthesized from definitions make every shard independently
 *   valid LLVM IR without changing call signatures;
 * - each shard carries only the debug-metadata nodes reachable from what it
 *   defines, renumbered densely in first-use order, so a shard's text (and
 *   object cache key) depends on its own content and not on unrelated edits.
 *
 * The splitter deliberately accepts only the narrow grammar scriptc emits.
 * An unexpected top-level form returns null and the caller compiles the
 * canonical TU normally — cache optimization must never become correctness.
 */

export interface LlvmProgramShard {
  /** Stable source identity used in object cache keys and diagnostics. */
  name: string;
  source: string;
}

export interface LlvmProgramSplit {
  shards: LlvmProgramShard[];
  /** Generated definitions promoted for shard linkage. The relocatable merge
   * must demote these while retaining the canonical public definitions. */
  promotedSymbols: string[];
  /** Canonical non-internal definitions that must stay externally visible
   * after the shard objects are relocatably merged. */
  publicSymbols: string[];
}

export interface LlvmProgramSplitOptions {
  /** Desired maximum source size per function shard. */
  targetBytes?: number;
  /** Inputs smaller than this keep the single-TU path. */
  minimumBytes?: number;
}

const DEFAULT_TARGET_BYTES = 2 * 1024 * 1024;
const DEFAULT_MINIMUM_BYTES = 4 * 1024 * 1024;
// Library edits pay a relocatable merge/archive cost after shard compilation,
// but their stable per-bucket object cache starts winning earlier than the
// executable lane's whole-program posture. Node 24 Linux profiling across
// 1.62–3.24MB generated modules found the crossover at roughly 2MB; four
// function buckets were the best general tradeoff for the 2.15MB target and
// remained profitable through 3.24MB. Executables retain the defaults above.
const LIBRARY_TARGET_BYTES = 768 * 1024;
const LIBRARY_MINIMUM_BYTES = 2 * 1024 * 1024;

interface FunctionDef {
  source: string;
  refs: number[];
  symbols: Set<string>;
  declaration: string;
  symbol: string;
  promoted: boolean;
}

interface GlobalDef {
  line: string;
  refs: number[];
  symbols: Set<string>;
  declaration: string | null;
  symbol: string;
  promoted: boolean;
}

// A quoted string (skipped, it may contain "!1") or a numbered metadata ref.
const MD_REF = /"(?:[^"\\]|\\.)*"|!(\d+)/g;

function mdRefs(text: string): number[] {
  const out: number[] = [];
  for (const m of text.matchAll(MD_REF)) if (m[1] !== undefined) out.push(Number(m[1]));
  return out;
}

const SYMBOL_REF = /@([-$._A-Za-z][-$.\w]*)/g;

function symbolRefs(text: string): Set<string> {
  return new Set(Array.from(text.matchAll(SYMBOL_REF), (m) => m[1]!));
}

function mdRewrite(text: string, ids: ReadonlyMap<number, number>): string {
  return text.replace(MD_REF, (all, d: string | undefined) => (d === undefined ? all : `!${ids.get(Number(d))}`));
}

interface Metadata {
  attrs: string[];
  nodes: Map<number, { body: string; refs: number[] }>;
  /** DICompileUnit bodies without `globals:`; only the globals shard defines
   * globals, and the list would pull every file's variables into every shard. */
  bare: Map<number, { body: string; refs: number[] }>;
  /** Named metadata other than !llvm.dbg.cu: always kept, their refs are roots. */
  named: { line: string; refs: number[] }[];
  cus: number[];
}

/** Metadata a shard needs: the nodes reachable from `pieces`, renumbered in
 * first-use order, plus the rewritten tail text. Null if a ref dangles. */
function shardTail(md: Metadata, pieces: readonly (readonly number[])[], withGlobals: boolean): { ids: Map<number, number>; tail: string } | null {
  const ids = new Map<number, number>();
  const order: number[] = [];
  const stack: number[] = [];
  for (const refs of [...md.named.map((n) => n.refs), ...pieces]) {
    for (let i = refs.length - 1; i >= 0; i--) stack.push(refs[i]!);
    // Roots are visited in text order: reverse-pushed above, popped here.
    while (stack.length > 0) {
      const id = stack.pop()!;
      if (ids.has(id)) continue;
      const node = (withGlobals ? undefined : md.bare.get(id)) ?? md.nodes.get(id);
      if (node === undefined) return null;
      ids.set(id, order.length);
      order.push(id);
      for (let i = node.refs.length - 1; i >= 0; i--) stack.push(node.refs[i]!);
    }
  }
  const cus = md.cus.filter((id) => ids.has(id)).map((id) => ids.get(id)!).sort((a, b) => a - b);
  const lines = [
    ...md.attrs,
    ...(cus.length === 0 ? [] : [`!llvm.dbg.cu = !{${cus.map((id) => `!${id}`).join(", ")}}`]),
    ...md.named.map((n) => mdRewrite(n.line, ids)),
    ...order.map((id, n) => `!${n} = ${mdRewrite(((withGlobals ? undefined : md.bare.get(id)) ?? md.nodes.get(id)!).body, ids)}`),
  ];
  return { ids, tail: lines.length === 0 ? "" : `\n${lines.join("\n")}` };
}

function symbolOf(spelling: string): string | null {
  const match = /^@([-$._A-Za-z][-$.\w]*)$/.exec(spelling);
  return match?.[1] ?? null;
}

function functionDefAt(lines: readonly string[], start: number): { def: FunctionDef; end: number } | null {
  const header = lines[start]!;
  const match = /^define\s+(internal\s+)?(.+?)\s+(@[-$._A-Za-z][-$.\w]*)\((.*)\)(.*)\{(?:\s*;.*)?$/.exec(header);
  if (!match) return null;
  let end = start + 1;
  while (end < lines.length && lines[end] !== "}") end++;
  if (end >= lines.length) return null;
  const symbol = symbolOf(match[3]!);
  if (symbol === null) return null;
  const promoted = match[1] !== undefined;
  const linkage = promoted ? "hidden " : "";
  const definitionHeader = promoted ? header.replace(/^define internal /, "define hidden ") : header;
  const source = [definitionHeader, ...lines.slice(start + 1, end + 1)].join("\n");
  // Parameter names are legal on declarations. Preserve the emitted text so
  // attributes, zeroext, and varargs stay byte-exact.
  // A definition's DISubprogram cannot be attached to a declaration in a
  // different shard. Its owning definition retains the original metadata.
  const attrs = match[5]!.replace(/\s+!dbg !\d+/g, "");
  const declaration = `declare ${linkage}${match[2]} ${match[3]}(${match[4]})${attrs}`.trimEnd();
  return { def: { source, refs: mdRefs(source), symbols: symbolRefs(source), declaration, symbol, promoted }, end };
}

function globalDef(line: string): GlobalDef | null {
  const match = /^(@[-$._A-Za-z][-$.\w]*)\s+=\s+(internal\s+)?(thread_local(?:\([^)]*\))?\s+)?(global|constant)\s+(.+)$/.exec(line);
  if (!match) return null;
  const symbol = symbolOf(match[1]!);
  if (symbol === null) return null;
  const promoted = match[2] !== undefined;
  const threadLocal = match[3] === undefined ? "" : `${match[3].trim()} `;
  // The declaration needs only the complete type. Emitted initializers begin
  // after it; the generated LLVM subset uses first-class scalars/pointers or
  // balanced aggregate types, so one small scanner is sufficient.
  const rest = match[5]!;
  let depth = 0;
  let quote = false;
  let typeEnd = -1;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i]!;
    if (ch === '"' && rest[i - 1] !== "\\") quote = !quote;
    if (quote) continue;
    if (ch === "{" || ch === "[" || ch === "<" || ch === "(") depth++;
    else if (ch === "}" || ch === "]" || ch === ">" || ch === ")") depth--;
    else if (ch === " " && depth === 0) {
      typeEnd = i;
      break;
    }
  }
  if (typeEnd < 0) return null;
  const type = rest.slice(0, typeEnd);
  return {
    refs: mdRefs(line),
    symbols: symbolRefs(line),
    line: promoted ? line.replace(`${match[1]} = internal `, `${match[1]} = hidden `) : line,
    declaration: `${match[1]} = external ${promoted ? "hidden " : ""}${threadLocal}${match[4]} ${type}`,
    symbol,
    promoted,
  };
}

function stableBucket(symbol: string, count: number): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < symbol.length; i++) {
    hash ^= symbol.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0) % count;
}

function chunksOf(
  functions: readonly FunctionDef[],
  targetBytes: number,
): { bucket: number; functions: FunctionDef[] }[] {
  const totalBytes = functions.reduce((sum, fn) => sum + Buffer.byteLength(fn.source) + 2, 0);
  // A power-of-two bucket count changes only when the program crosses a wide
  // size band. Ordinary edits therefore keep every function in the same
  // symbol-hash bucket; ceil(total/target) would reshuffle the whole program
  // whenever a small edit happened to add the next bucket.
  const required = Math.max(2, Math.ceil(totalBytes / targetBytes));
  const count = 2 ** Math.ceil(Math.log2(required));
  const chunks = Array.from({ length: count }, (): FunctionDef[] => []);
  for (const fn of functions) chunks[stableBucket(fn.symbol, count)]!.push(fn);
  return chunks.flatMap((chunk, bucket) =>
    chunk.length === 0 ? [] : [{ bucket, functions: chunk }],
  );
}

export function splitLlvmProgram(
  source: string,
  options: LlvmProgramSplitOptions = {},
): LlvmProgramSplit | null {
  const minimumBytes = options.minimumBytes ?? DEFAULT_MINIMUM_BYTES;
  if (Buffer.byteLength(source) < minimumBytes) return null;
  const targetBytes = Math.max(64 * 1024, options.targetBytes ?? DEFAULT_TARGET_BYTES);
  const lines = source.split("\n");
  const preamble: string[] = [];
  const globals: GlobalDef[] = [];
  const functions: FunctionDef[] = [];
  const md: Metadata = { attrs: [], nodes: new Map(), bare: new Map(), named: [], cus: [] };
  let sawDefinition = false;
  let inTrailer = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsWith("define ")) {
      if (inTrailer) return null;
      const parsed = functionDefAt(lines, i);
      if (parsed === null) return null;
      functions.push(parsed.def);
      sawDefinition = true;
      i = parsed.end;
      continue;
    }
    if (line.startsWith("@") && line.includes(" = ")) {
      if (inTrailer) return null;
      const parsed = globalDef(line);
      if (parsed === null) {
        // External declarations are already valid in every shard.
        if (/^@.+\s+=\s+external\s+/.test(line)) preamble.push(line);
        else return null;
      } else {
        // LLVM textual external TLS declarations compile on Darwin, but GNU
        // ELF clang emits the cross-shard reference as non-TLS and `ld -r`
        // correctly refuses the mismatch. Thread-instanced libraries keep
        // the canonical single-TU path until the producer can preserve TLS
        // model metadata portably across object formats.
        if (/\bthread_local(?:\([^)]*\))?\s+global\b/.test(line)) return null;
        globals.push(parsed);
        sawDefinition = true;
      }
      continue;
    }
    if (line.startsWith("attributes ") || line.startsWith("!")) inTrailer = true;
    if (inTrailer) {
      if (!line.startsWith("!")) {
        md.attrs.push(line);
        continue;
      }
      const node = /^!(\d+) = (.*)$/.exec(line);
      if (node !== null) {
        const id = Number(node[1]);
        if (md.nodes.has(id)) return null;
        md.nodes.set(id, { body: node[2]!, refs: mdRefs(node[2]!) });
        if (node[2]!.startsWith("distinct !DICompileUnit(")) {
          const body = node[2]!.replace(/, globals: !\d+/, "");
          md.bare.set(id, { body, refs: mdRefs(body) });
        }
        continue;
      }
      const named = /^!([A-Za-z_.$][\w.$]*) = (.*)$/.exec(line);
      if (named === null) return null;
      if (named[1] === "llvm.dbg.cu") md.cus = mdRefs(named[2]!);
      else md.named.push({ line, refs: mdRefs(named[2]!) });
    } else if (!sawDefinition || line.trim() !== "") preamble.push(line);
  }
  if (functions.length < 2) return null;
  const chunks = chunksOf(functions, targetBytes);
  if (chunks.length < 2) return null;
  // A shard declares only the symbols it references, so adding or removing an
  // unrelated function does not change it.
  const used = (symbols: Set<string>[]) => new Set(symbols.flatMap((set) => [...set]));
  const preambleRefs = preamble.flatMap(mdRefs);
  const shardSource = (head: string[], body: string[], bodyRefs: number[][], withGlobals: boolean): string | null => {
    const t = shardTail(md, [preambleRefs, ...bodyRefs], withGlobals);
    if (t === null) return null;
    return [mdRewrite(head.join("\n"), t.ids), ...body.map((b) => mdRewrite(b, t.ids)), t.tail].join("\n");
  };
  const functionShards: LlvmProgramShard[] = [];
  for (const { bucket, functions: chunk } of chunks) {
    const owned = new Set(chunk);
    const refd = used(chunk.map((fn) => fn.symbols));
    const globalDecls = globals.flatMap((g) => g.declaration !== null && refd.has(g.symbol) ? [g.declaration] : []);
    const declarations = functions
      .filter((fn) => !owned.has(fn) && refd.has(fn.symbol))
      .map((fn) => fn.declaration);
    const text = shardSource([...preamble, ...globalDecls, ...declarations, ""], chunk.map((fn) => fn.source), chunk.map((fn) => fn.refs), false);
    if (text === null) return null;
    functionShards.push({ name: `program-f${bucket.toString().padStart(3, "0")}.ll`, source: text });
  }
  // Global initializer changes are common (literal text, generated tables)
  // and should not invalidate an otherwise unrelated function bucket. Keep
  // all module storage in one dedicated shard that declares every function.
  const globalRefd = used(globals.map((g) => g.symbols));
  const globalText = shardSource(
    [...preamble, ...functions.filter((fn) => globalRefd.has(fn.symbol)).map((fn) => fn.declaration), ""],
    globals.map((global) => global.line),
    globals.map((global) => global.refs),
    true,
  );
  if (globalText === null) return null;
  const globalShard: LlvmProgramShard = { name: "program-globals.ll", source: globalText };
  const shards = [globalShard, ...functionShards];
  return {
    shards,
    promotedSymbols: [
      ...globals.filter((global) => global.promoted).map((global) => global.symbol),
      ...functions.filter((fn) => fn.promoted).map((fn) => fn.symbol),
    ],
    publicSymbols: [
      ...globals.filter((global) => !global.promoted).map((global) => global.symbol),
      ...functions.filter((fn) => !fn.promoted).map((fn) => fn.symbol),
    ],
  };
}

/** Dev-library policy tuned independently from executable splitting. */
export function splitLlvmLibraryProgram(source: string): LlvmProgramSplit | null {
  return splitLlvmProgram(source, {
    minimumBytes: LIBRARY_MINIMUM_BYTES,
    targetBytes: LIBRARY_TARGET_BYTES,
  });
}
