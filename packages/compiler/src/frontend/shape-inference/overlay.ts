/* Shape inference: the typed overlay (results/design-shape-inference,
 * maintainer decision 2026-10-23). The analysis's proven facts become JSDoc
 * types in a rewritten copy of each package JavaScript file, and the
 * lowering treats the rewritten file like a checked JavaScript file, so the
 * static tier compiles the package's hot code from those types.
 *
 * Only proven facts are written: a position whose value set contains ⊤
 * (anything from islands, JSON.parse, the network or the file system,
 * reflection, globals, `process`, caught exceptions, or code the analysis
 * cannot see) stays untyped. A check the lowering inserts where a value
 * meets an inferred type therefore fails only when the analysis is wrong;
 * such checks carry the inferred-fact failure message.
 *
 * The package's own JSDoc is a declaration (maintainer decision
 * 2026-10-25): it stays as written, and the overlay adds a type only where
 * the package's JSDoc declares none (a documented parameter, return or
 * binding keeps its documented type, as in the default build).
 *
 * Every edit is inline: no line breaks are added or removed, so positions
 * keep their lines. */
import * as ts from "../ts7/adapter.js";
import type { Atom } from "./domain.js";
import type { ShapeAnalysis } from "./analyze.js";
import type { SiteVerdict } from "./report.js";

export interface ShapeOverlay {
  /** Rewritten text per package file. */
  readonly files: Map<string, string>;
  /** Annotations written, for the build report. */
  readonly annotations: number;
  /** Branches the analysis proved unreachable, replaced by checks. */
  readonly deadBranches: number;
  /** The files with annotations or dead-branch checks. */
  readonly typed: ReadonlySet<string>;
}

interface Edit {
  readonly pos: number;
  readonly text: string;
  /** Replaces pos..end instead of inserting at pos. */
  readonly end?: number;
  /** The annotation (or dead branch) the edit belongs to. */
  readonly id?: number;
}

/** The overlay before annotation exclusions apply: per file, its text,
 * edits and appended typedefs. It depends only on the analysis, so a build
 * that drops refused annotations renders it again instead of analyzing
 * again (renderShapeOverlay). */
export interface ShapeOverlayPlan {
  readonly parts: Map<string, OverlayPart>;
}

interface OverlayPart {
  readonly text: string;
  readonly edits: Edit[];
  readonly suffix: string;
}

/** Marks the overlay's own comments (an unknown JSDoc tag, ignored). */
export const OVERLAY_MARK = "@scriptcShape";
const MARK = OVERLAY_MARK;

/** Above 1, values of several record key sets type as one merged record
 * with optional fields (SCRIPTC_SHAPE_RECORD_ARMS; experimental). */
const MAX_RECORD_ARMS = Number(process.env.SCRIPTC_SHAPE_RECORD_ARMS ?? 1);

/** The most class or record arms an inferred union may have. */
const MAX_ARMS = 6;

function list<T extends ts.Node>(arr: { readonly nodes: readonly T[] } | undefined): readonly T[] {
  return arr?.nodes ?? [];
}

let debugIndex = 0;

/** Annotations a build dropped because their lowering was refused: per
 * file, the annotation ids (positions in the overlay's input text); a file
 * in `files` gets no overlay at all. */
export interface OverlayExclusions {
  readonly annotations: ReadonlyMap<string, ReadonlySet<number>>;
  readonly files: ReadonlySet<string>;
}

export const NO_EXCLUSIONS: OverlayExclusions = { annotations: new Map(), files: new Set() };

/** The ids of the overlay annotations in a comment or trivia text. */
export function overlayAnnotationIds(text: string): number[] {
  const ids: number[] = [];
  for (const m of text.matchAll(/@scriptcShape #(\d+)/g)) ids.push(Number(m[1]));
  return ids;
}

export function planShapeOverlay(
  analysis: ShapeAnalysis,
  verdicts: readonly SiteVerdict[],
  packageFiles: readonly ts.SourceFile[],
  exclusions: OverlayExclusions = NO_EXCLUSIONS,
): ShapeOverlayPlan {
  // Debugging: SCRIPTC_DEBUG_SHAPE_FIELD=name prints that field's values per atom.
  const debugField = process.env["SCRIPTC_DEBUG_SHAPE_FIELD"];
  if (debugField !== undefined)
    for (const [atom, fields] of analysis.fields) {
      const id = fields.get(debugField);
      if (id !== undefined)
        process.stderr.write(
          `[shape-field] ${atom.kind}:${atom.label}.${debugField} = ${[...analysis.nodes[id]!.atoms].map((a) => `${a.kind}:${a.label}`).join(" | ")}\n`,
        );
    }
  const pSites = new Map<Atom, SiteVerdict>();
  const siteVerdicts = new Set<Atom>(verdicts.map((v) => v.site.atom));
  const dynHeld = dynHeldSites(analysis, verdicts);
  // Records and arrays print only for sites whose objects never escape: a
  // native record that reached untyped code would be seen as a copy.
  const siteKeys = new Map<Atom, { keys: string[]; optional: Set<string> }>();
  for (const v of verdicts) {
    if (v.verdict !== "P-local" || dynHeld.has(v.site.atom)) continue;
    if (v.site.kind === "array") {
      pSites.set(v.site.atom, v);
      continue;
    }
    const keys = keysOfSite(analysis, v);
    if (keys === null) continue;
    siteKeys.set(v.site.atom, keys);
    pSites.set(v.site.atom, v);
  }
  const parts = new Map<string, OverlayPart>();
  const overlaid = new Set<ts.SourceFile>(packageFiles);
  const exportedClasses = new Map<ts.SourceFile, Set<string>>();
  debugIndex = 0;
  // `if` branches no condition value allowed, per file: the overlay
  // replaces each with a throwing check, so the checker and the lowering
  // see the code the analysis saw.
  const deadByFile = new Map<ts.SourceFile, ts.Statement[]>();
  if (process.env["SCRIPTC_SHAPE_DEAD_BRANCHES"] !== "0")
    for (const s of analysis.branchIfs) {
      for (const branch of [s.thenStatement, s.elseStatement]) {
        if (branch === undefined || analysis.walkedBranches.has(branch)) continue;
        const sf = s.getSourceFile();
        let list = deadByFile.get(sf);
        if (list === undefined) deadByFile.set(sf, (list = []));
        list.push(branch);
      }
    }
  for (const sf of packageFiles) {
    if (exclusions.files.has(sf.fileName)) continue;
    const typedefs = new Map<string, string>();
    const typedefText: string[] = [];
    const edits: Edit[] = [];
    // One annotation: a JSDoc comment at `pos` carrying MARK and the
    // annotation's id (its position), so a refused lowering can name it and
    // the next load drop it. `close`: the text that closes a type cast.
    const annotate = (pos: number, tags: string, close?: number): void => {
      edits.push({
        pos,
        id: pos,
        text: `/** ${tags} ${MARK} #${pos} */ ${close !== undefined ? "(" : ""}`,
      });
      if (close !== undefined) edits.push({ pos: close, id: pos, text: ")" });
    };

    const className = (decl: ts.Node): string | null => {
      const own = (decl as ts.ClassLikeDeclaration).name;
      // A top-level class of another overlaid file: named through the type
      // alias the overlay exports from that file.
      if (decl.getSourceFile() !== sf) {
        const other = decl.getSourceFile();
        if (
          process.env["SCRIPTC_SHAPE_CROSS_FILE"] === "0" ||
          own === undefined ||
          !ts.isClassDeclaration(decl) ||
          decl.parent !== other ||
          !overlaid.has(other) ||
          exclusions.files.has(other.fileName)
        )
          return null;
        const alias = `__shape_class_${own.text}`;
        let names = exportedClasses.get(other);
        if (names === undefined) exportedClasses.set(other, (names = new Set()));
        names.add(own.text);
        return `import(${JSON.stringify(other.fileName)}).${alias}`;
      }
      if (own !== undefined && ts.isClassDeclaration(decl) && decl.parent === sf) return own.text;
      const p = decl.parent;
      if (
        p !== undefined &&
        ts.isVariableDeclaration(p) &&
        ts.isIdentifier(p.name) &&
        p.parent?.parent?.parent === sf
      )
        return p.name.text;
      return null;
    };

    // `inner`: inside a record field, where ⊤ and unprintable values are `any`.
    const typeOf = (atoms: ReadonlySet<Atom>, inner: boolean, depth: number): string | null => {
      if (atoms.size === 0) return inner ? "any" : null;
      const arms = new Set<string>();
      // Every array arm becomes one Array<…> of the joined element values.
      const elements = new Set<Atom>();
      let hasArray = false;
      const promised = new Set<Atom>();
      let hasPromise = false;
      const recordSites: Atom[] = [];
      for (const a of atoms) {
        let t: string | null = null;
        switch (a.kind) {
          case "prim":
            t =
              a.label === "null" ||
              a.label === "undefined" ||
              a.label === "string" ||
              a.label === "number" ||
              a.label === "boolean" ||
              a.label === "bigint"
                ? a.label
                : null;
            break;
          case "instance":
            t = a.node !== undefined ? className(a.node) : null;
            break;
          case "object": {
            const v = pSites.get(a);
            if (v === undefined || depth >= 4 || !siteKeys.has(a)) return inner ? "any" : null;
            recordSites.push(a);
            continue;
          }
          case "array": {
            if (analysis.escaped.has(a) || (siteVerdicts.has(a) && !pSites.has(a)))
              return inner ? "any" : null;
            // Only arrays the program writes as literals: a builtin's array
            // (a match result, `new Array(n)`) may have holes, and the
            // checker already types it from the library.
            if (
              a.node === undefined ||
              !ts.isArrayLiteralExpression(a.node) ||
              a.node.elements.nodes.some((e) => e.kind === ts.SyntaxKind.OmittedExpression)
            )
              return inner ? "any" : null;
            const el = analysis.elements.get(a);
            if (el !== undefined) for (const x of analysis.nodes[el]!.atoms) elements.add(x);
            hasArray = true;
            continue;
          }
          case "promise": {
            // One promise arm: the values it resolves to, joined.
            const value = analysis.fields.get(a)?.get("value");
            if (value !== undefined) for (const x of analysis.nodes[value]!.atoms) promised.add(x);
            hasPromise = true;
            continue;
          }
          default:
            t = null;
        }
        if (t === null) return inner ? "any" : null;
        arms.add(t);
      }
      // Records of one key set print as their typedef; records of several
      // key sets merge into one record whose fields missing from some sites
      // are optional (unions of overlapping records would need the lowering
      // to pick an arm per value).
      if (recordSites.length > 0) {
        const keySets = new Set(recordSites.map(keySetOf));
        if (keySets.size === 1) arms.add(recordType(recordSites[0]!, depth));
        else if (MAX_RECORD_ARMS > 1) arms.add(mergedRecordType(recordSites, depth));
        else return inner ? "any" : null;
      }
      if (hasArray) {
        const inside = depth < 4 ? typeOf(elements, true, depth + 1) : "any";
        arms.add(`Array<${inside ?? "any"}>`);
      }
      // A promise beside other values cannot cross into untyped code
      // (maybe-promise unions stay typed-only), so it stays untyped here.
      if (hasPromise) return inner ? "any" : null;
      // Arms, not atoms: per-site allocations of one record shape are one
      // typedef.
      if (arms.size > MAX_ARMS) return inner ? "any" : null;
      // Arithmetic on unknown values may answer a number or a bigint: the
      // lowering has no useful mixed representation, so those stay untyped.
      if (arms.has("number") && arms.has("bigint")) return inner ? "any" : null;
      if (arms.has("any")) return inner ? "any" : null;
      return [...arms].join(" | ");
    };

    // One typedef per key set: sites with the same keys intern to the same
    // structural record, so their field types are joined.
    const keySetOf = (site: Atom): string => {
      const k = siteKeys.get(site)!;
      return k.keys
        .map((key) => (k.optional.has(key) ? `${key}?` : key))
        .sort()
        .join(",");
    };
    const sitesByKeys = new Map<string, Atom[]>();
    for (const site of pSites.keys()) {
      if (pSites.get(site)!.site.kind !== "object") continue;
      const k = keySetOf(site);
      let l = sitesByKeys.get(k);
      if (l === undefined) sitesByKeys.set(k, (l = []));
      l.push(site);
    }
    const recordType = (site: Atom, depth: number): string => {
      const keySet = keySetOf(site);
      const existing = typedefs.get(keySet);
      if (existing !== undefined) return existing;
      const name = `__shape_${typedefs.size}`;
      typedefs.set(keySet, name);
      const { keys, optional } = siteKeys.get(site)!;
      const parts = keys.map((k) => {
        const atoms = new Set<Atom>();
        for (const other of sitesByKeys.get(keySet) ?? [site]) {
          const id = analysis.fields.get(other)?.get(k);
          if (id !== undefined) for (const a of analysis.nodes[id]!.atoms) atoms.add(a);
        }
        const t = typeOf(atoms, true, depth + 1);
        return `${/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k)}${optional.has(k) ? "?" : ""}: ${t ?? "any"}`;
      });
      typedefText.push(`/** @typedef {{${parts.join(", ")}}} ${name} ${MARK} */`);
      return name;
    };

    const mergedRecordType = (sites: readonly Atom[], depth: number): string => {
      const all = new Set<Atom>();
      for (const site of sites)
        for (const other of sitesByKeys.get(keySetOf(site)) ?? [site]) all.add(other);
      const keys: string[] = [];
      const optional = new Set<string>();
      for (const site of all) {
        const k = siteKeys.get(site)!;
        for (const key of k.keys) {
          if (!keys.includes(key)) keys.push(key);
          if (k.optional.has(key)) optional.add(key);
        }
      }
      for (const site of all) {
        const own = siteKeys.get(site)!.keys;
        for (const key of keys) if (!own.includes(key)) optional.add(key);
      }
      const keySet = `merged:${keys
        .map((k) => (optional.has(k) ? `${k}?` : k))
        .sort()
        .join(",")}`;
      const existing = typedefs.get(keySet);
      if (existing !== undefined) return existing;
      const name = `__shape_${typedefs.size}`;
      typedefs.set(keySet, name);
      const parts = keys.map((k) => {
        const atoms = new Set<Atom>();
        for (const site of all) {
          const id = analysis.fields.get(site)?.get(k);
          if (id !== undefined) for (const a of analysis.nodes[id]!.atoms) atoms.add(a);
        }
        const t = typeOf(atoms, true, depth + 1);
        return `${/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k)}${optional.has(k) ? "?" : ""}: ${t ?? "any"}`;
      });
      typedefText.push(`/** @typedef {{${parts.join(", ")}}} ${name} ${MARK} */`);
      return name;
    };

    // Return values merged over every analysis context of each function.
    const returns = new Map<ts.Node, Set<Atom>>();
    for (const info of analysis.functions.values()) {
      if (info.node.getSourceFile() !== sf || info.isAsync || info.isGenerator) continue;
      let set = returns.get(info.node);
      if (set === undefined) returns.set(info.node, (set = new Set()));
      for (const a of analysis.nodes[info.ret]!.atoms) set.add(a);
    }

    // Receivers each method runs on, merged over its analysis contexts.
    const thisAtoms = new Map<ts.Node, Set<Atom>>();
    for (const info of analysis.functions.values()) {
      if (info.node.getSourceFile() !== sf || !ts.isMethodDeclaration(info.node)) continue;
      let set = thisAtoms.get(info.node);
      if (set === undefined) thisAtoms.set(info.node, (set = new Set()));
      for (const a of analysis.nodes[info.thisNode]!.atoms) set.add(a);
    }
    const declaresMember = (cls: ts.Node, name: string): boolean =>
      analysis.classChain(cls).some((c) =>
        (c as ts.ClassLikeDeclaration).members.nodes.some((m) => {
          const n = (m as { name?: ts.Node }).name;
          return (
            n !== undefined && (ts.isIdentifier(n) || ts.isPrivateIdentifier(n)) && n.text === name
          );
        }),
      );
    // `this.m(…)` in an inherited method whose class does not declare `m`
    // (zod's ZodType._parseSync calls the subclasses' _parse): the receiver
    // is cast to the classes the method runs on, so the call dispatches over
    // them instead of through an untyped call.
    const receiverCasts = (method: ts.MethodDeclaration): void => {
      const cls = method.parent;
      const receivers = thisAtoms.get(method);
      if (cls === undefined || receivers === undefined || receivers.size === 0) return;
      if (![...receivers].every((a) => a.kind === "instance")) return;
      const t = typeOf(receivers, false, 0);
      if (t === null) return;
      const scan = (node: ts.Node): void => {
        if (ts.isFunctionLike(node) && !ts.isArrowFunction(node)) return;
        if (
          ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.expression.kind === ts.SyntaxKind.ThisKeyword &&
          ts.isIdentifier(node.expression.name) &&
          !declaresMember(cls, node.expression.name.text)
        ) {
          const self = node.expression.expression;
          annotate(ts.tokenStartOfNode(self), `@type {${t}}`, self.end);
        }
        ts.forEachChild(node, (c) => {
          scan(c);
          return undefined;
        });
      };
      if (method.body !== undefined) for (const st of method.body.statements.nodes) scan(st);
    };

    // Same-named instance methods of the file's classes form a family: a
    // call on a union of those classes needs one signature, so each member's
    // parameters and result join the whole family's values.
    const families = new Map<string, ts.MethodDeclaration[]>();
    const familyVisit = (node: ts.Node): void => {
      if (
        ts.isMethodDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        !list((node as { modifiers?: { nodes: readonly ts.Node[] } }).modifiers).some(
          (m) => m.kind === ts.SyntaxKind.StaticKeyword,
        )
      ) {
        let l = families.get(node.name.text);
        if (l === undefined) families.set(node.name.text, (l = []));
        l.push(node);
      }
      ts.forEachChild(node, (c) => {
        familyVisit(c);
        return undefined;
      });
    };
    familyVisit(sf);
    // Members the program runs (they have analysis contexts); members it
    // never reaches would only widen the family's types.
    const reached = new Set<ts.Node>();
    for (const info of analysis.functions.values())
      if (info.node.getSourceFile() === sf) reached.add(info.node);
    const familyOf = (fn: ts.FunctionLikeDeclaration): readonly ts.MethodDeclaration[] => {
      if (!ts.isMethodDeclaration(fn) || !ts.isIdentifier(fn.name))
        return [fn as ts.MethodDeclaration];
      const members = (families.get(fn.name.text) ?? [fn]).filter((m) => reached.has(m));
      return members.length > 0 ? members : [fn];
    };
    const paramValues = (fn: ts.FunctionLikeDeclaration, index: number): Set<Atom> => {
      const out = new Set<Atom>();
      for (const member of familyOf(fn)) {
        const p = list(member.parameters)[index];
        if (p === undefined) continue;
        for (const a of analysis.declValues(p)) out.add(a);
      }
      return out;
    };
    const returnValues = (fn: ts.FunctionLikeDeclaration): Set<Atom> | undefined => {
      let out: Set<Atom> | undefined;
      for (const member of familyOf(fn)) {
        const r = returns.get(member);
        if (r === undefined) continue;
        out ??= new Set();
        for (const a of r) out.add(a);
      }
      return out;
    };

    const paramTags = (fn: ts.FunctionLikeDeclaration): string | null => {
      const tags: string[] = [];
      // The package's JSDoc declares types: the overlay adds none where it
      // has one, and none at all for a signature it types as a whole.
      const doc = packageDocOf(fn);
      if (doc.whole) return null;
      if (!ts.isConstructorDeclaration(fn) && !doc.returns) {
        const ret = returnValues(fn);
        const t = ret !== undefined && ret.size > 0 ? typeOf(ret, false, 0) : null;
        const why = process.env["SCRIPTC_DEBUG_SHAPE_OVERLAY_WHY"];
        if (
          why !== undefined &&
          t === null &&
          ret !== undefined &&
          ts.isMethodDeclaration(fn) &&
          ts.isIdentifier(fn.name) &&
          fn.name.text === why
        )
          process.stderr.write(
            `[shape-overlay-why] ${fn.name.text}: ${[...ret].map((a) => `${a.kind}:${a.label}${analysis.escaped.has(a) ? "(escaped)" : ""}`).join(" | ")}\n`,
          );
        if (t !== null) tags.push(`@returns {${t}}`);
      }
      list(fn.parameters).forEach((p, index) => {
        if (
          !ts.isIdentifier(p.name) ||
          p.dotDotDotToken !== undefined ||
          p.initializer !== undefined ||
          p.questionToken !== undefined
        )
          return;
        const values = paramValues(fn, index);
        const t = typeOf(values, false, 0);
        // A `typeof p === "…"` test the proven values never pass would
        // narrow the typed parameter to never inside the branch, which the
        // lowering refuses: such a parameter stays untyped.
        if (t !== null && typeofTestsOutside(fn, p.name.text, values)) return;
        if (doc.params.has(p.name.text)) return;
        if (t !== null) tags.push(`@param {${t}} ${p.name.text}`);
      });
      return tags.length > 0 ? tags.join(" ") : null;
    };

    const visit = (node: ts.Node): void => {
      if (ts.isMethodDeclaration(node)) receiverCasts(node);
      if (
        ts.isMethodDeclaration(node) ||
        ts.isConstructorDeclaration(node) ||
        ts.isFunctionDeclaration(node) ||
        // Functions stored as object members (`run: function (…) {…}`).
        (process.env["SCRIPTC_SHAPE_MEMBER_FUNCTIONS"] !== "0" &&
          ts.isFunctionExpression(node) &&
          node.parent !== undefined &&
          ts.isPropertyAssignment(node.parent) &&
          node.parent.initializer === node)
      ) {
        if (node.body !== undefined) {
          const tags = paramTags(node);
          if (tags !== null) annotate(ts.tokenStartOfNode(node), tags);
        }
        // `this.f = …` fields of a constructor's top-level statements.
        if (ts.isConstructorDeclaration(node) && node.body !== undefined) {
          const cls = node.parent;
          const seen = new Set<string>();
          for (const st of list(node.body.statements)) {
            if (!ts.isExpressionStatement(st) || !ts.isBinaryExpression(st.expression)) continue;
            const b = st.expression;
            if (
              b.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
              !ts.isPropertyAccessExpression(b.left)
            )
              continue;
            if (
              b.left.expression.kind !== ts.SyntaxKind.ThisKeyword ||
              !ts.isIdentifier(b.left.name)
            )
              continue;
            const name = b.left.name.text;
            if (seen.has(name)) continue;
            seen.add(name);
            const t = cls !== undefined ? fieldType(cls, name) : null;
            if (t !== null && !packageDocOf(st).type)
              annotate(ts.tokenStartOfNode(st), `@type {${t}}`);
          }
        }
      }
      // Locals only: module-level bindings are initialized once (and a
      // record-typed module constant can turn a return type into a union of
      // overlapping records, which the lowering width-coerces).
      if (
        ts.isVariableStatement(node) &&
        (node.parent !== sf || process.env["SCRIPTC_SHAPE_OVERLAY_MODULE_VARS"] === "1") &&
        node.declarationList.declarations.nodes.length === 1
      ) {
        const d = node.declarationList.declarations.nodes[0]!;
        const init = d.initializer;
        if (ts.isIdentifier(d.name) && init !== undefined && !literalInitializer(init)) {
          const t = typeOf(analysis.declValues(d), false, 0);
          if (process.env["SCRIPTC_DEBUG_SHAPE_OVERLAY_WHY"] === d.name.text)
            process.stderr.write(
              `[shape-overlay-why] ${d.name.text}@${sf.getLineAndCharacterOfPosition(ts.tokenStartOfNode(d)).line + 1}: ${t} <- ${[...analysis.declValues(d)].map((a) => `${a.kind}:${a.label}`).join(" | ")}\n`,
            );
          if (t !== null && !packageDocOf(node).type)
            annotate(ts.tokenStartOfNode(node), `@type {${t}}`);
        }
      }
      ts.forEachChild(node, (c) => {
        visit(c);
        return undefined;
      });
    };

    const fieldType = (cls: ts.Node, name: string): string | null => {
      const atoms = new Set<Atom>();
      for (const a of analysis.atoms.atoms) {
        if (
          a.kind !== "instance" ||
          a.node === undefined ||
          !analysis.classChain(a.node).includes(cls)
        )
          continue;
        const id = analysis.fields.get(a)?.get(name);
        if (id !== undefined) for (const x of analysis.nodes[id]!.atoms) atoms.add(x);
      }
      return typeOf(atoms, false, 0);
    };

    visit(sf);
    // Dead branches: outermost first; edits inside a replaced range drop.
    const dead = (deadByFile.get(sf) ?? []).sort((a, b) => a.pos - b.pos);
    const ranges: [number, number][] = [];
    for (const branch of dead) {
      const start = ts.tokenStartOfNode(branch);
      if (ranges.some(([lo, hi]) => start >= lo && start < hi)) continue;
      ranges.push([start, branch.end]);
    }
    if (ranges.length > 0) {
      const kept = edits.filter((e) => !ranges.some(([lo, hi]) => e.pos > lo && e.pos < hi));
      edits.length = 0;
      edits.push(...kept);
      const pkg = packageNameOf(sf.fileName);
      const rel = sf.fileName.split("/node_modules/").pop() ?? sf.fileName;
      for (const [lo, hi] of ranges) {
        const line = sf.getLineAndCharacterOfPosition(lo).line + 1;
        const message =
          `scriptc internal error: shape inference proved the branch at ${rel}:${line} unreachable, but it ran. ` +
          `This is a bug in scriptc's shape analysis, not in the program. Rebuild with --no-shape-overlay, ` +
          `or set "scriptc": {"packages": {"${pkg}": {"shapes": false}}} in package.json.`;
        edits.push({
          pos: lo,
          end: hi,
          id: lo,
          text: `{ /** ${MARK} #${lo} */ throw new Error(${JSON.stringify(message)}); }`,
        });
      }
    }
    // Debugging: SCRIPTC_SHAPE_OVERLAY_ONLY=a-b keeps the annotations
    // numbered a..b (program order across files), to bisect a miscompile.
    const only = process.env["SCRIPTC_SHAPE_OVERLAY_ONLY"];
    if (only !== undefined) {
      const [lo, hi] = only.split("-").map(Number) as [number, number];
      edits.sort((a, b) => a.pos - b.pos);
      const kept = edits.filter(() => {
        const n = debugIndex++;
        return n >= lo && n <= hi;
      });
      edits.length = 0;
      edits.push(...kept);
    }
    if (edits.length === 0 && typedefText.length === 0) continue;
    parts.set(sf.fileName, { text: sf.text, edits, suffix: typedefText.join("") });
  }
  // Type aliases other files name these files' classes through.
  for (const [other, names] of exportedClasses) {
    const aliases = [...names]
      .sort()
      .map((n) => `/** @typedef {${n}} __shape_class_${n} ${MARK} */`)
      .join("");
    const part = parts.get(other.fileName);
    if (part !== undefined)
      parts.set(other.fileName, { ...part, suffix: `${part.suffix}\n${aliases}` });
    else
      parts.set(other.fileName, {
        text: other.text,
        edits: [],
        suffix: `\n${aliases}`,
      });
  }
  return { parts };
}

/** The overlay's files with the annotations a build dropped left out. */
export function renderShapeOverlay(
  plan: ShapeOverlayPlan,
  exclusions: OverlayExclusions = NO_EXCLUSIONS,
): ShapeOverlay {
  const files = new Map<string, string>();
  const typed = new Set<string>();
  let annotations = 0;
  let deadBranches = 0;
  for (const [file, part] of plan.parts) {
    const dropped = exclusions.annotations.get(file);
    const edits = part.edits.filter((e) => e.id === undefined || dropped?.has(e.id) !== true);
    for (const e of edits) {
      if (e.id === undefined || e.text === ")") continue;
      if (e.end !== undefined) deadBranches++;
      else annotations++;
    }
    if (edits.length === 0 && part.suffix === "") continue;
    const text = applyEdits(part.text, edits) + part.suffix;
    files.set(file, text);
    if (edits.some((e) => e.id !== undefined)) typed.add(file);
  }
  return { files, typed, annotations, deadBranches };
}

/** Literal sites whose objects some holder keeps in the lowering's dynamic
 * representation: a module-level binding of a JavaScript file (the overlay
 * does not type those, and the lowering keeps their objects dynamic), and,
 * transitively, the fields and elements of those objects and of every
 * object or array that is not P-local. A typed position that receives such
 * an object converts it to a native record, which is a copy: identity
 * comparisons and writes through either reference would diverge. */
function dynHeldSites(analysis: ShapeAnalysis, verdicts: readonly SiteVerdict[]): Set<Atom> {
  const held = new Set<Atom>();
  const work: Atom[] = [];
  const add = (a: Atom): void => {
    if ((a.kind === "object" || a.kind === "array") && !held.has(a)) {
      held.add(a);
      work.push(a);
    }
  };
  for (const sf of analysis.files) {
    if (!/\.[cm]?jsx?$/.test(sf.fileName)) continue;
    for (const st of sf.statements.nodes) {
      if (!ts.isVariableStatement(st)) continue;
      for (const d of st.declarationList.declarations.nodes)
        for (const a of analysis.declValues(d)) add(a);
    }
  }
  const pLocal = new Set<Atom>();
  for (const v of verdicts) if (v.verdict === "P-local") pLocal.add(v.site.atom);
  for (const a of analysis.atoms.atoms)
    if ((a.kind === "object" || a.kind === "array") && !pLocal.has(a)) work.push(a);
  const seen = new Set<Atom>();
  while (work.length > 0) {
    const a = work.pop()!;
    if (seen.has(a)) continue;
    seen.add(a);
    for (const id of analysis.fields.get(a)?.values() ?? [])
      for (const x of analysis.nodes[id]!.atoms) add(x);
    const el = analysis.elements.get(a);
    if (el !== undefined) for (const x of analysis.nodes[el]!.atoms) add(x);
  }
  return held;
}

interface PackageDoc {
  /** Documented parameter names. */
  readonly params: ReadonlySet<string>;
  readonly returns: boolean;
  readonly type: boolean;
  /** A tag that types the whole declaration (`@type`, `@template`,
   * `@this`, `@overload`, `@callback`). */
  readonly whole: boolean;
}

/** The type tags of the package's own JSDoc for a declaration: in its
 * leading trivia and in that of the statement or property holding it
 * (`/** … *\/ const f = function (…) {}`, `exports.f = function …`). */
function packageDocOf(node: ts.Node): PackageDoc {
  let text = "";
  for (let n: ts.Node | undefined = node; n !== undefined; n = n.parent) {
    const sf = n.getSourceFile();
    for (const m of sf.text.slice(n.pos, ts.tokenStartOfNode(n)).matchAll(/\/\*\*[\s\S]*?\*\//g))
      if (!m[0].includes(MARK)) text += m[0];
    const p: ts.Node | undefined = n.parent;
    if (
      p === undefined ||
      !(
        ts.isVariableDeclaration(p) ||
        ts.isVariableDeclarationList(p) ||
        ts.isVariableStatement(p) ||
        ts.isPropertyAssignment(p) ||
        ts.isParenthesizedExpression(p) ||
        ts.isExpressionStatement(p) ||
        ts.isExportAssignment(p) ||
        (ts.isBinaryExpression(p) &&
          p.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
          p.right === n)
      )
    )
      break;
  }
  const params = new Set<string>();
  for (const m of text.matchAll(/@(?:param|arg|argument)\b/g)) {
    let i = m.index + m[0].length;
    while (i < text.length && /\s/.test(text[i]!)) i++;
    if (text[i] === "{") {
      let depth = 0;
      for (; i < text.length; i++) {
        if (text[i] === "{") depth++;
        else if (text[i] === "}" && --depth === 0) {
          i++;
          break;
        }
      }
    }
    const name = /^\s*\[?\s*([A-Za-z_$][\w$]*)/.exec(text.slice(i));
    if (name !== null) params.add(name[1]!);
  }
  return {
    params,
    returns: /@returns?\b/.test(text),
    type: /@type\b/.test(text),
    whole: /@(?:type|template|this|overload|callback)\b/.test(text),
  };
}

/** The `typeof` results the values can have. */
function typeofResults(values: ReadonlySet<Atom>): Set<string> {
  const out = new Set<string>();
  for (const a of values) {
    if (a.kind === "prim")
      out.add(a.label === "null" ? "object" : a.label === "symbol" ? "symbol" : a.label);
    else if (a.kind === "function" || a.kind === "class") out.add("function");
    else out.add("object");
  }
  return out;
}

/** Whether the function's body compares `typeof name` with a result the
 * values never have. */
function typeofTestsOutside(
  fn: ts.FunctionLikeDeclaration,
  name: string,
  values: ReadonlySet<Atom>,
): boolean {
  const results = typeofResults(values);
  let outside = false;
  const visit = (n: ts.Node): void => {
    if (outside) return;
    if (
      ts.isBinaryExpression(n) &&
      (n.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        n.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken ||
        n.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
        n.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken)
    ) {
      for (const [op, lit] of [
        [n.left, n.right],
        [n.right, n.left],
      ] as const)
        if (
          ts.isTypeOfExpression(op) &&
          ts.isIdentifier(op.expression) &&
          op.expression.text === name &&
          ts.isStringLiteral(lit) &&
          !results.has(lit.text)
        )
          outside = true;
    }
    ts.forEachChild(n, (c) => {
      visit(c);
      return undefined;
    });
  };
  if (fn.body !== undefined) visit(fn.body);
  return outside;
}

function packageNameOf(fileName: string): string {
  const parts = (fileName.split("/node_modules/").pop() ?? "").split("/");
  return parts[0]!.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0]!;
}

function literalInitializer(e: ts.Expression): boolean {
  return (
    ts.isObjectLiteralExpression(e) ||
    (ts.isArrayLiteralExpression(e) && e.elements.nodes.length > 0) ||
    ts.isStringLiteral(e) ||
    ts.isNumericLiteral(e) ||
    ts.isNoSubstitutionTemplateLiteral(e) ||
    ts.isArrowFunction(e) ||
    ts.isFunctionExpression(e) ||
    e.kind === ts.SyntaxKind.TrueKeyword ||
    e.kind === ts.SyntaxKind.FalseKeyword
  );
}

function applyEdits(text: string, edits: readonly Edit[]): string {
  const sorted = [...edits].sort((a, b) => a.pos - b.pos);
  let out = "";
  let at = 0;
  for (const e of sorted) {
    out += text.slice(at, e.pos) + e.text;
    at = e.end ?? e.pos;
  }
  return out + text.slice(at);
}

/** A record site's keys: its static keys, or for a literal with spreads its
 * own keys plus every key a spread source contributes (optional unless
 * every value of that source has it). Null when a computed key or an
 * untracked spread source makes the key set unknown. */
function keysOfSite(
  analysis: ShapeAnalysis,
  v: SiteVerdict,
): { keys: string[]; optional: Set<string> } | null {
  const site = v.site;
  if (site.keys !== null) return { keys: site.keys, optional: new Set() };
  if (site.hasComputedKey) return null;
  const fields = analysis.fields.get(site.atom);
  const any = fields?.get("*");
  if (any !== undefined && analysis.nodes[any]!.atoms.size > 0) return null;
  const required = new Set(site.ownKeys);
  for (const spread of site.spreads) {
    const sets: Set<string>[] = [];
    for (const a of analysis.nodes[spread]!.atoms) {
      if (a.kind === "prim" && (a.label === "undefined" || a.label === "null")) continue;
      if (a.kind !== "object") return null;
      const own = new Set<string>();
      for (const k of analysis.fields.get(a)?.keys() ?? []) if (k !== "*") own.add(k);
      sets.push(own);
    }
    const first = sets[0];
    if (first === undefined) continue;
    for (const k of first) if (sets.every((set) => set.has(k))) required.add(k);
  }
  const all = [...site.ownKeys];
  for (const k of fields?.keys() ?? []) if (k !== "*" && !all.includes(k)) all.push(k);
  return { keys: all, optional: new Set(all.filter((k) => !required.has(k))) };
}
