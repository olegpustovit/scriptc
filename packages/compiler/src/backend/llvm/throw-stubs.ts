/* Cold throw stubs for tail-called throw paths (LlEmitter.tailThrow).
 *
 * A throw path that leaves the function right after the runtime throw call
 * (one of the scr_throw_* functions, then `ret <dummy>` or the unwinding
 * raise) becomes `tail call @stub(…)` + `ret`: the stub makes the same call
 * and ends with the same terminator. The site compiles to a jump, so the path
 * needs no stack frame of its own. */

/** One stub: the runtime throw it calls, its parameter types, and how it
 * leaves (the caller's return type and terminator). */
export interface ThrowStub {
  readonly callee: string;
  readonly types: readonly string[];
  readonly nounwind: boolean;
  readonly ret: string;
  readonly terminator: string;
}

/** Parameter types a stub forwards. A tail call keeps every argument in a
 * register for at most six integer and eight floating-point arguments
 * (x86-64 System V; AArch64 has more), so a stub takes at most six. */
const STUB_TYPES = new Set(["ptr", "double", "i64", "i32", "i1"]);
const STUB_MAX_ARGS = 6;

/** Splits an argument list at its top-level commas. */
function splitArgs(text: string): string[] | null {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '"') quoted = !quoted;
    if (quoted) continue;
    if (c === "(" || c === "[" || c === "{" || c === "<") depth++;
    else if (c === ")" || c === "]" || c === "}" || c === ">") depth--;
    else if (c === "," && depth === 0) {
      out.push(text.slice(start, i).trim());
      start = i + 1;
    }
    if (depth < 0) return null;
  }
  if (depth !== 0 || quoted) return null;
  const last = text.slice(start).trim();
  if (last !== "") out.push(last);
  return out;
}

/** The runtime throw call on an emitted line (a call of a scr_throw_* function,
 * optionally `nounwind`, a debug attachment and a comment), or null when the
 * line is something else or its arguments are not plain typed values. */
export function parseThrowCall(
  line: string,
): { callee: string; args: { type: string; value: string }[]; nounwind: boolean } | null {
  const head = /^ {2}call void @(scr_throw_\w+|scr_rethrow)\(/.exec(line);
  if (head === null) return null;
  const open = head[0].length - 1;
  let depth = 0;
  let close = -1;
  for (let i = open; i < line.length; i++) {
    const c = line.charAt(i);
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) {
      close = i;
      break;
    }
  }
  if (close < 0) return null;
  const rest = line.slice(close + 1);
  const tail = /^( nounwind)?(, !dbg !\d+)?( ;.*)?$/.exec(rest);
  if (tail === null) return null;
  const parts = splitArgs(line.slice(open + 1, close));
  if (parts === null || parts.length > STUB_MAX_ARGS) return null;
  const args: { type: string; value: string }[] = [];
  for (const part of parts) {
    const space = part.indexOf(" ");
    if (space < 0) return null;
    const type = part.slice(0, space);
    const value = part.slice(space + 1).trim();
    if (!STUB_TYPES.has(type) || value === "" || value.includes(" ")) return null;
    args.push({ type, value });
  }
  return { callee: head[1]!, args, nounwind: tail[1] !== undefined };
}

/** A short code for a type in a stub's symbol. */
export function throwStubTypeCode(type: string): string {
  switch (type) {
    case "ptr":
      return "p";
    case "double":
      return "d";
    case "i64":
      return "l";
    case "i32":
      return "i";
    case "i1":
      return "b";
    case "void":
      return "v";
    default:
      return "u";
  }
}

/** The definitions of the requested stubs, in symbol order. */
export function throwStubDefs(stubs: ReadonlyMap<string, ThrowStub>, fnAttrs: string): string[] {
  const out: string[] = [];
  for (const name of [...stubs.keys()].sort()) {
    const stub = stubs.get(name)!;
    const params = stub.types.map((type, i) => `${type} %a${i}`).join(", ");
    out.push(
      `define internal ${stub.ret} @${name}(${params}) cold noinline ${fnAttrs} {`,
      `entry:`,
      `  call void @${stub.callee}(${params})${stub.nounwind ? " nounwind" : ""}`,
      ...stub.terminator.split("\n").map((line) => `  ${line.trim()}`),
      `}`,
      ``,
    );
  }
  return out;
}
