import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { compile, deserializeModule } from "../../index.js";
import { emitLlvmModule } from "./emitter.js";
import { parseThrowCall, throwStubDefs } from "./throw-stubs.js";

async function moduleFor(source: string) {
  const dir = await mkdtemp(join(tmpdir(), "scriptc-throw-stubs-"));
  try {
    const entry = join(dir, "main.ts"),
      output = join(dir, "main.ir.json");
    await writeFile(entry, source);
    const result = await compile(entry, { outDir: dir, outPath: output, outputKind: "ir" });
    if (!result.ok)
      throw new Error(result.diagnostics.map((item) => `${item.code}: ${item.message}`).join("\n"));
    return deserializeModule(await readFile(output, "utf8"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** The definition of the source function `name`. */
function body(ir: string, name: string): string {
  return new RegExp(
    `^define internal [^\\n]*@sc_b?f_[^\\n(]*${name}(?:\\.i32)?\\([^]*?^}`,
    "m",
  ).exec(ir)![0];
}

test("parses the runtime throw calls a stub can forward", () => {
  expect(
    parseThrowCall(
      "  call void @scr_throw_node_coded(double 0x3FF0000000000000, ptr @sc_lit_1, ptr %t4) nounwind, !dbg !12 ; comment",
    ),
  ).toEqual({
    callee: "scr_throw_node_coded",
    args: [
      { type: "double", value: "0x3FF0000000000000" },
      { type: "ptr", value: "@sc_lit_1" },
      { type: "ptr", value: "%t4" },
    ],
    nounwind: true,
  });
  expect(parseThrowCall("  call void @scr_rethrow(ptr %t2)")).toEqual({
    callee: "scr_rethrow",
    args: [{ type: "ptr", value: "%t2" }],
    nounwind: false,
  });
  // Other calls, constant expressions, attributes and more than six
  // arguments stay as they are.
  expect(parseThrowCall("  call void @scr_str_release(ptr %t1)")).toBeNull();
  expect(parseThrowCall("  %t3 = call ptr @scr_throw_str(ptr %t1)")).toBeNull();
  expect(
    parseThrowCall("  call void @scr_throw_str(ptr getelementptr (i8, ptr @g, i64 8))"),
  ).toBeNull();
  expect(parseThrowCall("  call void @scr_throw_str(ptr noundef %t1)")).toBeNull();
  expect(
    parseThrowCall(
      "  call void @scr_throw_ref(ptr %a, ptr %b, ptr %c, ptr %d, ptr %e, ptr %f, ptr %g)",
    ),
  ).toBeNull();
});

test("a stub makes the throw call and leaves as its caller did", () => {
  const defs = throwStubDefs(
    new Map([
      [
        "sc_throw_tail.scr_throw_str.p.d",
        {
          callee: "scr_throw_str",
          types: ["ptr"],
          nounwind: false,
          ret: "double",
          terminator: "ret double 0x0000000000000000",
        },
      ],
      [
        "sc_throw_tail.scr_throw_str.p.raise",
        {
          callee: "scr_throw_str",
          types: ["ptr"],
          nounwind: true,
          ret: "ptr",
          terminator: "call void @scr_unwind_raise()\n  unreachable",
        },
      ],
    ]),
    "#0",
  ).join("\n");
  expect(defs).toContain(
    [
      "define internal double @sc_throw_tail.scr_throw_str.p.d(ptr %a0) cold noinline #0 {",
      "entry:",
      "  call void @scr_throw_str(ptr %a0)",
      "  ret double 0x0000000000000000",
      "}",
    ].join("\n"),
  );
  expect(defs).toContain(
    [
      "define internal ptr @sc_throw_tail.scr_throw_str.p.raise(ptr %a0) cold noinline #0 {",
      "entry:",
      "  call void @scr_throw_str(ptr %a0) nounwind",
      "  call void @scr_unwind_raise()",
      "  unreachable",
      "}",
    ].join("\n"),
  );
});

const SOURCE = `
interface Item { kind: number; next: Item | undefined }
function check(n: number): number {
  if (n < 0) throw "negative";
  return n / 3;
}
function guarded(n: number): number {
  try {
    if (n > 10) throw new RangeError("large");
    return n;
  } catch (e) {
    return -1;
  }
}
function nextKind(item: Item): number {
  return item.next!.kind + 1;
}
function twice(item: Item): number {
  return nextKind(item) * 2;
}
const a: Item = { kind: 1, next: undefined };
const b: Item = { kind: 2, next: a };
for (let i = -1; i < 2; i++) {
  try { console.log(check(i), guarded(i * 20)); } catch (e) { console.log((e as Error).message); }
}
try { console.log(twice(b), twice(a)); } catch (e) { console.log((e as Error).message); }
`;

const LINUX = { targetTriple: "x86_64-unknown-linux-gnu", unwindAbi: true } as const;

test("throw paths that leave the function tail-call a cold stub", async () => {
  const ir = emitLlvmModule(await moduleFor(SOURCE), LINUX);
  // check returns its dummy after the throw: one tail call, then ret.
  const check = body(ir, "check");
  expect(check).toMatch(
    /%(t\d+) = tail call double @sc_throw_tail\.scr_throw_str\.p\.d\([^\n]*\n\s+ret double %\1/,
  );
  expect(check).not.toMatch(/^\s+call void @scr_throw_str\(/m);
  expect(ir).toContain(
    "define internal double @sc_throw_tail.scr_throw_str.p.d(ptr %a0) cold noinline",
  );
  // A throw inside try goes to the handler.
  const guarded = body(ir, "guarded");
  expect(guarded).toMatch(
    /\n\s+call void @scr_throw_obj\([^\n]*\n(?:\s+call [^\n]*\n)*\s+br label %try\./,
  );
  expect(guarded).not.toContain("@sc_throw_tail.scr_throw_obj");
  // A raising function's throw path tail-calls a stub that raises; the
  // call is not marked nounwind, and the function stays on the unwinding ABI.
  const nextKind = body(ir, "nextKind");
  expect(nextKind).toMatch(
    /= tail call double @sc_throw_tail\.scr_throw_node_coded\.dpp\.raise\([^\n]*\)\n/,
  );
  expect(nextKind).not.toMatch(/@sc_throw_tail\.[^\n]*\.raise\([^\n]*\) nounwind/);
  expect(body(ir, "twice")).toMatch(/invoke double @sc_b?f_[^(]*nextKind/);
  expect(ir).toMatch(
    /define internal double @sc_throw_tail\.scr_throw_node_coded\.dpp\.raise\(double %a0, ptr %a1, ptr %a2\) cold noinline[^\n]*\{\nentry:\n\s+call void @scr_throw_node_coded\(double %a0, ptr %a1, ptr %a2\)[^\n]*\n\s+call void @scr_unwind_raise\(\)\n\s+unreachable/,
  );
});
