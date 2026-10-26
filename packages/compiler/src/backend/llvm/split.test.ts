import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, test } from "vitest";
import { splitLlvmLibraryProgram, splitLlvmProgram } from "./split.js";
import { LlvmDebugInfo } from "./debug-info.js";
import { VOID } from "../../ir/ir.js";

const scratch: string[] = [];
afterAll(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(scratch.map((path) => rm(path, { recursive: true, force: true })));
});

const SAMPLE = `%Pair = type { i64, i64 }
declare void @runtime(ptr)

@hidden_value = internal global i64 7
@public_value = constant i64 11

define internal i64 @left() #0 {
entry:
  %v = load i64, ptr @hidden_value
  ret i64 %v
}

define internal i64 @right() #0 {
entry:
  %v = call i64 @left()
  ret i64 %v
}

define i64 @public_entry() #0 {
entry:
  %a = call i64 @right()
  %b = load i64, ptr @public_value
  %r = add i64 %a, %b
  ret i64 %r
}

attributes #0 = { sanitize_address }
`;

test("splits generated LLVM functions and promotes only private cross-shard definitions", () => {
  const split = splitLlvmProgram(SAMPLE, { minimumBytes: 0, targetBytes: 64 * 1024 });
  // The production floor is 64 KiB. Make enough functions to cross it while
  // retaining the readable SAMPLE assertions below.
  expect(split).not.toBeNull();
  expect(splitLlvmProgram(SAMPLE)).toBeNull();
  const large = SAMPLE.replace(
    "define i64 @public_entry",
    `${Array.from({ length: 80 }, (_, i) => `define internal i64 @pad_${i}() #0 {\nentry:\n  ; ${"x".repeat(2048)}\n  ret i64 ${i}\n}\n`).join("\n")}\ndefine i64 @public_entry`,
  );
  const actual = splitLlvmProgram(large, { minimumBytes: 0, targetBytes: 64 * 1024 });
  expect(actual).not.toBeNull();
  expect(actual!.shards.length).toBeGreaterThan(1);
  expect(actual!.promotedSymbols).toContain("hidden_value");
  expect(actual!.promotedSymbols).toContain("left");
  expect(actual!.promotedSymbols).not.toContain("public_value");
  expect(actual!.promotedSymbols).not.toContain("public_entry");
  expect(actual!.publicSymbols).toEqual(["public_value", "public_entry"]);
  expect(actual!.shards[0]!.name).toBe("program-globals.ll");
  expect(actual!.shards[0]!.source).toContain("@hidden_value = hidden global i64 7");
  // Shards declare only what they reference: `left` loads @hidden_value.
  const leftShard = actual!.shards.find((shard) => shard.source.includes("define hidden i64 @left() #0"))!;
  expect(leftShard.source).toContain("@hidden_value = external hidden global i64");
  expect(actual!.shards.some((shard) =>
    !shard.source.includes("define hidden i64 @right() #0") &&
    shard.source.includes("declare hidden i64 @right() #0")
  )).toBe(true);
});

test("thread-local program state conservatively keeps the single-TU path", () => {
  const tls = SAMPLE.replace(
    "@hidden_value = internal global i64 7",
    "@hidden_value = internal thread_local global i64 7",
  );
  expect(splitLlvmProgram(tls, { minimumBytes: 0, targetBytes: 64 * 1024 })).toBeNull();
});

test("debug metadata stays on definitions when splitting LLVM modules", async () => {
  const debug = new LlvmDebugInfo("/source/main.ts", new Map([["/source/main.ts", "console.log(1);\n"]]));
  let source = SAMPLE;
  for (const name of ["left", "right", "public_entry"]) {
    const loc = { file: "/source/main.ts", start: 0, end: 1 };
    const scope = debug.function({ name, loc, params: [], locals: [], body: [], returnType: VOID });
    const location = debug.location(loc, scope);
    source = source.replace(new RegExp(`(@${name}\\(\\) #0) \\{([\\s\\S]*?)\\n\\}`), (_, header: string, body: string) =>
      `${header} !dbg ${scope} {${body.split("\n").map((line) => line.startsWith("  ") ? `${line}, !dbg ${location}` : line).join("\n")}\n}`,
    );
  }
  source += debug.render();
  const split = splitLlvmProgram(source, { minimumBytes: 0 });
  expect(split).not.toBeNull();
  const dir = await mkdtemp(join(tmpdir(), "scriptc-debug-split-"));
  scratch.push(dir);
  for (const shard of split!.shards) {
    expect(shard.source).not.toMatch(/^declare.*!dbg/m);
    const path = join(dir, shard.name);
    await writeFile(path, shard.source);
    const result = spawnSync("clang", ["-Wno-override-module", "-c", path, "-o", `${path}.o`], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  }
});

test("shards carry only their own debug metadata, numbered independently of the rest of the program", async () => {
  // One DISubprogram + DILocation per function, all in one compile unit.
  const program = (names: readonly string[], lineOf: (name: string) => number) => {
    const funcs = names.map((name, i) =>
      `define internal i64 @${name}() #0 !dbg !${4 + 2 * i} {\nentry:\n  ; ${"x".repeat(2048)}\n  ret i64 0, !dbg !${5 + 2 * i}\n}\n`);
    const nodes = names.flatMap((name, i) => [
      `!${4 + 2 * i} = distinct !DISubprogram(name: "${name}", scope: !0, file: !0, line: ${lineOf(name)}, type: !1, scopeLine: ${lineOf(name)}, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2)`,
      `!${5 + 2 * i} = !DILocation(line: ${lineOf(name)}, column: 1, scope: !${4 + 2 * i})`,
    ]);
    return [
      "declare void @runtime(ptr)\n", ...funcs, "attributes #0 = { noinline }",
      "!llvm.dbg.cu = !{!2}", "!llvm.module.flags = !{!3}",
      '!0 = !DIFile(filename: "a.ts", directory: "/src")', "!1 = !DISubroutineType(types: !{})",
      '!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !0, producer: "scriptc", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)',
      '!3 = !{i32 2, !"Debug Info Version", i32 3}', ...nodes, "",
    ].join("\n");
  };
  const names = Array.from({ length: 80 }, (_, i) => `pad_${i}`);
  const options = { minimumBytes: 0, targetBytes: 64 * 1024 };
  const before = splitLlvmProgram(program(names, () => 1), options)!;
  // Edit one function and add another: every later metadata id shifts in the
  // canonical module, but only the shards owning those functions may change.
  const after = splitLlvmProgram(program(["added", ...names], (n) => n === "pad_7" ? 2 : 1), options)!;
  const was = new Map(before.shards.map((shard) => [shard.name, shard.source]));
  const changed = after.shards.filter((shard) => was.get(shard.name) !== shard.source);
  expect(changed.length).toBeGreaterThan(0);
  expect(changed.length).toBeLessThanOrEqual(2);
  const dir = await mkdtemp(join(tmpdir(), "scriptc-md-split-"));
  scratch.push(dir);
  for (const shard of after.shards) {
    expect(shard.source).not.toMatch(/!\d{3,}/); // dense: nothing close to the canonical ids
    const path = join(dir, shard.name);
    await writeFile(path, shard.source);
    const result = spawnSync("clang", ["-Wno-override-module", "-c", path, "-o", `${path}.o`], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
  }
});

test("dev libraries split at the measured 2MB crossover while executables retain 4MB", () => {
  const body = Array.from({ length: 700 }, (_, i) =>
    `define internal i64 @library_pad_${i}() #0 {\nentry:\n  ; ${"x".repeat(3072)}\n  ret i64 ${i}\n}\n`,
  ).join("\n");
  const source = SAMPLE.replace("define i64 @public_entry", `${body}\ndefine i64 @public_entry`);
  expect(Buffer.byteLength(source)).toBeGreaterThan(2 * 1024 * 1024);
  expect(Buffer.byteLength(source)).toBeLessThan(4 * 1024 * 1024);
  expect(splitLlvmProgram(source)).toBeNull();
  expect(splitLlvmLibraryProgram(source)?.shards).toHaveLength(5);

  const belowCrossover = source.slice(0, Math.floor(1.9 * 1024 * 1024));
  expect(splitLlvmLibraryProgram(belowCrossover)).toBeNull();
});

test("every shard compiles and its merged object exposes only canonical public definitions", async () => {
  const body = Array.from({ length: 120 }, (_, i) =>
    `define internal i64 @pad_${i}() #0 {\nentry:\n  ; ${"x".repeat(2048)}\n  ret i64 ${i}\n}\n`,
  ).join("\n");
  const split = splitLlvmProgram(
    SAMPLE.replace("define i64 @public_entry", `${body}\ndefine i64 @public_entry`),
    { minimumBytes: 0, targetBytes: 64 * 1024 },
  )!;
  const dir = await mkdtemp(join(tmpdir(), "scriptc-llvm-split-"));
  scratch.push(dir);
  const objects: string[] = [];
  for (const shard of split.shards) {
    const source = join(dir, shard.name);
    const object = `${source}.o`;
    await writeFile(source, shard.source);
    execFileSync("clang", ["-Wno-override-module", "-c", source, "-o", object]);
    objects.push(object);
  }
  const combined = join(dir, "combined.o");
  execFileSync("ld", ["-r", ...objects, "-o", combined]);
  if (process.platform === "linux") {
    const keep = join(dir, "keep.txt");
    await writeFile(keep, "public_entry\npublic_value\n");
    execFileSync("objcopy", [`--keep-global-symbols=${keep}`, combined]);
  }
  const globals = execFileSync("nm", ["-g", combined], { encoding: "utf8" });
  expect(globals).toContain("public_entry");
  expect(globals).toContain("public_value");
  expect(globals).not.toContain("hidden_value");
  expect(globals).not.toContain("left");
  expect((await readFile(combined)).length).toBeGreaterThan(0);
});
