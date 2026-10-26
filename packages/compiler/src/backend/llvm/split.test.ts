import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, test } from "vitest";
import { splitLlvmLibraryProgram, splitLlvmProgram, splitLlvmProgramFile } from "./split.js";
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
  expect(actual!.shards[0]!.source()).toContain("@hidden_value = hidden global i64 7");
  // Shards declare only what they reference: `left` loads @hidden_value.
  const leftShard = actual!.shards.find((shard) =>
    shard.source().includes("define hidden i64 @left() #0"),
  )!;
  expect(leftShard.source()).toContain("@hidden_value = external hidden global i64");
  expect(
    actual!.shards.some(
      (shard) =>
        !shard.source().includes("define hidden i64 @right() #0") &&
        shard.source().includes("declare hidden i64 @right() #0"),
    ),
  ).toBe(true);
});

test("thread-local definitions and declarations preserve their storage model across shards", () => {
  const tls = SAMPLE.replace(
    "@hidden_value = internal global i64 7",
    "@hidden_value = internal thread_local global i64 7",
  );
  const split = splitLlvmProgram(tls, { minimumBytes: 0, targetBytes: 64 * 1024 })!;
  expect(split.shards[0]!.source()).toContain("@hidden_value = hidden thread_local global i64 7");
  expect(
    split.shards.some((shard) =>
      shard.source().includes("@hidden_value = external hidden thread_local global i64"),
    ),
  ).toBe(true);
});

const PADDING = Array.from(
  { length: 80 },
  (_, i) =>
    `define internal i64 @pad_${i}() #0 {\nentry:\n  ; ${"x".repeat(2048)}\n  ret i64 ${i}\n}\n`,
).join("\n");

/** SAMPLE with more globals after @public_value and enough functions to
 * split into several shards. `use` names a global some function references
 * (a shard declares only what it references). */
function withGlobals(globals: string, tail = "", use = ""): string {
  const user =
    use === ""
      ? ""
      : `define internal i64 @user() #0 {\nentry:\n  %p = ptrtoint ptr @${use} to i64\n  ret i64 %p\n}\n`;
  return `${SAMPLE.replace(
    "@public_value = constant i64 11",
    `@public_value = constant i64 11\n${globals}`,
  ).replace("define i64 @public_entry", `${PADDING}\n${user}\ndefine i64 @public_entry`)}${tail}`;
}

/** Whether some function shard contains `text`. */
const declared = (functions: readonly { source: () => string }[], text: string): boolean =>
  functions.some((shard) => shard.source().includes(text));

/** Writes each shard and compiles it with clang. */
async function compileShards(
  shards: readonly { name: string; source: () => string }[],
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "scriptc-llvm-split-shards-"));
  scratch.push(dir);
  for (const shard of shards) {
    const source = join(dir, shard.name);
    await writeFile(source, shard.source());
    execFileSync("clang", ["-Wno-override-module", "-c", source, "-o", `${source}.o`]);
  }
}

test("private unnamed_addr lookup tables are promoted like internal globals", async () => {
  const split = splitLlvmProgram(
    withGlobals('@table = private unnamed_addr constant [2 x i8] c"\\01\\02"', "", "table"),
    { minimumBytes: 0, targetBytes: 64 * 1024 },
  )!;
  expect(split).not.toBeNull();
  const [globals, ...functions] = split.shards;
  expect(globals!.source()).toContain('@table = hidden unnamed_addr constant [2 x i8] c"\\01\\02"');
  expect(declared(functions, "@table = external hidden constant [2 x i8]")).toBe(true);
  expect(split.promotedSymbols).toContain("table");
  await compileShards(split.shards);
});

test("aggregate initializers over several lines stay whole in the globals shard", async () => {
  // The regex global's comment holds unbalanced brackets.
  const split = splitLlvmProgram(
    withGlobals(
      `@regex = internal global { ptr, i64 } { ptr @left, i64 0 } ; /(a|[b/
@vt = internal constant [2 x { i64, ptr }] [
  { i64, ptr } { i64 1, ptr @left },
  { i64, ptr } { i64 2, ptr @right }
]`,
      "",
      "vt",
    ),
    { minimumBytes: 0, targetBytes: 64 * 1024 },
  )!;
  expect(split).not.toBeNull();
  const [globals, ...functions] = split.shards;
  expect(globals!.source()).toContain(
    "@vt = hidden constant [2 x { i64, ptr }] [\n  { i64, ptr } { i64 1, ptr @left },\n  { i64, ptr } { i64 2, ptr @right }\n]",
  );
  expect(declared(functions, "@vt = external hidden constant [2 x { i64, ptr }]")).toBe(true);
  for (const shard of functions) expect(shard.source()).not.toContain("{ i64, ptr } { i64 1");
  expect(split.promotedSymbols).toEqual(expect.arrayContaining(["regex", "vt"]));
  await compileShards(split.shards);
});

test("globals after the attributes and metadata join the globals shard", async () => {
  const split = splitLlvmProgram(withGlobals("", "@flag = internal constant i1 true\n", "flag"), {
    minimumBytes: 0,
    targetBytes: 64 * 1024,
  })!;
  expect(split).not.toBeNull();
  const [globals, ...functions] = split.shards;
  expect(globals!.source()).toContain("@flag = hidden constant i1 true");
  expect(declared(functions, "@flag = external hidden constant i1")).toBe(true);
  await compileShards(split.shards);
});

test("a module split from its file has the shards of the same module split in memory", async () => {
  const dir = await mkdtemp(join(tmpdir(), "scriptc-llvm-split-file-"));
  scratch.push(dir);
  const options = { minimumBytes: 0, targetBytes: 64 * 1024 };
  const storage = withGlobals(
    `@table = private unnamed_addr constant [2 x i8] c"\\01\\02"
@vt = internal constant [2 x { i64, ptr }] [
  { i64, ptr } { i64 1, ptr @left },
  { i64, ptr } { i64 2, ptr @right }
]`,
    "@flag = internal constant i1 true\n",
  );
  for (const [name, source] of [
    ["sample.ll", withGlobals("")],
    ["storage.ll", storage],
  ] as const) {
    const path = join(dir, name);
    await writeFile(path, source);
    const fromFile = splitLlvmProgramFile(path, options)!;
    expect(fromFile).not.toBeNull();
    const materialize = (split: NonNullable<typeof fromFile>) => ({
      ...split,
      shards: split.shards.map((shard) => ({ name: shard.name, source: shard.source() })),
    });
    expect(materialize(fromFile)).toEqual(materialize(splitLlvmProgram(source, options)!));
  }
});

test.skipIf(process.platform === "win32")(
  "split and merged native modules keep globals independent on concurrent threads",
  async () => {
    const source = `%State = type { i64, i64 }
@state = internal thread_local global %State { i64 7, i64 0 }
@foreign = external thread_local global i64

define void @set_owner(i64 %owner) {
entry:
  store i64 %owner, ptr getelementptr inbounds (%State, ptr @state, i64 0, i32 1)
  ret void
}

define i64 @get_owner() {
entry:
  %owner = load i64, ptr getelementptr inbounds (%State, ptr @state, i64 0, i32 1)
  ret i64 %owner
}

define i64 @next_value() {
entry:
  %current = load i64, ptr @state
  %next = add i64 %current, 1
  store i64 %next, ptr @state
  %other = load i64, ptr @foreign
  %after = add i64 %other, 1
  store i64 %after, ptr @foreign
  %result = add i64 %current, %other
  ret i64 %result
}
`;
    const split = splitLlvmProgram(source, { minimumBytes: 0, targetBytes: 64 * 1024 })!;
    expect(split.shards.length).toBeGreaterThan(2);
    const dir = await mkdtemp(join(tmpdir(), "scriptc-llvm-thread-state-"));
    scratch.push(dir);
    const objects: string[] = [];
    for (const shard of split.shards) {
      const path = join(dir, shard.name);
      const object = `${path}.o`;
      await writeFile(path, shard.source());
      execFileSync("clang", ["-Wno-override-module", "-O2", "-c", path, "-o", object]);
      objects.push(object);
    }
    const combined = join(dir, "combined.o");
    execFileSync("ld", ["-r", ...objects, "-o", combined]);
    if (process.platform === "linux") {
      const keep = join(dir, "keep.txt");
      await writeFile(keep, "set_owner\nget_owner\nnext_value\n");
      execFileSync("objcopy", [`--keep-global-symbols=${keep}`, combined]);
    }
    const binary = join(dir, "thread-state");
    execFileSync("clang", [
      "-std=c11",
      "-O2",
      "-pthread",
      join(import.meta.dirname, "split-thread-state.test.c"),
      combined,
      "-o",
      binary,
    ]);
    expect(execFileSync(binary, { encoding: "utf8", timeout: 10000 })).toBe(
      "thread state stays isolated across compiled partitions\n",
    );
  },
);

test("shared metadata bounds shard growth while preserving every definition", () => {
  const names = Array.from({ length: 120 }, (_, i) => `metadata_pad_${i}`);
  const body = names
    .map(
      (name) =>
        `define internal i64 @${name}() #0 {\nentry:\n  ; ${"x".repeat(32 * 1024)}\n  ret i64 1\n}\n`,
    )
    .join("\n");
  const source =
    SAMPLE.replace("define i64 @public_entry", `${body}\ndefine i64 @public_entry`) +
    `!0 = !{!"${"x".repeat(256 * 1024)}"}\n`;
  const split = splitLlvmProgram(source, { minimumBytes: 0, targetBytes: 64 * 1024 });
  expect(split).not.toBeNull();
  expect(split!.shards.length).toBeGreaterThan(1);
  expect(
    split!.shards.reduce((bytes, shard) => bytes + Buffer.byteLength(shard.source()), 0),
  ).toBeLessThanOrEqual(2 * Buffer.byteLength(source));
  const definitions = split!.shards.flatMap((shard) =>
    [...shard.source().matchAll(/^define (?:hidden )?i64 @(\w+)\(/gm)].map((match) => match[1]),
  );
  expect(definitions.sort()).toEqual([...names, "left", "right", "public_entry"].sort());
  expect(split!.publicSymbols).toEqual(["public_value", "public_entry"]);

  // Metadata no shard references is not duplicated into any of them.
  const shared = SAMPLE + `!0 = !{!"${"x".repeat(2 * 1024 * 1024)}"}\n`;
  const unshared = splitLlvmProgram(shared, { minimumBytes: 0 });
  expect(unshared).not.toBeNull();
  for (const shard of unshared!.shards) expect(shard.source()).not.toContain("xxxx");
});

test("debug metadata stays on definitions when splitting LLVM modules", async () => {
  const debug = new LlvmDebugInfo(
    "/source/main.ts",
    new Map([["/source/main.ts", "console.log(1);\n"]]),
  );
  let source = SAMPLE;
  for (const name of ["left", "right", "public_entry"]) {
    const loc = { file: "/source/main.ts", start: 0, end: 1 };
    const scope = debug.function({ name, loc, params: [], locals: [], body: [], returnType: VOID });
    const location = debug.location(loc, scope);
    source = source.replace(
      new RegExp(`(@${name}\\(\\) #0) \\{([\\s\\S]*?)\\n\\}`),
      (_, header: string, body: string) =>
        `${header} !dbg ${scope} {${body
          .split("\n")
          .map((line) => (line.startsWith("  ") ? `${line}, !dbg ${location}` : line))
          .join("\n")}\n}`,
    );
  }
  source += debug.render();
  const split = splitLlvmProgram(source, { minimumBytes: 0 });
  expect(split).not.toBeNull();
  const dir = await mkdtemp(join(tmpdir(), "scriptc-debug-split-"));
  scratch.push(dir);
  for (const shard of split!.shards) {
    expect(shard.source()).not.toMatch(/^declare.*!dbg/m);
    const path = join(dir, shard.name);
    await writeFile(path, shard.source());
    const result = spawnSync("clang", ["-Wno-override-module", "-c", path, "-o", `${path}.o`], {
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  }
});

test("shards carry only their own debug metadata, numbered independently of the rest of the program", async () => {
  // One DISubprogram + DILocation per function, all in one compile unit.
  const program = (names: readonly string[], lineOf: (name: string) => number) => {
    const funcs = names.map(
      (name, i) =>
        `define internal i64 @${name}() #0 !dbg !${4 + 2 * i} {\nentry:\n  ; ${"x".repeat(2048)}\n  ret i64 0, !dbg !${5 + 2 * i}\n}\n`,
    );
    const nodes = names.flatMap((name, i) => [
      `!${4 + 2 * i} = distinct !DISubprogram(name: "${name}", scope: !0, file: !0, line: ${lineOf(name)}, type: !1, scopeLine: ${lineOf(name)}, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2)`,
      `!${5 + 2 * i} = !DILocation(line: ${lineOf(name)}, column: 1, scope: !${4 + 2 * i})`,
    ]);
    return [
      "declare void @runtime(ptr)\n",
      ...funcs,
      "attributes #0 = { noinline }",
      "!llvm.dbg.cu = !{!2}",
      "!llvm.module.flags = !{!3}",
      '!0 = !DIFile(filename: "a.ts", directory: "/src")',
      "!1 = !DISubroutineType(types: !{})",
      '!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !0, producer: "scriptc", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)',
      '!3 = !{i32 2, !"Debug Info Version", i32 3}',
      ...nodes,
      "",
    ].join("\n");
  };
  const names = Array.from({ length: 80 }, (_, i) => `pad_${i}`);
  const options = { minimumBytes: 0, targetBytes: 64 * 1024 };
  const before = splitLlvmProgram(
    program(names, () => 1),
    options,
  )!;
  // Edit one function and add another: every later metadata id shifts in the
  // canonical module, but only the shards owning those functions may change.
  const after = splitLlvmProgram(
    program(["added", ...names], (name) => (name === "pad_7" ? 2 : 1)),
    options,
  )!;
  const was = new Map(before.shards.map((shard) => [shard.name, shard.source()]));
  const changed = after.shards.filter((shard) => was.get(shard.name) !== shard.source());
  expect(changed.length).toBeGreaterThan(0);
  expect(changed.length).toBeLessThanOrEqual(2);
  const dir = await mkdtemp(join(tmpdir(), "scriptc-md-split-"));
  scratch.push(dir);
  for (const shard of after.shards) {
    expect(shard.source()).not.toMatch(/!\d{3,}/); // dense: nothing close to the canonical ids
    const path = join(dir, shard.name);
    await writeFile(path, shard.source());
    const result = spawnSync("clang", ["-Wno-override-module", "-c", path, "-o", `${path}.o`], {
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
  }
});

test("dev libraries split at the measured 2MB crossover while executables retain 4MB", () => {
  const body = Array.from(
    { length: 700 },
    (_, i) =>
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
  const body = Array.from(
    { length: 120 },
    (_, i) =>
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
    await writeFile(source, shard.source());
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
