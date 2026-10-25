import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { compile, deserializeModule } from "../src/index.js";
import { emitLlvmModule } from "../src/backend/llvm/emitter.js";

test("scans of strings that are not ASCII read their UTF-16 units", async () => {
  const dir = await mkdtemp(join(tmpdir(), "scriptc-unit-loops-"));
  try {
    const entry = join(dir, "main.ts");
    await writeFile(
      entry,
      `
function spaces(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 32) n++;
  return n;
}
function skip(s: string): number {
  let pos = 0;
  while (pos < s.length && s.charCodeAt(pos) !== 32) pos++;
  return pos;
}
function pairs(s: string, t: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === t.charCodeAt(i % t.length)) n++;
  return n;
}
let text = "";
for (let k = 0; k < 400; k++) text += k % 3 === 0 ? "café " : "naïve façade ";
const other = text.replace(/a/g, "ä");
let total = 0;
for (let pass = 0; pass < 4; pass++)
  total += spaces(text) + spaces(other) + pairs(text, other) + skip(text);
console.log(total, spaces("plain ascii text"), spaces(""));
`,
    );
    const outPath = join(dir, "main.ir.json");
    const lowered = await compile(entry, { outDir: dir, outPath, outputKind: "ir" });
    if (!lowered.ok)
      throw new Error(lowered.diagnostics.map((d) => `${d.code}: ${d.message}`).join("\n"));
    const ll = emitLlvmModule(deserializeModule(await readFile(outPath, "utf8")));
    const body = (name: string): string =>
      ll.match(
        new RegExp(
          `define internal [^\\n]+ @sc_bf_${name}(?:\\.i32)?\\([^\\n]*\\) #0 \\{[\\s\\S]*?\\n\\}`,
        ),
      )![0];

    const spaces = body("spaces");
    // A string that is not ASCII is converted to units and published as the
    // scan receiver once, before the loop, and its copy loads units.
    expect(spaces).toMatch(/call void @scr_str_scan_units\(ptr %\S+\)/);
    // The copies follow the checked one: bytes, then units.
    const bytesAt = spaces.search(/^bytes\.version\.fast\d+:/m);
    const unitsAt = spaces.search(/^bytes\.version\.fast\.units\d+:/m);
    expect(bytesAt).toBeGreaterThan(0);
    expect(unitsAt).toBeGreaterThan(bytesAt);
    const units = spaces.slice(unitsAt);
    expect(units).toMatch(/load i16, ptr %\S+\n\s+%\S+ = uitofp i16/);
    expect(units).not.toContain("@sc_str_char_code_at_int");
    // An ASCII string still reads bytes.
    const bytes = spaces.slice(bytesAt, unitsAt);
    expect(bytes).toMatch(/load i8, ptr %\S+\n\s+%\S+ = uitofp i8/);
    expect(bytes).not.toContain("@sc_str_char_code_at_int");
    // A while loop over a counter below the length reads units too.
    const skip = body("skip");
    expect(skip).toMatch(/^bytes\.version\.fast\.units\d+:/m);
    // Its fast copies read the length the guard took; the checked copy
    // still asks for it.
    const skipFastAt = skip.search(/^bytes\.version\.fast\d+:/m);
    expect(skip.slice(0, skipFastAt)).toContain("@sc_str_utf16_len");
    expect(skip.slice(skipFastAt)).not.toContain("@sc_str_utf16_len");
    // Two strings cannot both be the scan receiver.
    expect(body("pairs")).not.toContain("bytes.version.fast.units");

    const exe = join(dir, "main");
    const built = await compile(entry, { outputKind: "exe", outDir: dir, outPath: exe });
    if (!built.ok) throw new Error(JSON.stringify(built.diagnostics));
    let text = "";
    for (let k = 0; k < 400; k++) text += k % 3 === 0 ? "café " : "naïve façade ";
    const other = text.replace(/a/g, "ä");
    const count = (s: string): number => s.split(" ").length - 1;
    let pairs = 0;
    for (let i = 0; i < text.length; i++)
      if (text.charCodeAt(i) === other.charCodeAt(i % other.length)) pairs++;
    const total = 4 * (count(text) + count(other) + pairs + text.indexOf(" "));
    expect(execFileSync(exe, { encoding: "utf8" })).toBe(`${total} 2 0\n`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loops that start at each token publish the scan receiver only when it changed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "scriptc-unit-republish-"));
  try {
    const entry = join(dir, "main.ts");
    await writeFile(
      entry,
      `
function words(s: string): number {
  let n = 0,
    pos = 0;
  while (pos < s.length) {
    while (pos < s.length && s.charCodeAt(pos) !== 32) pos++;
    while (pos < s.length && s.charCodeAt(pos) === 32) pos++;
    n++;
  }
  return n;
}
let text = "";
for (let k = 0; k < 400; k++) text += k % 3 === 0 ? "café " : "naïve  façade ";
console.log(words(text), words(text.replace(/a/g, "ä")), words("plain ascii"));
`,
    );
    const outPath = join(dir, "main.ir.json");
    const lowered = await compile(entry, { outDir: dir, outPath, outputKind: "ir" });
    if (!lowered.ok)
      throw new Error(lowered.diagnostics.map((d) => `${d.code}: ${d.message}`).join("\n"));
    const ll = emitLlvmModule(deserializeModule(await readFile(outPath, "utf8")));
    const words = ll.match(
      /define internal [^\n]+ @sc_bf_words(?:\.i32)?\([^\n]*\) #0 \{[\s\S]*?\n\}/,
    )![0];
    // Each inner loop's entry compares the scan receiver with `s` and calls
    // the runtime to publish `s` only when they differ.
    const guards = [
      ...words.matchAll(
        /^bytes\.version\.publish\d+:[^\n]*\n\s+(%\S+) = load ptr, ptr @scr_str_scan\n\s+(%\S+) = icmp eq ptr \1, (%\S+)\n\s+br i1 \2, label %(bytes\.version\.publish\.load\d+), label %(bytes\.version\.publish\.units\d+)\n/gm,
      ),
    ];
    expect(guards.length).toBeGreaterThanOrEqual(2);
    for (const [, , , s, load, convert] of guards) {
      const block = words.slice(words.search(new RegExp(`^${convert}:`, "m")));
      expect(block).toMatch(
        new RegExp(
          `^${convert}:[^\\n]*\\n\\s+call void @scr_str_scan_units\\(ptr ${s}\\)\\n\\s+br label %${load}\\n`,
        ),
      );
    }
    const calls = words.match(/call void @scr_str_scan_units\(ptr %\S+\)/g)!;
    expect(calls.length).toBe(guards.length);

    const exe = join(dir, "main");
    const built = await compile(entry, { outputKind: "exe", outDir: dir, outPath: exe });
    if (!built.ok) throw new Error(JSON.stringify(built.diagnostics));
    expect(execFileSync(exe, { encoding: "utf8" })).toBe("666 666 2\n");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
