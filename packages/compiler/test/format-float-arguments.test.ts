import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { compile, deserializeModule, validateModule } from "../src/index.js";

test("util.format %f lowers a boolean argument once", async () => {
  const dir = await mkdtemp(join(tmpdir(), "scriptc-format-float-"));
  try {
    const entry = join(dir, "main.ts");
    const outPath = join(dir, "main.ir.json");
    await writeFile(
      entry,
      [
        'import { format } from "node:util";',
        "const xs = [1, 2, 3];",
        'console.log(format("%f %f", xs.some((x) => x > 2), xs.every((x) => x > 0)));',
      ].join("\n"),
    );
    const result = await compile(entry, { outDir: dir, outPath, outputKind: "ir" });
    if (!result.ok)
      throw new Error(result.diagnostics.map((d) => `${d.code}: ${d.message}`).join("\n"));
    const mod = deserializeModule(await readFile(outPath, "utf8"));
    expect(validateModule(mod)).toEqual([]);
    // One lifted helper per argument: the evaluated-for-effect statement
    // reuses the lowered value instead of lowering the argument again.
    const helpers = mod.functions
      .map((f) => f.name)
      .filter((name) => name.startsWith("%arr."))
      .map((name) => name.replace(/\.[0-9a-f]+$/, ""))
      .sort();
    expect(helpers).toEqual(["%arr.every", "%arr.some"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
