import lib from "./split.cjs";
import chain from "./initialized.cjs";
import table from "./split-let.cjs";
import { n as linkedN, bump, external, handler, swapHandler } from "./lib.cjs";
import "./writer.cjs";

console.log("default", lib.n, lib.render("default"));
console.log("default lexical receiver", lib.receiverKind());
console.log("default chain", chain.n, chain.render("chain"), chain.render === lib.render);
console.log("default literal", table.n, table.render("default"), table.label);
bump();
console.log("linked import snapshots", linkedN, lib.n, external, lib.external);
swapHandler();
const linkedHandler = handler;
console.log("linked function snapshot", handler(), linkedHandler(), lib.handler());
