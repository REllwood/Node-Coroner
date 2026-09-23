import { fileURLToPath } from "node:url";

if (process.argv.length === 2) {
  process.argv.push("analyse", fileURLToPath(new URL("../fixtures/oom.json", import.meta.url)));
}

await import("./cli.js");
