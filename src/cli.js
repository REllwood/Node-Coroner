#!/usr/bin/env node
import { readFile, stat, writeFile } from "node:fs/promises";
import process from "node:process";
import { analyseBundle } from "./analyse.js";
import { BundleError, parseBundle } from "./bundle.js";
import { toMarkdown, toText } from "./report.js";

const MAX_BUNDLE_BYTES = 5 * 1024 * 1024;

function help() {
  return `Node Coroner v0.1

Usage:
  npm start -- analyse <bundle.json> [--format text|json|markdown] [--output <new-path>]
  npm start -- --help

Saved bundles are validated and bounded before analysis. Reports are sanitised by
default. An incident finding does not change the successful exit status.`;
}

function argumentsFor(values) {
  if (values.includes("--help") || values.includes("-h")) return { help: true };
  if (values[0] !== "analyse" || !values[1]) throw new BundleError("Expected analyse and a bundle path");
  let format = "text";
  let output = null;
  for (let index = 2; index < values.length; index += 1) {
    if (values[index] === "--format") format = values[++index];
    else if (values[index] === "--output") output = values[++index];
    else throw new BundleError(`Unknown option ${values[index]}`);
  }
  if (!["text", "json", "markdown"].includes(format)) throw new BundleError("--format must be text, json or markdown");
  if (output !== null && (!output || typeof output !== "string")) throw new BundleError("--output requires a path");
  return { path: values[1], format, output };
}

async function main() {
  const options = argumentsFor(process.argv.slice(2));
  if (options.help) return void process.stdout.write(`${help()}\n`);
  const metadata = await stat(options.path);
  if (!metadata.isFile() || metadata.size > MAX_BUNDLE_BYTES) throw new BundleError(`Bundle must be a regular file no larger than ${MAX_BUNDLE_BYTES} bytes`);
  const report = analyseBundle(parseBundle(await readFile(options.path, "utf8")));
  const rendered = options.format === "json"
    ? `${JSON.stringify(report, null, 2)}\n`
    : options.format === "markdown"
      ? `${toMarkdown(report)}\n`
      : `${toText(report)}\n`;
  if (options.output) {
    await writeFile(options.output, rendered, { encoding: "utf8", flag: "wx" });
    process.stdout.write(`Wrote sanitised ${options.format} report to ${options.output}\n`);
  } else process.stdout.write(rendered);
}

main().catch((error) => {
  process.stderr.write(`Node Coroner: ${error instanceof BundleError || error?.code ? error.message : "Unexpected analysis failure"}\n`);
  process.exitCode = 2;
});
