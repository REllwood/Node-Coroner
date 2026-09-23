import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { analyseBundle } from "../src/analyse.js";
import { BundleError, parseBundle } from "../src/bundle.js";
import { toMarkdown, toText } from "../src/report.js";

const fixture = async (name) => parseBundle(await readFile(new URL(`../fixtures/${name}.json`, import.meta.url), "utf8"));

test("fixture suite distinguishes five common termination categories", async () => {
  const examples = new Map([
    ["oom", "out-of-memory"],
    ["uncaught-exception", "uncaught-exception"],
    ["unhandled-rejection", "unhandled-rejection"],
    ["native-crash", "native-crash"],
    ["external-termination", "external-termination"]
  ]);
  for (const [name, expected] of examples) {
    const report = analyseBundle(await fixture(name));
    assert.ok(report.hypotheses.some((item) => item.category === expected), `${name} should include ${expected}`);
    for (const hypothesis of report.hypotheses) assert.ok(hypothesis.supports.length > 0);
  }
});

test("a clean exit does not manufacture an incident", async () => {
  const report = analyseBundle(await fixture("clean-exit"));
  assert.equal(report.observedOutcome.status, "clean-exit");
  assert.deepEqual(report.hypotheses, []);
});

test("reports redact credentials and paths before rendering evidence", async () => {
  const external = analyseBundle(await fixture("external-termination"));
  assert.match(external.timeline[0].text, /\[redacted named credential\]/);
  assert.equal(external.sanitisation.replacementCount, 1);
  const oom = analyseBundle(await fixture("oom"));
  assert.doesNotMatch(JSON.stringify(oom), /\/Users\/example/);
  assert.equal(oom.sanitisation.replacementCount, 1);
});

test("malformed and duplicate evidence is rejected", () => {
  const malformed = {
    format: "node-coroner.bundle.v1",
    nodeVersion: "22.17.0",
    outcome: { exitCode: 1, signal: null },
    evidence: [
      { id: "same", kind: "stderr", source: "one", timestamp: "2026-07-24T00:00:00Z", timestampQuality: "exact", text: "one" },
      { id: "same", kind: "stderr", source: "two", timestamp: "2026-07-24T00:00:01Z", timestampQuality: "exact", text: "two" }
    ]
  };
  assert.throws(() => parseBundle(malformed), BundleError);
  assert.throws(() => parseBundle("{"), BundleError);
});

test("environment-shaped and sensitive-key values are redacted with truthful disclosure", () => {
  const bundle = parseBundle({
    format: "node-coroner.bundle.v1",
    nodeVersion: "22.17.0",
    command: "node service.mjs",
    outcome: { exitCode: 1, signal: null },
    evidence: [{
      id: "diagnostic-1",
      kind: "diagnostic",
      source: "local report",
      timestamp: "2026-07-24T01:00:00.000Z",
      timestampQuality: "exact",
      data: {
        environment: { DATABASE_URL: "postgres://private" },
        apiKey: "plain-value-that-pattern-scanning-would-miss",
        nested: { password: "another-plain-value" }
      }
    }]
  });
  const report = analyseBundle(bundle);
  const rendered = JSON.stringify(report);
  assert.doesNotMatch(rendered, /postgres:\/\/private|plain-value/);
  assert.ok(report.sanitisation.categories.includes("environment values"));
  assert.ok(report.sanitisation.categories.includes("sensitive field"));
  assert.deepEqual(report.sanitisation.excludedByBundleContract, ["unselected files"]);
});

test("evidence identifiers and environment assignments are sanitised before JSON export", () => {
  const bundle = parseBundle({
    format: "node-coroner.bundle.v1",
    nodeVersion: "NODE_VERSION=22.17.0 PRIVATE_TOKEN=hidden-version",
    command: "node service.mjs",
    outcome: { exitCode: 1, signal: null },
    evidence: [{
      id: "/Users/private-account/evidence-1",
      kind: "stderr",
      source: "captured stderr",
      timestamp: "2026-07-24T01:00:00.000Z",
      timestampQuality: "exact",
      text:
        'DATABASE_URL=postgres://user:private-password@db.example.test/app customSecret="prefix \\"hidden value\\"" unhandled rejection'
    }]
  });
  const report = analyseBundle(bundle);
  const rendered = JSON.stringify(report);
  assert.doesNotMatch(
    rendered,
    /private-account|private-password|hidden value|hidden-version/
  );
  assert.equal(report.timeline[0].id, "evidence-1-redacted");
  assert.ok(report.hypotheses[0].supports.includes("evidence-1-redacted"));
  assert.ok(report.sanitisation.categories.includes("Unix path"));
  assert.ok(report.sanitisation.categories.includes("environment assignment"));
});

test("a zero exit remains successful when evidence supports a contradictory hypothesis", () => {
  const bundle = parseBundle({
    format: "node-coroner.bundle.v1",
    nodeVersion: "22.17.0",
    command: "node service.mjs",
    outcome: { exitCode: 0, signal: null },
    evidence: [{
      id: "stderr-1",
      kind: "stderr",
      source: "captured stderr",
      timestamp: "2026-07-24T01:00:00.000Z",
      timestampQuality: "exact",
      text: "FATAL ERROR: JavaScript heap out of memory"
    }]
  });
  const report = analyseBundle(bundle);
  assert.equal(
    report.observedOutcome.status,
    "successful-exit-with-contradictory-evidence"
  );
  assert.ok(report.hypotheses[0].contradicts.includes("The recorded exit code is zero."));
  assert.match(toText(report), /successful zero exit with contradictory/);
});

test("Markdown rendering neutralises imported HTML and active Markdown", () => {
  const report = analyseBundle(parseBundle({
    format: "node-coroner.bundle.v1",
    nodeVersion: "22.17.0",
    command: "node service.mjs",
    outcome: { exitCode: 1, signal: null },
    evidence: [{
      id: "![identifier](https://example.test/id)",
      kind: "stderr",
      source: "<script>alert(1)</script> ![source](https://example.test/source)",
      timestamp: "2026-07-24T01:00:00.000Z",
      timestampQuality: "exact",
      text: "<b>unhandled rejection</b> ![tracker](https://example.test/pixel)"
    }]
  }));
  const markdown = toMarkdown(report);
  assert.doesNotMatch(markdown, /<script>|<img|<b>/);
  assert.doesNotMatch(markdown, /!\[(?:identifier|source|tracker)\]\(https:/);
  assert.doesNotMatch(markdown, /https:\/\//);
  assert.match(markdown, /&lt;script&gt;/);
  assert.match(
    markdown,
    /&#33;&#91;tracker&#93;&#40;https&#58;\/\/example&#46;test\/pixel&#41;/
  );
});
