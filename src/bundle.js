const LIMITS = Object.freeze({
  evidence: 5_000,
  text: 64 * 1024,
  identifier: 160,
  command: 2_048,
  diagnosticBytes: 256 * 1024
});

export class BundleError extends Error {
  constructor(message) {
    super(message);
    this.name = "BundleError";
  }
}

function record(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BundleError(`${path} must be an object`);
  }
  return value;
}

function boundedString(value, path, maximum, required = true) {
  if ((!required && value === undefined) || (!required && value === null)) return null;
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new BundleError(`${path} must be a non-empty string of at most ${maximum} characters`);
  }
  return value;
}

function parseTimestamp(value, path) {
  const source = boundedString(value, path, 64);
  const milliseconds = Date.parse(source);
  if (!Number.isFinite(milliseconds)) throw new BundleError(`${path} must be an RFC 3339 timestamp`);
  return { source, milliseconds };
}

function normaliseEvidence(value, index) {
  const path = `bundle.evidence[${index}]`;
  const item = record(value, path);
  if (!['process', 'stderr', 'diagnostic', 'resource'].includes(item.kind)) {
    throw new BundleError(`${path}.kind is not supported`);
  }
  if (!['exact', 'derived', 'unknown'].includes(item.timestampQuality)) {
    throw new BundleError(`${path}.timestampQuality must be exact, derived or unknown`);
  }
  const timestamp = parseTimestamp(item.timestamp, `${path}.timestamp`);
  const text = item.text === undefined ? null : boundedString(item.text, `${path}.text`, LIMITS.text);
  let data = null;
  if (item.data !== undefined) {
    data = record(item.data, `${path}.data`);
    if (JSON.stringify(data).length > LIMITS.diagnosticBytes) {
      throw new BundleError(`${path}.data exceeds the diagnostic data limit`);
    }
  }
  if (text === null && data === null) throw new BundleError(`${path} must include text or data`);
  return Object.freeze({
    id: boundedString(item.id, `${path}.id`, LIMITS.identifier),
    kind: item.kind,
    source: boundedString(item.source, `${path}.source`, LIMITS.identifier),
    timestamp: timestamp.source,
    timeMs: timestamp.milliseconds,
    timestampQuality: item.timestampQuality,
    text,
    data
  });
}

export function parseBundle(input) {
  let raw;
  try {
    raw = typeof input === "string" ? JSON.parse(input) : input;
  } catch (error) {
    throw new BundleError(`Bundle is not valid JSON: ${error.message}`);
  }
  const bundle = record(raw, "bundle");
  if (bundle.format !== "node-coroner.bundle.v1") {
    throw new BundleError("bundle.format must be node-coroner.bundle.v1");
  }
  const outcome = record(bundle.outcome, "bundle.outcome");
  const exitCode = outcome.exitCode ?? null;
  const signal = outcome.signal ?? null;
  if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255)) {
    throw new BundleError("bundle.outcome.exitCode must be null or an integer from 0 to 255");
  }
  if (signal !== null && !/^SIG[A-Z0-9]{1,20}$/.test(signal)) {
    throw new BundleError("bundle.outcome.signal must be null or a POSIX signal name");
  }
  if (!Array.isArray(bundle.evidence) || bundle.evidence.length > LIMITS.evidence) {
    throw new BundleError(`bundle.evidence must be an array of at most ${LIMITS.evidence} records`);
  }
  const evidence = bundle.evidence.map(normaliseEvidence);
  const ids = new Set();
  for (const item of evidence) {
    if (ids.has(item.id)) throw new BundleError(`bundle.evidence contains duplicate id ${item.id}`);
    ids.add(item.id);
  }
  return Object.freeze({
    format: bundle.format,
    nodeVersion: boundedString(bundle.nodeVersion, "bundle.nodeVersion", 64),
    command: boundedString(bundle.command, "bundle.command", LIMITS.command, false),
    outcome: Object.freeze({ exitCode, signal }),
    evidence: Object.freeze(evidence)
  });
}
