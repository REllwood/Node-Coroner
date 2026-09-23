import { sanitiseText, sanitiseValue } from "./redact.js";

function searchable(item) {
  return `${item.text ?? ""}\n${item.data ? JSON.stringify(item.data) : ""}`;
}

const RULES = Object.freeze([
  {
    id: "NC-OOM",
    category: "out-of-memory",
    title: "JavaScript heap exhaustion",
    match: /heap out of memory|allocation failed|ineffective mark-compacts|javascript heap/i,
    signals: [],
    explanation: "The available artefacts are consistent with V8 failing to allocate within the JavaScript heap limit.",
    next: "Inspect allocation growth and heap limits, then reproduce with an appropriate diagnostic report or heap profile."
  },
  {
    id: "NC-UNCAUGHT",
    category: "uncaught-exception",
    title: "Uncaught JavaScript exception",
    match: /uncaught exception|uncaughtexception|throw new [a-z]*error|^\s*at .+\(.+\.m?js:\d+/im,
    signals: [],
    explanation: "The final stderr evidence is consistent with an exception reaching the process boundary.",
    next: "Inspect the first application stack frame and reproduce with source maps and the same input."
  },
  {
    id: "NC-REJECTION",
    category: "unhandled-rejection",
    title: "Unhandled promise rejection",
    match: /unhandledpromiserejection|unhandled rejection|err_unhandled_rejection/i,
    signals: [],
    explanation: "The runtime reported a promise rejection that was not handled before process termination.",
    next: "Trace the rejected promise to its creator and add explicit async error handling at the owning boundary."
  },
  {
    id: "NC-NATIVE",
    category: "native-crash",
    title: "Native abort or segmentation fault",
    match: /segmentation fault|native crash|fatal native|sigsegv|sigabrt/i,
    signals: ["SIGSEGV", "SIGABRT", "SIGBUS"],
    explanation: "The signal or diagnostic text is consistent with termination below ordinary JavaScript exception handling.",
    next: "Preserve the matching executable and native symbols, then use a platform debugger or core-dump workflow."
  },
  {
    id: "NC-EXTERNAL",
    category: "external-termination",
    title: "External termination request",
    match: /received sigterm|terminated by supervisor|killed by operator/i,
    signals: ["SIGTERM", "SIGKILL", "SIGINT", "SIGHUP"],
    explanation: "The observed signal is normally delivered by another process, an operator or the operating system.",
    next: "Correlate the timestamp with supervisor, container and operating-system records outside this bundle."
  }
]);

function sanitiseEvidence(item, notices, safeId) {
  const safeSource = sanitiseText(item.source);
  const safeText = item.text === null ? null : sanitiseText(item.text);
  notices.push(...safeSource.redactions, ...(safeText?.redactions ?? []));
  return {
    id: safeId,
    kind: item.kind,
    source: safeSource.value,
    timestamp: item.timestamp,
    timestampQuality: item.timestampQuality,
    text: safeText?.value ?? null,
    data: item.data === null ? null : sanitiseValue(item.data, notices)
  };
}

export function analyseBundle(bundle) {
  const timeline = [...bundle.evidence].sort((left, right) => left.timeMs - right.timeMs || left.id.localeCompare(right.id));
  const notices = [];
  const safeEvidenceIds = new Map(
    timeline.map((item, index) => {
      const safeId = sanitiseText(item.id);
      notices.push(...safeId.redactions);
      return [
        item.id,
        safeId.redactions.length > 0
          ? `evidence-${index + 1}-redacted`
          : safeId.value
      ];
    })
  );
  const hypotheses = [];
  for (const rule of RULES) {
    const matching = timeline.filter((item) => rule.match.test(searchable(item)));
    const signalMatch = bundle.outcome.signal !== null && rule.signals.includes(bundle.outcome.signal);
    if (matching.length === 0 && !signalMatch) continue;
    const supports = matching.map((item) => safeEvidenceIds.get(item.id));
    if (signalMatch) supports.unshift("observed-outcome");
    const confidence = signalMatch && matching.length > 0 ? "high" : matching.length > 0 || signalMatch ? "medium" : "low";
    hypotheses.push({
      ruleId: rule.id,
      category: rule.category,
      title: rule.title,
      confidence,
      explanation: rule.explanation,
      supports: [...new Set(supports)],
      contradicts: bundle.outcome.exitCode === 0 ? ["The recorded exit code is zero."] : [],
      missing: matching.length === 0 ? ["No matching textual or diagnostic record was supplied."] : [],
      nextCollectionStep: rule.next
    });
  }
  hypotheses.sort((left, right) => ({ high: 0, medium: 1, low: 2 })[left.confidence] - ({ high: 0, medium: 1, low: 2 })[right.confidence] || left.ruleId.localeCompare(right.ruleId));

  const successful = bundle.outcome.exitCode === 0 && bundle.outcome.signal === null;
  const outcomeStatus = successful
    ? hypotheses.length === 0
      ? "clean-exit"
      : "successful-exit-with-contradictory-evidence"
    : "incident-observed";
  const safeTimeline = timeline.map((item) =>
    sanitiseEvidence(item, notices, safeEvidenceIds.get(item.id))
  );
  const safeCommand = bundle.command === null ? null : sanitiseText(bundle.command);
  if (safeCommand) notices.push(...safeCommand.redactions);
  const safeNodeVersion = sanitiseText(bundle.nodeVersion);
  notices.push(...safeNodeVersion.redactions);
  return {
    format: "node-coroner.report.v1",
    observedOutcome: {
      status: outcomeStatus,
      exitCode: bundle.outcome.exitCode,
      signal: bundle.outcome.signal
    },
    nodeVersion: safeNodeVersion.value,
    command: safeCommand?.value ?? null,
    hypotheses,
    timeline: safeTimeline,
    sanitisation: {
      appliedBeforeRendering: true,
      replacementCount: notices.length,
      categories: [...new Set(notices)].sort(),
      excludedByBundleContract: ["unselected files"],
      transformedBeforeRendering: [
        "environment-shaped object values",
        "values stored under sensitive field names",
        "credential and path patterns in strings"
      ]
    },
    limitations: [
      "The report ranks patterns in supplied artefacts and does not establish a single root cause.",
      "Operating-system and process-supervisor records were not collected by this analyser."
    ]
  };
}

export const recognisedCategories = Object.freeze(RULES.map((rule) => rule.category));
