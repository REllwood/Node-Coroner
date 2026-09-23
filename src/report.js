function inline(value) {
  return String(value)
    .replaceAll(/\r?\n/g, " ")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll(/[\\`*_[\]{}()#+.!|:@]/g, (character) => {
      return `&#${character.codePointAt(0)};`;
    });
}

export function toText(report) {
  const outcome =
    report.observedOutcome.status === "clean-exit"
      ? "Observed outcome: clean exit."
      : report.observedOutcome.status === "successful-exit-with-contradictory-evidence"
        ? "Observed outcome: successful zero exit with contradictory diagnostic evidence."
        : `Observed outcome: exit=${report.observedOutcome.exitCode ?? "none"}, signal=${report.observedOutcome.signal ?? "none"}.`;
  const lines = [outcome];
  if (report.hypotheses.length === 0 && report.observedOutcome.status !== "clean-exit") {
    lines.push("No recognised termination pattern had enough supplied evidence.");
  }
  for (const hypothesis of report.hypotheses) {
    lines.push(
      `[${hypothesis.confidence}] ${hypothesis.title} (${hypothesis.ruleId})`,
      `  ${hypothesis.explanation}`,
      `  Evidence: ${hypothesis.supports.join(", ")}`,
      `  Next: ${hypothesis.nextCollectionStep}`
    );
  }
  lines.push(`Indexed ${report.timeline.length} sanitised evidence record(s).`);
  return lines.join("\n");
}

export function toMarkdown(report) {
  const lines = [
    "# Node Coroner incident report",
    "",
    report.observedOutcome.status === "clean-exit"
      ? "Observed outcome: clean exit; no incident hypothesis was manufactured."
      : report.observedOutcome.status === "successful-exit-with-contradictory-evidence"
        ? "Observed outcome: successful zero exit with contradictory diagnostic evidence; hypotheses below remain explicitly contradicted."
        : `Observed outcome: exit code ${inline(report.observedOutcome.exitCode ?? "not recorded")}, signal ${inline(report.observedOutcome.signal ?? "not recorded")}.`,
    ""
  ];
  if (report.hypotheses.length === 0) lines.push("No recognised termination hypothesis is supported by the supplied evidence.", "");
  for (const hypothesis of report.hypotheses) {
    lines.push(
      `## ${inline(hypothesis.title)}`,
      "",
      `Rule: ${inline(hypothesis.ruleId)}; confidence: ${inline(hypothesis.confidence)}.`,
      "",
      inline(hypothesis.explanation),
      "",
      `Supporting evidence: ${hypothesis.supports.map((id) => `\`${inline(id)}\``).join(", ")}.`,
      ""
    );
    if (hypothesis.contradicts.length > 0) {
      lines.push(
        `Contradictory evidence: ${hypothesis.contradicts.map(inline).join(" ")}`,
        ""
      );
    }
    if (hypothesis.missing.length > 0) {
      lines.push(`Missing evidence: ${hypothesis.missing.map(inline).join(" ")}`, "");
    }
    lines.push(`Next collection step: ${inline(hypothesis.nextCollectionStep)}`, "");
  }
  lines.push("## Evidence timeline", "");
  for (const item of report.timeline) {
    const excerpt = item.text ?? JSON.stringify(item.data);
    lines.push(`- ${inline(item.timestamp)} [${inline(item.id)}] ${inline(item.source)}: ${inline(excerpt).slice(0, 500)}`);
  }
  lines.push(
    "",
    `Sanitisation replacements: ${inline(report.sanitisation.replacementCount)}.`,
    "",
    ...report.limitations.map((item) => `- ${inline(item)}`),
    ""
  );
  return lines.join("\n");
}
