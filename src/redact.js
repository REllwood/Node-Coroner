const SECRET_PATTERNS = [
  { label: "bearer credential", expression: /\bBearer\s+[A-Za-z0-9._~+\/-]{8,}/gi },
  { label: "named credential", expression: /\b(api[_-]?key|token|secret|password)\s*[=:]\s*[^\s,;]+/gi },
  {
    label: "environment assignment",
    expression:
      /(^|[\s"'(,;])([A-Za-z_][A-Za-z0-9_]{0,63})\s*=\s*(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s]+)/gm,
    replacement: (_match, prefix, key) =>
      `${prefix}${key}=[redacted environment value]`
  },
  { label: "Unix path", expression: /(?:^|[\s"'(])\/(?:Users|home|var|opt|srv|tmp)\/[^\s"')]+/g },
  { label: "Windows path", expression: /\b[A-Za-z]:\\(?:[^\s"']+\\)*[^\s"']*/g }
];

export function sanitiseText(input) {
  let value = String(input);
  const redactions = [];
  for (const pattern of SECRET_PATTERNS) {
    value = value.replace(pattern.expression, (match, ...captures) => {
      redactions.push(pattern.label);
      if (pattern.replacement) {
        return pattern.replacement(match, ...captures);
      }
      const prefix = match.startsWith("/") || /^[A-Za-z]:\\/.test(match) ? "" : match[0].match(/[\s"'(]/)?.[0] ?? "";
      return `${prefix}[redacted ${pattern.label}]`;
    });
  }
  return { value, redactions };
}

function protectedFieldCategory(key) {
  const normalised = String(key).toLowerCase().replaceAll(/[^a-z0-9]/g, "");
  if (
    ["env", "environment", "environmentvariables", "processenv"].includes(
      normalised
    )
  ) {
    return "environment values";
  }
  if (
    /(api.?key|authori[sz]ation|cookie|credential|passw(or)?d|secret|token)/i.test(
      String(key)
    )
  ) {
    return "sensitive field";
  }
  return undefined;
}

export function sanitiseValue(value, notices) {
  if (typeof value === "string") {
    const result = sanitiseText(value);
    notices.push(...result.redactions);
    return result.value;
  }
  if (Array.isArray(value)) return value.slice(0, 1_000).map((item) => sanitiseValue(item, notices));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).slice(0, 1_000).map(([key, item]) => {
        const safeKey = sanitiseText(key);
        notices.push(...safeKey.redactions);
        const protectedCategory = protectedFieldCategory(key);
        if (protectedCategory) {
          notices.push(protectedCategory);
          return [safeKey.value, `[redacted ${protectedCategory}]`];
        }
        return [safeKey.value, sanitiseValue(item, notices)];
      })
    );
  }
  return value;
}
