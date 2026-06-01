import { randomBytes } from "node:crypto";
import type { PiiCategory, PiiSpan } from "./types.js";
import { findEmailSpans } from "./email.js";
import {
  findIsraeliIdCandidates,
  isIsraeliIdStrictFieldKey,
  shouldRedactIsraeliIdValue,
} from "./israeliId.js";
import { detectPhoneNumbers, toPiiPhoneCategory } from "./phone.js";
import { isAlreadyRedacted, redactStructuredNames } from "./names.js";

export { isValidIsraeliId } from "./israeliId.js";

function makeToken(category: PiiCategory, index: number): string {
  const suffix = randomBytes(4).toString("hex");
  return `[${category}_${index}_${suffix}]`;
}

function overlaps(a: { start: number; end: number }, b: { start: number; end: number }): boolean {
  return a.start < b.end && b.start < a.end;
}

function mergeNonOverlapping(
  spans: Array<Omit<PiiSpan, "token"> & { start: number; end: number }>,
): Array<Omit<PiiSpan, "token"> & { start: number; end: number }> {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const result: Array<Omit<PiiSpan, "token"> & { start: number; end: number }> = [];
  for (const span of sorted) {
    const last = result[result.length - 1];
    if (last && overlaps(span, last)) continue;
    result.push(span);
  }
  return result;
}

export function findPiiSpans(text: string): PiiSpan[] {
  const raw: Array<Omit<PiiSpan, "token"> & { start: number; end: number }> = [];

  for (const email of findEmailSpans(text)) {
    raw.push({ category: "PII-EMAIL", ...email });
  }

  for (const id of findIsraeliIdCandidates(text)) {
    if (
      shouldRedactIsraeliIdValue(id.original, {
        fullText: text,
        proseContextStart: id.start,
        proseContextEnd: id.end,
      })
    ) {
      raw.push({ category: "PII-IL-ID", ...id });
    }
  }

  const reserved = raw.map((s) => ({ start: s.start, end: s.end }));

  for (const phone of detectPhoneNumbers(text)) {
    const span = {
      category: toPiiPhoneCategory(phone.type),
      start: phone.start,
      end: phone.end,
      original: phone.original,
    };
    if (reserved.some((r) => overlaps(span, r))) continue;
    raw.push(span);
  }

  const merged = mergeNonOverlapping(raw);
  const counters: Record<PiiCategory, number> = {
    "PII-EMAIL": 0,
    "PII-PHONE-IL": 0,
    "PII-PHONE-INTL": 0,
    "PII-IL-ID": 0,
    "PII-NAME": 0,
  };

  return merged.map((span) => {
    const idx = counters[span.category]++;
    return { ...span, token: makeToken(span.category, idx) };
  });
}

export function redactText(text: string, spans: PiiSpan[]): string {
  if (spans.length === 0) return text;
  const positioned = spans.filter((s) => s.start < s.end);
  if (positioned.length === 0) return text;

  const sorted = [...positioned].sort((a, b) => b.start - a.start);
  let result = text;
  for (const span of sorted) {
    result = result.slice(0, span.start) + span.token + result.slice(span.end);
  }
  return result;
}

function redactJsonValue(
  key: string | undefined,
  value: unknown,
  allSpans: PiiSpan[],
): unknown {
  if (typeof value === "string") {
    if (key && (isIsraeliIdStrictFieldKey(key) || key.toLowerCase() === "id")) {
      if (
        shouldRedactIsraeliIdValue(value, { fieldKey: key }) &&
        !isAlreadyRedacted(value)
      ) {
        const token = makeToken("PII-IL-ID", allSpans.filter((s) => s.category === "PII-IL-ID").length);
        allSpans.push({
          category: "PII-IL-ID",
          start: 0,
          end: 0,
          original: value,
          token,
        });
        return token;
      }
    }

    const spans = findPiiSpans(value);
    allSpans.push(...spans);
    return redactText(value, spans);
  }

  if (Array.isArray(value)) {
    return value.map((item, i) => redactJsonValue(`${key ?? ""}[${i}]`, item, allSpans));
  }

  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = redactJsonValue(k, v, allSpans);
    }
    return out;
  }

  return value;
}

export function redactJsonStringValues(jsonText: string): { redacted: string; spans: PiiSpan[] } {
  const allSpans: PiiSpan[] = [];

  try {
    const parsed: unknown = JSON.parse(jsonText);
    const { value: afterNames, spans: nameSpans } = redactStructuredNames(parsed);
    allSpans.push(...nameSpans);

    const redacted = redactJsonValue(undefined, afterNames, allSpans);
    return { redacted: JSON.stringify(redacted), spans: allSpans };
  } catch {
    const spans = findPiiSpans(jsonText);
    return { redacted: redactText(jsonText, spans), spans };
  }
}

export function redactMessageContent(content: string): { redacted: string; spans: PiiSpan[] } {
  const trimmed = content.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const { redacted, spans } = redactJsonStringValues(content);
    return { redacted, spans };
  }
  const spans = findPiiSpans(content);
  return { redacted: redactText(content, spans), spans };
}
