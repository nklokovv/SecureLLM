import type { PhoneMatch, PhoneMatchType } from "./types.js";

const phoneCandidateRegex =
  /(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{1,4}\)?[\s.-]?){2,5}\d{3,4}(?!\d)/g;

export function normalizePhone(raw: string): string {
  return raw.replace(/[^\d+]/g, "");
}

export function isIsraeliMobile(normalized: string): boolean {
  if (/^05\d{8}$/.test(normalized)) {
    return true;
  }
  if (/^\+9725\d{8}$/.test(normalized)) {
    return true;
  }
  if (/^9725\d{8}$/.test(normalized)) {
    return true;
  }
  return false;
}

export function isIsraeliLandline(normalized: string): boolean {
  if (/^0[2-9]\d{7}$/.test(normalized)) {
    return true;
  }
  if (/^\+972[2-9]\d{7}$/.test(normalized)) {
    return true;
  }
  if (/^972[2-9]\d{7}$/.test(normalized)) {
    return true;
  }
  return false;
}

export function isInternationalPhone(normalized: string): boolean {
  return /^\+[1-9]\d{7,14}$/.test(normalized);
}

function toPiiPhoneCategory(type: PhoneMatchType): "PII-PHONE-IL" | "PII-PHONE-INTL" {
  return type === "international" ? "PII-PHONE-INTL" : "PII-PHONE-IL";
}

export function detectPhoneNumbers(text: string): PhoneMatch[] {
  const matches: PhoneMatch[] = [];

  for (const match of text.matchAll(phoneCandidateRegex)) {
    const original = match[0].trim();
    const start = match.index ?? 0;
    const end = start + match[0].length;
    const normalized = normalizePhone(original);

    if (isIsraeliMobile(normalized)) {
      matches.push({
        original,
        normalized: normalized.startsWith("+")
          ? normalized
          : normalized.startsWith("972")
            ? `+${normalized}`
            : `+972${normalized.slice(1)}`,
        type: "israeli_mobile",
        start,
        end,
      });
      continue;
    }

    if (isIsraeliLandline(normalized)) {
      matches.push({
        original,
        normalized: normalized.startsWith("+")
          ? normalized
          : normalized.startsWith("972")
            ? `+${normalized}`
            : `+972${normalized.slice(1)}`,
        type: "israeli_landline",
        start,
        end,
      });
      continue;
    }

    if (isInternationalPhone(normalized)) {
      matches.push({
        original,
        normalized,
        type: "international",
        start,
        end,
      });
    }
  }

  return matches;
}

export { toPiiPhoneCategory };
