/** Context phrases from Appendix / task corpus (prose and labels). */
export const IL_ID_CONTEXT_PATTERNS: RegExp[] = [
  /\bnational\s+id\b/i,
  /\bnational\s+identification\b/i,
  /\bid\s+number\b/i,
  /\bidentity\s+number\b/i,
  /\bteudat\s+zeh?ut\b/i,
  /\bמספר\s+זהות\b/i,
  /\b(?:her|his|my|your|their|our)\s+id\s+is\b/i,
  /\b(?:her|his|my|your|their)\s+identity\s+is\b/i,
  /\bmine\s+is\b/i,
  /\bid\s+is\b/i,
  /\bcontact\s+details\b/i,
];

/** JSON keys: redact any 9-digit value (checksum optional). */
export const IL_ID_STRICT_FIELD_KEY_RE =
  /^(id_number|national_id|nationalId|national_id_number|israeli_id|israeliId|teudat(?:_zehut)?|identity_number)$/i;

/** JSON key `id`: redact only when checksum validates. */
export const IL_ID_SHORT_FIELD_KEY_RE = /^id$/i;

export function isValidIsraeliId(value: string): boolean {
  const digits = value.replace(/\D/g, "");

  if (!/^\d{9}$/.test(digits)) {
    return false;
  }

  const sum = digits
    .split("")
    .map((char, index) => {
      const digit = Number(char);
      const weight = index % 2 === 0 ? 1 : 2;
      const product = digit * weight;

      return product > 9 ? product - 9 : product;
    })
    .reduce((acc, num) => acc + num, 0);

  return sum % 10 === 0;
}

export function hasIsraeliIdContext(text: string, start: number, end: number): boolean {
  const windowStart = Math.max(0, start - 100);
  const windowEnd = Math.min(text.length, end + 40);
  const window = text.slice(windowStart, windowEnd);
  return IL_ID_CONTEXT_PATTERNS.some((pattern) => pattern.test(window));
}

export function isIsraeliIdStrictFieldKey(key: string): boolean {
  return IL_ID_STRICT_FIELD_KEY_RE.test(key);
}

export function isIsraeliIdShortFieldKey(key: string): boolean {
  return IL_ID_SHORT_FIELD_KEY_RE.test(key);
}

export function shouldRedactIsraeliIdValue(
  value: string,
  options?: { fieldKey?: string; proseContextStart?: number; proseContextEnd?: number; fullText?: string },
): boolean {
  const digits = value.replace(/\D/g, "");
  if (!/^\d{9}$/.test(digits)) {
    return false;
  }

  if (isValidIsraeliId(digits)) {
    return true;
  }

  if (options?.fieldKey && isIsraeliIdStrictFieldKey(options.fieldKey)) {
    return true;
  }

  if (options?.fieldKey && isIsraeliIdShortFieldKey(options.fieldKey) && isValidIsraeliId(digits)) {
    return true;
  }

  if (
    options?.fullText !== undefined &&
    options.proseContextStart !== undefined &&
    options.proseContextEnd !== undefined &&
    hasIsraeliIdContext(options.fullText, options.proseContextStart, options.proseContextEnd)
  ) {
    return true;
  }

  return false;
}

export function findIsraeliIdCandidates(text: string): Array<{ start: number; end: number; original: string }> {
  const candidates: Array<{ start: number; end: number; original: string }> = [];
  const re = /\b\d{9}\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    candidates.push({
      start: m.index,
      end: m.index + m[0].length,
      original: m[0],
    });
  }
  return candidates;
}
