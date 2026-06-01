/** Must contain @ and a dot in the domain part. */
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

export function isValidEmailFormat(value: string): boolean {
  return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(value);
}

export function findEmailSpans(text: string): Array<{ start: number; end: number; original: string }> {
  const spans: Array<{ start: number; end: number; original: string }> = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(EMAIL_RE.source, EMAIL_RE.flags);
  while ((m = re.exec(text)) !== null) {
    if (isValidEmailFormat(m[0])) {
      spans.push({
        start: m.index,
        end: m.index + m[0].length,
        original: m[0],
      });
    }
  }
  return spans;
}
