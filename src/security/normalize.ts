const ZERO_WIDTH = /[\u200B-\u200D\uFEFF]/g;

const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  "$": "s",
};

export function collapseWhitespace(text: string): string {
  return text.replace(ZERO_WIDTH, "").replace(/\s+/g, " ").trim();
}

export function deLeet(text: string): string {
  return text
    .split("")
    .map((c) => LEET_MAP[c] ?? c)
    .join("");
}

export function tryDecodeBase64(text: string): string {
  const b64Pattern = /[A-Za-z0-9+/]{16,}={0,2}/g;
  return text.replace(b64Pattern, (match) => {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      if (/^[\x20-\x7E\u00A0-\u024F\s]+$/.test(decoded)) {
        return `${match} ${decoded}`;
      }
    } catch {
      /* ignore */
    }
    return match;
  });
}

export function tryDecodeUrl(text: string): string {
  return text.replace(/%[0-9A-Fa-f]{2}/g, (seq) => {
    try {
      return decodeURIComponent(seq);
    } catch {
      return seq;
    }
  });
}

export function normalizeForDetection(text: string): string {
  let n = collapseWhitespace(text);
  n = tryDecodeUrl(n);
  n = tryDecodeBase64(n);
  n = deLeet(n);
  return n.toLowerCase();
}
