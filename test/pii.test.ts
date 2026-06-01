import { describe, it, expect } from "vitest";
import {
  findPiiSpans,
  redactMessageContent,
  isValidIsraeliId,
  redactText,
} from "../src/security/pii.js";

const VALID_IL_ID = "123456782";

describe("PII redaction", () => {
  it("validates Israeli ID check digit", () => {
    expect(isValidIsraeliId(VALID_IL_ID)).toBe(true);
    expect(isValidIsraeliId("123456789")).toBe(false);
  });

  it("redacts email in prose", () => {
    const { redacted, spans } = redactMessageContent(
      "Contact me at alice@example.com for details.",
    );
    expect(spans.some((s) => s.category === "PII-EMAIL")).toBe(true);
    expect(redacted).not.toContain("alice@example.com");
    expect(redacted).toMatch(/\[PII-EMAIL_/);
  });

  it("redacts IL and intl phones", () => {
    const text = "Call 050-1234567 or +1 415 555 0100";
    const spans = findPiiSpans(text);
    expect(spans.some((s) => s.category === "PII-PHONE-IL")).toBe(true);
    expect(spans.some((s) => s.category === "PII-PHONE-INTL")).toBe(true);
    const redacted = redactText(text, spans);
    expect(redacted).not.toContain("050-1234567");
  });

  it("redacts Israeli national ID", () => {
    const { redacted, spans } = redactMessageContent(`ID number ${VALID_IL_ID} please`);
    expect(spans.some((s) => s.category === "PII-IL-ID")).toBe(true);
    expect(redacted).not.toContain(VALID_IL_ID);
  });

  it("redacts multiple individuals in one message", () => {
    const text =
      "Alice: alice@a.com, Bob: bob@b.com, phones 0501111111 and +44 20 7946 0958";
    const { redacted, spans } = redactMessageContent(text);
    expect(spans.filter((s) => s.category === "PII-EMAIL").length).toBeGreaterThanOrEqual(2);
    expect(redacted).not.toContain("alice@a.com");
    expect(redacted).not.toContain("bob@b.com");
  });

  it("redacts person name fields in JSON", () => {
    const json = JSON.stringify({
      customer: { name: "Yossi Cohen", email: "x@y.com" },
    });
    const { redacted, spans } = redactMessageContent(json);
    expect(spans.some((s) => s.category === "PII-NAME" && s.original === "Yossi Cohen")).toBe(true);
    const parsed = JSON.parse(redacted) as { customer: { name: string } };
    expect(parsed.customer.name).toMatch(/\[PII-NAME_/);
  });

  it("redacts PII inside customer JSON payload (Appendix-style)", () => {
    const json = JSON.stringify({
      customer: {
        name: "[REDACTED]",
        id_number: "111111118",
        email: "a.test@example.com",
        phone: "+1-202-555-0143",
      },
      request: "summarise account history",
    });
    const { redacted, spans } = redactMessageContent(json);
    expect(spans.some((s) => s.category === "PII-IL-ID" && s.original === "111111118")).toBe(true);
    expect(spans.some((s) => s.category === "PII-EMAIL")).toBe(true);
    expect(spans.some((s) => s.category === "PII-PHONE-INTL")).toBe(true);
    const parsed = JSON.parse(redacted) as {
      customer: { id_number: string; email: string; phone: string };
    };
    expect(parsed.customer.email).toMatch(/\[PII-EMAIL_/);
    expect(parsed.customer.phone).toMatch(/\[PII-PHONE-INTL_/);
    expect(parsed.customer.id_number).toMatch(/\[PII-IL-ID_/);
    expect(redacted).not.toContain("a.test@example.com");
  });

  it("redacts PII inside JSON in-place", () => {
    const json = JSON.stringify({
      user: { email: "test@corp.io", id: VALID_IL_ID },
    });
    const { redacted, spans } = redactMessageContent(json);
    expect(spans.length).toBeGreaterThanOrEqual(2);
    const parsed = JSON.parse(redacted) as { user: { email: string; id: string } };
    expect(parsed.user.email).toMatch(/\[PII-EMAIL_/);
    expect(parsed.user.id).toMatch(/\[PII-IL-ID_/);
    expect(JSON.parse(redacted)).toBeTruthy();
  });

  it("redacts multiple people with mixed IL phones and one valid national ID", () => {
    const text = `Hi, I'm reaching out because Shira (shira+work@example.co.il,
052-555-0199) asked me to share my contact:
shaul.barak@example.com, phone 03-555-0184.
Her ID is 123456782, mine is 987654321.`;
    const { redacted, spans } = redactMessageContent(text);
    expect(spans.filter((s) => s.category === "PII-EMAIL")).toHaveLength(2);
    expect(spans.filter((s) => s.category === "PII-PHONE-IL")).toHaveLength(2);
    expect(spans.filter((s) => s.category === "PII-IL-ID")).toHaveLength(2);
    expect(redacted).not.toContain("shira+work@example.co.il");
    expect(redacted).not.toContain("052-555-0199");
    expect(redacted).not.toContain("03-555-0184");
    expect(redacted).not.toContain("123456782");
    expect(redacted).not.toContain("987654321");
  });

  it("redacts profile update with email, IL mobile, and national ID", () => {
    const text = `Please update my profile. My contact details are:
email: yossi.cohen@example.com
mobile: +972-50-555-0142
national ID: 000000018
Confirm when the change is applied.`;
    const { redacted, spans } = redactMessageContent(text);
    expect(spans.some((s) => s.category === "PII-EMAIL")).toBe(true);
    expect(spans.some((s) => s.category === "PII-PHONE-IL")).toBe(true);
    expect(spans.some((s) => s.category === "PII-IL-ID")).toBe(true);
    expect(redacted).not.toContain("yossi.cohen@example.com");
    expect(redacted).not.toContain("+972-50-555-0142");
    expect(redacted).not.toContain("000000018");
  });

  it("tokens are unique and reversible with vault entries", () => {
    const { redacted, spans } = redactMessageContent("Email: a@b.co and a@b.co duplicate");
    const tokens = new Set(spans.map((s) => s.token));
    expect(tokens.size).toBe(spans.length);
    for (const span of spans) {
      expect(redacted).toContain(span.token);
    }
  });
});
