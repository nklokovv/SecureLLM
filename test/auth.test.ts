import { describe, it, expect } from "vitest";
import { hashApiKey } from "../src/utils/hash.js";
import { constantTimeEqual } from "../src/utils/constantTime.js";

describe("authentication helpers", () => {
  it("hashes API keys deterministically", () => {
    const h1 = hashApiKey("test-key-123");
    const h2 = hashApiKey("test-key-123");
    expect(h1).toBe(h2);
    expect(h1).not.toBe("test-key-123");
  });

  it("constant-time compare matches equal strings", () => {
    const hash = hashApiKey("secret");
    expect(constantTimeEqual(hash, hash)).toBe(true);
  });

  it("constant-time compare rejects different strings", () => {
    expect(constantTimeEqual(hashApiKey("a"), hashApiKey("b"))).toBe(false);
  });

  it("constant-time compare rejects different lengths safely", () => {
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
  });
});
