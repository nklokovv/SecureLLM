import { describe, it, expect } from "vitest";
import { isModelSupported, supportedModels } from "../src/providers/index.js";

describe("provider model support", () => {
  it("supports gpt-4o", () => {
    expect(isModelSupported("gpt-4o")).toBe(true);
  });

  it("does not silently support claude-3-5-sonnet (OpenAI-only gateway)", () => {
    expect(isModelSupported("claude-3-5-sonnet")).toBe(false);
  });

  it("reports the supported model list", () => {
    expect(supportedModels()).toEqual(["gpt-4o"]);
  });
});
