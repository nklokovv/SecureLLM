import { detectInjection } from "./injectionPatterns.js";

export interface OutputViolation {
  ruleId: string;
  reason: string;
}

const SK_KEY_RE = /\bsk-[A-Za-z0-9]{20,}\b/;
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/;
const AWS_KEY_RE = /\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b/;
/** Model compliance JSON dumping known config / env key names */
const CONFIG_LEAK_RE =
  /\b(MONGODB_URI|REDIS_URL|DATABASE_URL|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b\s*["':=]/i;

export function validateLlmOutput(content: string): OutputViolation | null {
  if (SK_KEY_RE.test(content)) {
    return { ruleId: "OUT-SECRET-001", reason: "OpenAI-style API key detected in output" };
  }
  if (JWT_RE.test(content)) {
    return { ruleId: "OUT-SECRET-002", reason: "JWT-shaped secret detected in output" };
  }
  if (AWS_KEY_RE.test(content)) {
    return { ruleId: "OUT-SECRET-003", reason: "AWS access key detected in output" };
  }
  if (CONFIG_LEAK_RE.test(content)) {
    return {
      ruleId: "OUT-SECRET-004",
      reason: "Configuration or environment variable names/values detected in output",
    };
  }

  const injectionEcho = detectInjection(content);
  if (injectionEcho) {
    return {
      ruleId: "OUT-ECHO-001",
      reason: `LLM output echoed injection pattern (${injectionEcho.ruleId})`,
    };
  }

  return null;
}
