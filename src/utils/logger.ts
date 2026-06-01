import pino from "pino";

const redactPaths = [
  "req.headers['x-api-key']",
  "req.headers.x-api-key",
  "OPENAI_API_KEY",
  "apiKey",
  "api_key",
  "authorization",
];

export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: {
    paths: redactPaths,
    censor: "[REDACTED]",
  },
});
