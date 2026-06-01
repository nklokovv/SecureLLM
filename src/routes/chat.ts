import { Router, type Request } from "express";
import { z } from "zod";
import type { Env } from "../config/env.js";
import { authenticate } from "../middleware/auth.js";
import { createRateLimitMiddleware } from "../middleware/rateLimit.js";
import { detectInjectionInMessages } from "../security/injectionPatterns.js";
import { redactMessageContent } from "../security/pii.js";
import { validateLlmOutput } from "../security/outputValidation.js";
import {
  chatCompletion,
  isProviderReady,
  isModelSupported,
  supportedModels,
} from "../providers/index.js";
import { writeAuditLog } from "../services/auditService.js";
import { storePiiVault } from "../services/tokenVault.js";

const chatBodySchema = z.object({
  model: z.enum(["claude-3-5-sonnet", "gpt-4o"]),
  messages: z
    .array(
      z.object({
        role: z.enum(["user", "assistant", "system"]),
        content: z.string().min(1),
      }),
    )
    .min(1),
  max_tokens: z.number().int().positive().max(8192).default(1024),
});

function latencyMs(req: Request): number {
  return Date.now() - (req.startTime ?? Date.now());
}

export function createChatRouter(env: Env): Router {
  const router = Router();
  const rateLimit = createRateLimitMiddleware(env);

  router.post("/v1/chat", authenticate, rateLimit, async (req, res, next) => {
    const correlationId = req.correlationId ?? "unknown";
    const apiKeyId = req.apiKeyDoc?.keyId ?? "unknown";
    const threats: string[] = req.detectedThreats ?? [];

    try {
      const parsed = chatBodySchema.safeParse(req.body);
      if (!parsed.success) {
        await writeAuditLog({
          correlationId,
          apiKeyId,
          llmModel: null,
          requestBody: req.body,
          responseBody: null,
          detectedThreats: threats,
          latencyMs: latencyMs(req),
          status: "blocked",
          httpStatus: 400,
          message: "Invalid request body",
        });
        res.status(400).json({ error: "Invalid request body", details: parsed.error.flatten() });
        return;
      }

      const { model, messages, max_tokens } = parsed.data;

      if (!isModelSupported(model)) {
        await writeAuditLog({
          correlationId,
          apiKeyId,
          llmModel: model,
          requestBody: parsed.data,
          responseBody: null,
          detectedThreats: threats,
          latencyMs: latencyMs(req),
          status: "error",
          httpStatus: 400,
          message: `Model not available: ${model}`,
        });
        res.status(400).json({
          error: "Model not available",
          model,
          supported: supportedModels(),
          hint: "This gateway is configured for OpenAI. Anthropic models are not wired; no silent substitution is performed.",
        });
        return;
      }

      const injection = detectInjectionInMessages(messages);
      if (injection) {
        threats.push(injection.ruleId);
        await writeAuditLog({
          correlationId,
          apiKeyId,
          llmModel: model,
          requestBody: parsed.data,
          responseBody: null,
          detectedThreats: threats,
          latencyMs: latencyMs(req),
          status: "blocked",
          httpStatus: 400,
          message: `Prompt injection detected: ${injection.ruleId}`,
        });
        res.status(400).json({
          error: "Prompt injection detected",
          ruleId: injection.ruleId,
          category: injection.category,
        });
        return;
      }

      const redactedMessages: Array<{ role: "user" | "assistant" | "system"; content: string }> =
        [];
      const allSpans = [];

      for (const msg of messages) {
        const { redacted, spans } = redactMessageContent(msg.content);
        allSpans.push(...spans);
        redactedMessages.push({ role: msg.role, content: redacted });
      }

      if (allSpans.length > 0) {
        await storePiiVault(env, correlationId, allSpans);
        for (const s of allSpans) {
          threats.push(s.category);
        }
      }

      if (!isProviderReady(env)) {
        await writeAuditLog({
          correlationId,
          apiKeyId,
          llmModel: model,
          requestBody: parsed.data,
          responseBody: null,
          detectedThreats: threats,
          latencyMs: latencyMs(req),
          status: "error",
          httpStatus: 503,
          message: "LLM provider not configured",
        });
        res.status(503).json({
          error: "LLM provider not configured",
          provider: "openai",
        });
        return;
      }

      let llmResponse;
      try {
        llmResponse = await chatCompletion(env, {
          model,
          messages: redactedMessages,
          max_tokens,
        });
      } catch (err) {
        await writeAuditLog({
          correlationId,
          apiKeyId,
          llmModel: model,
          requestBody: { ...parsed.data, messages: redactedMessages },
          responseBody: null,
          detectedThreats: threats,
          latencyMs: latencyMs(req),
          status: "error",
          httpStatus: 502,
          message: err instanceof Error ? err.message : "Provider error",
        });
        res.status(502).json({ error: "LLM provider error" });
        return;
      }

      const outputViolation = validateLlmOutput(llmResponse.content);
      if (outputViolation) {
        threats.push(outputViolation.ruleId);
        await writeAuditLog({
          correlationId,
          apiKeyId,
          llmModel: model,
          requestBody: { ...parsed.data, messages: redactedMessages },
          responseBody: { content: "[REDACTED]" },
          detectedThreats: threats,
          latencyMs: latencyMs(req),
          status: "blocked",
          httpStatus: 502,
          message: outputViolation.reason,
        });
        res.status(502).json({
          error: "Output validation failed",
          ruleId: outputViolation.ruleId,
          reason: outputViolation.reason,
        });
        return;
      }

      const responseBody = {
        model: llmResponse.model,
        message: { role: "assistant" as const, content: llmResponse.content },
        usage: llmResponse.usage,
        correlationId,
      };

      await writeAuditLog({
        correlationId,
        apiKeyId,
        llmModel: model,
        requestBody: { ...parsed.data, messages: redactedMessages },
        responseBody,
        detectedThreats: threats,
        latencyMs: latencyMs(req),
        status: "allowed",
        httpStatus: 200,
        message:
          allSpans.length > 0
            ? `PII redacted: ${allSpans.length} span(s) — originals in vault for correlation ${correlationId}`
            : undefined,
      });

      res.json(responseBody);
    } catch (err) {
      next(err);
    }
  });

  return router;
}
