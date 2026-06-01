import { vi, describe, it, expect, beforeEach } from "vitest";
import type { ChatRequest } from "../src/providers/openai.js";
import type { AuditRecordInput } from "../src/services/auditService.js";
import type { VaultEntry } from "../src/services/tokenVault.js";
import type { CorpusHarnessState } from "./helpers/corpusHarness.js";

const harness = vi.hoisted(
  (): CorpusHarnessState => ({
    auditStore: [],
    vaultStore: new Map(),
    lastChatRequest: null,
    chatResponse: {
      content: "Benign assistant reply.",
      model: "gpt-4o-2024-08-06",
      usage: { prompt_tokens: 1, completion_tokens: 1 },
    },
  }),
);

vi.mock("../src/middleware/auth.js", () => ({
  authenticate: vi.fn(
    (
      req: {
        header: (n: string) => string | undefined;
        apiKeyDoc?: {
          keyId: string;
          keyHash: string;
          role: "client" | "admin";
          rateLimitPerMinute: null;
        };
      },
      res: { status: (n: number) => { json: (b: unknown) => void } },
      next: () => void,
    ) => {
      const raw = req.header("x-api-key");
      if (raw === "test-client-key") {
        req.apiKeyDoc = {
          keyId: "client-test",
          keyHash: "hash-client",
          role: "client",
          rateLimitPerMinute: null,
        };
        next();
        return;
      }
      if (raw === "test-admin-key") {
        req.apiKeyDoc = {
          keyId: "admin-test",
          keyHash: "hash-admin",
          role: "admin",
          rateLimitPerMinute: null,
        };
        next();
        return;
      }
      res.status(401).json({ error: "Invalid API key" });
    },
  ),
  requireAdmin: vi.fn(
    (
      req: { apiKeyDoc?: { role: string } },
      res: { status: (n: number) => { json: (b: unknown) => void } },
      next: () => void,
    ) => {
      if (req.apiKeyDoc?.role === "admin") next();
      else res.status(403).json({ error: "Admin role required" });
    },
  ),
}));

vi.mock("../src/services/rateLimitService.js", () => ({
  checkRateLimit: vi.fn(async () => ({ allowed: true, remaining: 99 })),
}));

vi.mock("../src/services/auditService.js", () => ({
  writeAuditLog: vi.fn(async (input: AuditRecordInput) => {
    harness.auditStore.push({ ...input, timestamp: new Date() });
  }),
  queryAuditLogs: vi.fn(async (since: Date, limit: number) => {
    return harness.auditStore
      .filter((e) => e.timestamp >= since)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit)
      .map((e) => ({
        timestamp: e.timestamp,
        correlationId: e.correlationId,
        apiKeyId: e.apiKeyId,
        llmModel: e.llmModel,
        requestHash: "mock-request-hash",
        responseHash: e.responseBody !== null ? "mock-response-hash" : null,
        detectedThreats: e.detectedThreats,
        latencyMs: e.latencyMs,
        status: e.status,
        httpStatus: e.httpStatus,
        message: e.message,
      }));
  }),
}));

vi.mock("../src/services/tokenVault.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/services/tokenVault.js")>();
  return {
    ...actual,
    storePiiVault: vi.fn(
      async (
        _env: unknown,
        correlationId: string,
        spans: Array<{ token: string; original: string; category: string }>,
      ) => {
        const entries: VaultEntry[] = spans.map((s) => ({
          token: s.token,
          original: s.original,
          category: s.category,
        }));
        harness.vaultStore.set(correlationId, entries);
        return entries;
      },
    ),
    getPiiVault: vi.fn(async (correlationId: string) => {
      return harness.vaultStore.get(correlationId) ?? null;
    }),
  };
});

vi.mock("../src/providers/index.js", () => ({
  isProviderReady: vi.fn(() => true),
  isModelSupported: vi.fn((model: string) => model === "gpt-4o"),
  supportedModels: vi.fn(() => ["gpt-4o"]),
  chatCompletion: vi.fn(async (_env: unknown, req: ChatRequest) => {
    harness.lastChatRequest = req;
    return harness.chatResponse;
  }),
}));

import request from "supertest";
import { restoreFromVault } from "../src/services/tokenVault.js";
import { INJ_CORPUS, PII_CORPUS, INJ_ECHO_CORPUS } from "./corpus/entries.js";
import {
  resetHarnessState,
  getTestApp,
  CLIENT_KEY,
  ADMIN_KEY,
  chatBody,
  getAuditByCorrelation,
} from "./helpers/corpusHarness.js";

describe("Corpus acceptance criteria", () => {
  beforeEach(() => {
    resetHarnessState(harness);
  });

  describe("INJ-* — HTTP 400 and audit identifies firing rule", () => {
    for (const row of INJ_CORPUS) {
      it(`blocks ${row.ruleId} (${row.label})`, async () => {
        const app = await getTestApp();
        const res = await request(app)
          .post("/v1/chat")
          .set("x-api-key", CLIENT_KEY)
          .send(chatBody(row.payload));

        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({
          error: "Prompt injection detected",
          ruleId: row.ruleId,
        });

        const entry = harness.auditStore[harness.auditStore.length - 1];
        expect(entry).toBeDefined();
        expect(entry!.status).toBe("blocked");
        expect(entry!.httpStatus).toBe(400);
        expect(entry!.detectedThreats).toContain(row.ruleId);
        expect(entry!.message).toContain(row.ruleId);
        expect(harness.lastChatRequest).toBeNull();
      });

      it(`blocks ${row.ruleId} variation (${row.variation.kind})`, async () => {
        const app = await getTestApp();
        const res = await request(app)
          .post("/v1/chat")
          .set("x-api-key", CLIENT_KEY)
          .send(chatBody(row.variation.payload));

        expect(res.status).toBe(400);
        expect(res.body.ruleId).toBe(row.ruleId);

        const entry = harness.auditStore[harness.auditStore.length - 1];
        expect(entry.detectedThreats).toContain(row.ruleId);
      });
    }
  });

  describe("PII-* — redacted to LLM; originals only via audit vault", () => {
    for (const row of PII_CORPUS) {
      const runPiiCase = async (
        content: string,
        label: string,
        secrets: string[] = row.secrets,
      ) => {
        const app = await getTestApp();
        const res = await request(app)
          .post("/v1/chat")
          .set("x-api-key", CLIENT_KEY)
          .send(chatBody(content));

        expect(res.status, `${row.category} ${label}`).toBe(200);
        expect(res.body.correlationId).toBeTruthy();
        expect(harness.lastChatRequest).not.toBeNull();

        const sent = harness.lastChatRequest!.messages.map((m) => m.content).join("\n");
        for (const secret of secrets) {
          expect(sent, `${row.category} must not forward: ${secret}`).not.toContain(secret);
        }
        expect(sent).toMatch(new RegExp(`\\[${row.category}_`));

        const audit = getAuditByCorrelation(harness, res.body.correlationId as string);
        expect(audit).toBeDefined();
        expect(audit!.status).toBe("allowed");
        expect(audit!.detectedThreats).toContain(row.category);

        const auditRes = await request(app)
          .get("/v1/audit")
          .query({ since: new Date(0).toISOString(), limit: 10 })
          .set("x-api-key", ADMIN_KEY);

        expect(auditRes.status).toBe(200);
        const entry = auditRes.body.entries.find(
          (e: { correlationId: string }) => e.correlationId === res.body.correlationId,
        );
        expect(entry?.piiVault?.length).toBeGreaterThan(0);
        const vaultEntry = entry.piiVault.find(
          (v: { category: string }) => v.category === row.category,
        );
        expect(vaultEntry).toBeDefined();
        expect(restoreFromVault(sent, entry.piiVault)).toContain(vaultEntry.original);
      };

      it(`redacts and vaults ${row.category} (${row.label})`, async () => {
        await runPiiCase(row.payload, "primary");
      });

      it(`redacts ${row.category} with ${row.variation.kind} variation`, async () => {
        await runPiiCase(
          row.variation.payload,
          "variation",
          row.variation.secrets ?? row.secrets,
        );
      });
    }
  });

  describe("OUT-ECHO-001 — stubbed model echoes each INJ-* payload", () => {
    for (const row of INJ_ECHO_CORPUS) {
      it(`rejects echoed ${row.ruleId} (${row.label})`, async () => {
        harness.chatResponse = {
          content: row.stubbedReply,
          model: "gpt-4o-2024-08-06",
          usage: { prompt_tokens: 1, completion_tokens: 1 },
        };

        const app = await getTestApp();
        const res = await request(app)
          .post("/v1/chat")
          .set("x-api-key", CLIENT_KEY)
          .send(chatBody("What is two plus two?"));

        expect(res.status).toBe(502);
        expect(res.body).toMatchObject({
          error: "Output validation failed",
          ruleId: "OUT-ECHO-001",
        });
        expect(res.body.reason).toContain(row.ruleId);

        const entry = harness.auditStore[harness.auditStore.length - 1];
        expect(entry.status).toBe("blocked");
        expect(entry.httpStatus).toBe(502);
        expect(entry.detectedThreats).toContain("OUT-ECHO-001");
        expect(entry.message).toContain(row.ruleId);
      });
    }
  });

  describe("Model availability — no silent provider substitution", () => {
    it("rejects claude-3-5-sonnet with 400 and never calls the provider", async () => {
      const app = await getTestApp();
      const res = await request(app)
        .post("/v1/chat")
        .set("x-api-key", CLIENT_KEY)
        .send({
          model: "claude-3-5-sonnet",
          messages: [{ role: "user", content: "Hello" }],
          max_tokens: 64,
        });

      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({
        error: "Model not available",
        model: "claude-3-5-sonnet",
        supported: ["gpt-4o"],
      });
      expect(harness.lastChatRequest).toBeNull();

      const entry = harness.auditStore[harness.auditStore.length - 1];
      expect(entry.httpStatus).toBe(400);
      expect(entry.llmModel).toBe("claude-3-5-sonnet");
      expect(entry.message).toContain("claude-3-5-sonnet");
    });

    it("serves gpt-4o normally", async () => {
      const app = await getTestApp();
      const res = await request(app)
        .post("/v1/chat")
        .set("x-api-key", CLIENT_KEY)
        .send(chatBody("Hello"));

      expect(res.status).toBe(200);
      expect(harness.lastChatRequest).not.toBeNull();
      expect(harness.lastChatRequest!.model).toBe("gpt-4o");
    });
  });
});
