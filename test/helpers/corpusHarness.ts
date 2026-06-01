import type { Application } from "express";
import type { ChatRequest, ChatResponse } from "../../src/providers/openai.js";
import type { AuditRecordInput } from "../../src/services/auditService.js";
import type { VaultEntry } from "../../src/services/tokenVault.js";

export interface StoredAudit extends AuditRecordInput {
  timestamp: Date;
}

export interface CorpusHarnessState {
  auditStore: StoredAudit[];
  vaultStore: Map<string, VaultEntry[]>;
  lastChatRequest: ChatRequest | null;
  chatResponse: ChatResponse;
}

export const TEST_ENV = {
  PORT: 3001,
  NODE_ENV: "test" as const,
  MONGODB_URI: "mongodb://localhost:27017/securellm-test",
  REDIS_URL: "redis://localhost:6379",
  OPENAI_API_KEY: "sk-test-key-for-corpus",
  DEFAULT_RATE_LIMIT: 30,
  TOKEN_VAULT_TTL_SECONDS: 3600,
};

export const CLIENT_KEY = "test-client-key";
export const ADMIN_KEY = "test-admin-key";

let appInstance: Application | null = null;

export function createHarnessState(): CorpusHarnessState {
  return {
    auditStore: [],
    vaultStore: new Map(),
    lastChatRequest: null,
    chatResponse: {
      content: "Benign assistant reply.",
      model: "gpt-4o-2024-08-06",
      usage: { prompt_tokens: 1, completion_tokens: 1 },
    },
  };
}

export function resetHarnessState(state: CorpusHarnessState): void {
  state.auditStore.length = 0;
  state.vaultStore.clear();
  state.lastChatRequest = null;
  state.chatResponse = {
    content: "Benign assistant reply.",
    model: "gpt-4o-2024-08-06",
    usage: { prompt_tokens: 1, completion_tokens: 1 },
  };
}

export async function getTestApp(): Promise<Application> {
  if (!appInstance) {
    const { createApp } = await import("../../src/app.js");
    appInstance = createApp(TEST_ENV);
  }
  return appInstance;
}

export function getAuditByCorrelation(
  state: CorpusHarnessState,
  correlationId: string,
): StoredAudit | undefined {
  return state.auditStore.find((e) => e.correlationId === correlationId);
}

export function chatBody(content: string): {
  model: "gpt-4o";
  messages: Array<{ role: "user"; content: string }>;
  max_tokens: number;
} {
  return {
    model: "gpt-4o",
    messages: [{ role: "user", content }],
    max_tokens: 64,
  };
}
