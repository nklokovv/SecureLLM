import OpenAI from "openai";
import type { Env } from "../config/env.js";

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  max_tokens: number;
}

export interface ChatResponse {
  content: string;
  model: string;
  usage?: { prompt_tokens: number; completion_tokens: number };
}

let client: OpenAI | null = null;

export function isProviderReady(env: Env): boolean {
  return Boolean(env.OPENAI_API_KEY && env.OPENAI_API_KEY.length > 0);
}

function getClient(env: Env): OpenAI {
  if (!isProviderReady(env)) {
    throw new Error("OpenAI provider not configured");
  }
  if (!client) {
    client = new OpenAI({ apiKey: env.OPENAI_API_KEY });
  }
  return client;
}

/** Models this gateway can actually serve. Only OpenAI is wired. */
const SUPPORTED_MODELS = new Set(["gpt-4o"]);

export function isModelSupported(model: string): boolean {
  return SUPPORTED_MODELS.has(model);
}

export function supportedModels(): string[] {
  return [...SUPPORTED_MODELS];
}

export async function chatCompletion(env: Env, req: ChatRequest): Promise<ChatResponse> {
  const openai = getClient(env);

  const response = await openai.chat.completions.create({
    model: req.model,
    messages: req.messages.map((m) => ({
      role: m.role,
      content: m.content,
    })),
    max_tokens: req.max_tokens,
  });

  const choice = response.choices[0];
  const content = choice?.message?.content ?? "";

  return {
    content,
    model: response.model,
    usage: response.usage
      ? {
          prompt_tokens: response.usage.prompt_tokens,
          completion_tokens: response.usage.completion_tokens,
        }
      : undefined,
  };
}
