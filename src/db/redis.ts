import { Redis } from "ioredis";
import type { Env } from "../config/env.js";
import { logger } from "../utils/logger.js";

let client: Redis | null = null;

export function getRedis(): Redis {
  if (!client) {
    throw new Error("Redis not initialized");
  }
  return client;
}

export async function connectRedis(env: Env): Promise<void> {
  if (client) return;
  client = new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: 3,
  });
  await client.ping();
  logger.info("Redis connected");
}

export async function pingRedis(): Promise<boolean> {
  if (!client) return false;
  try {
    const result = await client.ping();
    return result === "PONG";
  } catch {
    return false;
  }
}

export async function disconnectRedis(): Promise<void> {
  if (client) {
    await client.quit();
    client = null;
  }
}
