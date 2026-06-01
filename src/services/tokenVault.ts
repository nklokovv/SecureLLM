import { getRedis } from "../db/redis.js";
import type { Env } from "../config/env.js";
import type { PiiSpan } from "../security/pii.js";

export interface VaultEntry {
  token: string;
  original: string;
  category: string;
}

function vaultKey(correlationId: string): string {
  return `pii:vault:${correlationId}`;
}

export async function storePiiVault(
  env: Env,
  correlationId: string,
  spans: PiiSpan[],
): Promise<VaultEntry[]> {
  if (spans.length === 0) return [];

  const redis = getRedis();
  const key = vaultKey(correlationId);
  const entries: VaultEntry[] = spans.map((s) => ({
    token: s.token,
    original: s.original,
    category: s.category,
  }));

  await redis.set(key, JSON.stringify(entries), "EX", env.TOKEN_VAULT_TTL_SECONDS);
  return entries;
}

export async function getPiiVault(correlationId: string): Promise<VaultEntry[] | null> {
  const redis = getRedis();
  const raw = await redis.get(vaultKey(correlationId));
  if (!raw) return null;
  return JSON.parse(raw) as VaultEntry[];
}

export function restoreFromVault(text: string, entries: VaultEntry[]): string {
  let result = text;
  for (const entry of entries) {
    result = result.split(entry.token).join(entry.original);
  }
  return result;
}
