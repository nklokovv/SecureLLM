import { getRedis } from "../db/redis.js";

const WINDOW_MS = 60_000;

export async function checkRateLimit(
  apiKeyId: string,
  limitPerMinute: number,
): Promise<{ allowed: boolean; remaining: number }> {
  const redis = getRedis();
  const key = `ratelimit:${apiKeyId}`;
  const now = Date.now();
  const windowStart = now - WINDOW_MS;

  const multi = redis.multi();
  multi.zremrangebyscore(key, 0, windowStart);
  multi.zadd(key, now, `${now}`);
  multi.zcard(key);
  multi.pexpire(key, WINDOW_MS);
  const results = await multi.exec();

  const count = (results?.[2]?.[1] as number) ?? 0;
  const allowed = count <= limitPerMinute;
  const remaining = Math.max(0, limitPerMinute - count);

  return { allowed, remaining };
}
