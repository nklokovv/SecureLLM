import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../src/db/redis.js", () => {
  const store = new Map<string, number[]>();

  return {
    getRedis: () => ({
      multi: () => {
        const cmds: Array<() => Promise<unknown>> = [];
        const api = {
          zremrangebyscore: () => {
            cmds.push(async () => "OK");
            return api;
          },
          zadd: (_k: string, score: number) => {
            cmds.push(async () => {
              const key = "ratelimit:test";
              const arr = store.get(key) ?? [];
              arr.push(score);
              store.set(key, arr);
              return 1;
            });
            return api;
          },
          zcard: () => {
            cmds.push(async () => {
              const arr = store.get("ratelimit:test") ?? [];
              return arr.length;
            });
            return api;
          },
          pexpire: () => {
            cmds.push(async () => "OK");
            return api;
          },
          exec: async () => {
            const results: Array<[null, unknown]> = [];
            for (const cmd of cmds) {
              results.push([null, await cmd()]);
            }
            return results;
          },
        };
        return api;
      },
    }),
  };
});

import { checkRateLimit } from "../src/services/rateLimitService.js";

describe("rate limiting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("allows requests under limit", async () => {
    const result = await checkRateLimit("test-key", 30);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
  });
});
