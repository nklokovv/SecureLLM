import type { Request, Response, NextFunction } from "express";
import type { Env } from "../config/env.js";
import { checkRateLimit } from "../services/rateLimitService.js";

export function createRateLimitMiddleware(env: Env) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.apiKeyDoc) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const limit =
      req.apiKeyDoc.rateLimitPerMinute ?? env.DEFAULT_RATE_LIMIT;

    try {
      const { allowed, remaining } = await checkRateLimit(req.apiKeyDoc.keyId, limit);
      res.setHeader("X-RateLimit-Limit", String(limit));
      res.setHeader("X-RateLimit-Remaining", String(remaining));

      if (!allowed) {
        res.status(429).json({ error: "Rate limit exceeded" });
        return;
      }
      next();
    } catch {
      res.status(503).json({ error: "Rate limit service unavailable" });
    }
  };
}
