import { Router } from "express";
import type { Env } from "../config/env.js";
import { pingMongo } from "../db/mongo.js";
import { pingRedis } from "../db/redis.js";
import { isProviderReady } from "../providers/index.js";

export function createHealthRouter(env: Env): Router {
  const router = Router();

  router.get("/healthz", async (_req, res) => {
    const [mongo, redis] = await Promise.all([pingMongo(), pingRedis()]);
    const provider = isProviderReady(env);

    const healthy = mongo && redis;
    const status = healthy ? 200 : 503;

    res.status(status).json({
      status: healthy ? "ok" : "degraded",
      checks: {
        mongo,
        redis,
        provider: {
          openai: provider,
          ready: provider,
        },
      },
    });
  });

  return router;
}
