import { loadEnv } from "./config/env.js";
import { connectMongo, disconnectMongo } from "./db/mongo.js";
import { connectRedis, disconnectRedis } from "./db/redis.js";
import { createApp } from "./app.js";
import { logger } from "./utils/logger.js";

async function main(): Promise<void> {
  const env = loadEnv();
  await connectMongo(env);
  await connectRedis(env);

  const app = createApp(env);
  const server = app.listen(env.PORT, () => {
    logger.info({ port: env.PORT }, "SecureLLM Gateway listening");
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, "Shutting down");
    server.close();
    await disconnectRedis();
    await disconnectMongo();
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  logger.fatal({ err }, "Failed to start");
  process.exit(1);
});
