import express from "express";
import { pinoHttp } from "pino-http";
import type { IncomingMessage } from "node:http";
import type { Env } from "./config/env.js";
import { logger } from "./utils/logger.js";
import { requestContext } from "./middleware/requestContext.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { createHealthRouter } from "./routes/health.js";
import { createChatRouter } from "./routes/chat.js";
import { createAuditRouter } from "./routes/audit.js";

export function createApp(env: Env): express.Application {
  const app = express();

  app.use(
    pinoHttp({
      logger,
      customProps: (req: IncomingMessage & { correlationId?: string }) => ({
        correlationId: req.correlationId,
      }),
    }) as express.RequestHandler,
  );
  app.use(express.json({ limit: "1mb" }));
  app.use(requestContext);

  app.use(createHealthRouter(env));
  app.use(createChatRouter(env));
  app.use(createAuditRouter());

  // Malformed JSON body → 400 (not 500)
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) => {
      if (
        err &&
        typeof err === "object" &&
        "type" in err &&
        (err as { type?: string }).type === "entity.parse.failed"
      ) {
        res.status(400).json({
          error: "Invalid JSON body",
          hint: "Escape quotes inside strings with backslash, or use jq to build the payload",
        });
        return;
      }
      next(err);
    },
  );

  app.use(errorHandler);

  return app;
}
