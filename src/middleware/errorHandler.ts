import type { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";

export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  logger.error(
    { err, correlationId: req.correlationId },
    "Unhandled error",
  );
  if (res.headersSent) return;
  res.status(500).json({ error: "Internal server error" });
}
