import type { Request, Response, NextFunction } from "express";
import { v4 as uuidv4 } from "uuid";

export function requestContext(req: Request, _res: Response, next: NextFunction): void {
  req.correlationId = uuidv4();
  req.startTime = Date.now();
  req.detectedThreats = [];
  next();
}
