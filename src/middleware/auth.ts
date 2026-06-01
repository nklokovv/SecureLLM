import type { Request, Response, NextFunction } from "express";
import { ApiKey } from "../models/ApiKey.js";
import { hashApiKey } from "../utils/hash.js";
import { constantTimeEqual } from "../utils/constantTime.js";

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const rawKey = req.header("x-api-key");
  if (!rawKey) {
    res.status(401).json({ error: "Missing x-api-key header" });
    return;
  }

  const keyHash = hashApiKey(rawKey);
  const doc = await ApiKey.findOne({ keyHash }).exec();

  if (!doc) {
    res.status(401).json({ error: "Invalid API key" });
    return;
  }

  if (!constantTimeEqual(doc.keyHash, keyHash)) {
    res.status(401).json({ error: "Invalid API key" });
    return;
  }

  req.apiKeyDoc = doc;
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.apiKeyDoc) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (req.apiKeyDoc.role !== "admin") {
    res.status(403).json({ error: "Admin role required" });
    return;
  }
  next();
}
