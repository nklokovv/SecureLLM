import { createHash } from "node:crypto";

export function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export function hashApiKey(rawKey: string): string {
  return sha256(rawKey);
}
