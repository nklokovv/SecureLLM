import { AuditLog, type AuditStatus } from "../models/AuditLog.js";
import { sha256 } from "../utils/hash.js";

export interface AuditRecordInput {
  correlationId: string;
  apiKeyId: string;
  llmModel: string | null;
  requestBody: unknown;
  responseBody: unknown | null;
  detectedThreats: string[];
  latencyMs: number;
  status: AuditStatus;
  httpStatus: number;
  message?: string;
}

export async function writeAuditLog(input: AuditRecordInput): Promise<void> {
  const requestHash = sha256(JSON.stringify(input.requestBody ?? {}));
  const responseHash =
    input.responseBody !== null ? sha256(JSON.stringify(input.responseBody)) : null;

  await AuditLog.create({
    timestamp: new Date(),
    correlationId: input.correlationId,
    apiKeyId: input.apiKeyId,
    llmModel: input.llmModel,
    requestHash,
    responseHash,
    detectedThreats: input.detectedThreats,
    latencyMs: input.latencyMs,
    status: input.status,
    httpStatus: input.httpStatus,
    message: input.message,
  });
}

export async function queryAuditLogs(
  since: Date,
  limit: number,
): Promise<
  Array<{
    timestamp: Date;
    correlationId: string;
    apiKeyId: string;
    llmModel: string | null;
    requestHash: string;
    responseHash: string | null;
    detectedThreats: string[];
    latencyMs: number;
    status: AuditStatus;
    httpStatus: number;
    message?: string;
  }>
> {
  const capped = Math.min(Math.max(limit, 1), 500);
  const docs = await AuditLog.find({ timestamp: { $gte: since } })
    .sort({ timestamp: -1 })
    .limit(capped)
    .lean();

  return docs.map((d) => ({
    timestamp: d.timestamp,
    correlationId: d.correlationId,
    apiKeyId: d.apiKeyId,
    llmModel: d.llmModel,
    requestHash: d.requestHash,
    responseHash: d.responseHash,
    detectedThreats: d.detectedThreats,
    latencyMs: d.latencyMs,
    status: d.status,
    httpStatus: d.httpStatus,
    message: d.message,
  }));
}
