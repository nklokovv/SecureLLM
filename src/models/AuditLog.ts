import mongoose, { Schema, type Document, type Model } from "mongoose";

export type AuditStatus = "allowed" | "blocked" | "error";

export interface IAuditLog extends Document {
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
}

const auditLogSchema = new Schema<IAuditLog>(
  {
    timestamp: { type: Date, required: true, index: true },
    correlationId: { type: String, required: true, index: true },
    apiKeyId: { type: String, required: true, index: true },
    llmModel: { type: String, default: null },
    requestHash: { type: String, required: true },
    responseHash: { type: String, default: null },
    detectedThreats: { type: [String], default: [] },
    latencyMs: { type: Number, required: true },
    status: { type: String, enum: ["allowed", "blocked", "error"], required: true },
    httpStatus: { type: Number, required: true },
    message: { type: String },
  },
  { timestamps: false },
);

export const AuditLog: Model<IAuditLog> =
  mongoose.models.AuditLog ?? mongoose.model<IAuditLog>("AuditLog", auditLogSchema);
