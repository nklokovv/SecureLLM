import mongoose, { Schema, type Document, type Model } from "mongoose";

export type ApiKeyRole = "client" | "admin";

export interface IApiKey extends Document {
  keyId: string;
  keyHash: string;
  role: ApiKeyRole;
  rateLimitPerMinute: number | null;
  createdAt: Date;
}

const apiKeySchema = new Schema<IApiKey>(
  {
    keyId: { type: String, required: true, unique: true, index: true },
    keyHash: { type: String, required: true, unique: true },
    role: { type: String, enum: ["client", "admin"], required: true },
    rateLimitPerMinute: { type: Number, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

export const ApiKey: Model<IApiKey> =
  mongoose.models.ApiKey ?? mongoose.model<IApiKey>("ApiKey", apiKeySchema);
