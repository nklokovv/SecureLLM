import mongoose from "mongoose";
import type { Env } from "../config/env.js";
import { logger } from "../utils/logger.js";

let connected = false;

export async function connectMongo(env: Env): Promise<void> {
  if (connected) return;
  await mongoose.connect(env.MONGODB_URI);
  connected = true;
  logger.info("MongoDB connected");
}

export async function pingMongo(): Promise<boolean> {
  if (mongoose.connection.readyState !== 1) return false;
  try {
    await mongoose.connection.db?.admin().ping();
    return true;
  } catch {
    return false;
  }
}

export async function disconnectMongo(): Promise<void> {
  if (!connected) return;
  await mongoose.disconnect();
  connected = false;
}
