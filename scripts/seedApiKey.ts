import mongoose from "mongoose";
import { loadEnv } from "../src/config/env.js";
import { ApiKey } from "../src/models/ApiKey.js";
import { hashApiKey } from "../src/utils/hash.js";

async function seed(): Promise<void> {
  const env = loadEnv();
  await mongoose.connect(env.MONGODB_URI);

  const clientKey = process.env.SEED_CLIENT_KEY ?? "client-dev-key-change-me";
  const adminKey = process.env.SEED_ADMIN_KEY ?? "admin-dev-key-change-me";

  const keys = [
    { keyId: "client-default", raw: clientKey, role: "client" as const, rateLimit: null },
    { keyId: "admin-default", raw: adminKey, role: "admin" as const, rateLimit: null },
  ];

  for (const k of keys) {
    await ApiKey.findOneAndUpdate(
      { keyId: k.keyId },
      {
        keyId: k.keyId,
        keyHash: hashApiKey(k.raw),
        role: k.role,
        rateLimitPerMinute: k.rateLimit,
      },
      { upsert: true, new: true },
    );
    console.log(`Seeded ${k.role} key: ${k.keyId} (use x-api-key: ${k.raw})`);
  }

  await mongoose.disconnect();
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
