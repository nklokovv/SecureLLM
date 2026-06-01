import type { IApiKey } from "../models/ApiKey.js";

declare global {
  namespace Express {
    interface Request {
      correlationId?: string;
      startTime?: number;
      apiKeyDoc?: IApiKey;
      detectedThreats?: string[];
    }
  }
}

export {};
