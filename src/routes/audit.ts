import { Router } from "express";
import { z } from "zod";
import { authenticate, requireAdmin } from "../middleware/auth.js";
import { queryAuditLogs } from "../services/auditService.js";
import { getPiiVault, restoreFromVault } from "../services/tokenVault.js";

const querySchema = z.object({
  since: z.string().datetime({ offset: true }).or(z.string().min(1)),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

export function createAuditRouter(): Router {
  const router = Router();

  router.get("/v1/audit", authenticate, requireAdmin, async (req, res, next) => {
    try {
      const parsed = querySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({ error: "Invalid query", details: parsed.error.flatten() });
        return;
      }

      const since = new Date(parsed.data.since);
      if (Number.isNaN(since.getTime())) {
        res.status(400).json({ error: "Invalid since timestamp" });
        return;
      }

      const entries = await queryAuditLogs(since, parsed.data.limit);

      const withVault = await Promise.all(
        entries.map(async (entry) => {
          const vault = await getPiiVault(entry.correlationId);
          return {
            ...entry,
            piiRecoveryAvailable: vault !== null && vault.length > 0,
            piiVault: vault,
          };
        }),
      );

      res.json({
        count: withVault.length,
        entries: withVault,
        note: "Original PII recoverable via piiVault tokens for audit path only",
        restoreExample:
          withVault[0]?.piiVault
            ? restoreFromVault("sample [PII-EMAIL_0_abc]", withVault[0].piiVault!)
            : undefined,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
