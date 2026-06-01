import { randomBytes } from "node:crypto";
import type { PiiSpan } from "./types.js";

const nameFieldRegex =
  /^(name|fullName|firstName|lastName|clientName|customerName|contactName)$/i;

export function isAlreadyRedacted(value: string): boolean {
  return /^\[(?:PII-|PERSON_|REDACTED)/i.test(value.trim());
}

export interface NameRedactionResult {
  value: unknown;
  spans: PiiSpan[];
}

function makeNameToken(index: number): string {
  const suffix = randomBytes(4).toString("hex");
  return `[PII-NAME_${index}_${suffix}]`;
}

export function redactStructuredNames(
  input: unknown,
  nameIndexStart = 0,
): NameRedactionResult {
  const spans: PiiSpan[] = [];
  let nameIndex = nameIndexStart;

  const walk = (value: unknown): unknown => {
    if (Array.isArray(value)) {
      return value.map((item) => walk(item));
    }

    if (value && typeof value === "object") {
      const result: Record<string, unknown> = {};

      for (const [key, fieldValue] of Object.entries(value)) {
        if (
          typeof fieldValue === "string" &&
          nameFieldRegex.test(key) &&
          fieldValue.trim() !== "" &&
          !isAlreadyRedacted(fieldValue)
        ) {
          const token = makeNameToken(nameIndex++);
          spans.push({
            category: "PII-NAME",
            start: 0,
            end: 0,
            original: fieldValue,
            token,
          });
          result[key] = token;
        } else {
          result[key] = walk(fieldValue);
        }
      }

      return result;
    }

    return value;
  };

  return { value: walk(input), spans };
}
