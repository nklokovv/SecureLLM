/**
 * Manual check: pass a string as if it were LLM output.
 * Usage: npx tsx scripts/checkOutputValidation.ts "text from model"
 */
import { validateLlmOutput } from "../src/security/outputValidation.js";

const text = process.argv.slice(2).join(" ");
if (!text?.trim()) {
  console.error('Usage: npx tsx scripts/checkOutputValidation.ts "assistant reply here"');
  process.exit(1);
}

const result = validateLlmOutput(text.trim());
if (result) {
  console.log("BLOCKED", result);
  process.exit(0);
}
console.log("ALLOWED (would return to client)");
process.exit(0);
