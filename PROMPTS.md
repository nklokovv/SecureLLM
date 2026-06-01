# PROMPTS.md — AI process documentation

## 1. Tools used

| Tool | Purpose |
|------|---------|
| **ChatGPT** | Exploration of the sanitized brief and architecture; challenging/redesigning the PII redaction approach |
| **Cursor (Composer)** | Implementation, tests, Docker setup, and documentation |

## 2. Why multiple tools

ChatGPT was used **first**, on the sanitized brief (Appendix A removed), to reason about requirements, attack categories, and architecture risk before any code existed. **Cursor (Composer)** then implemented and iterated the solution files.

The clearest moment of one tool challenging another was the **PII redaction module** (`src/security/pii/*`). Composer's first pass was a naive, monolithic rule dump — a pile of regexes that flagged any 9-digit number as an Israeli ID and any digit run as a phone, with high false-positive rates and no structure. I took that output to ChatGPT to challenge the approach, and rewrote it into the current design: Israeli-ID **check-digit validation** instead of bare 9-digit matching, **context-window gating** (only redact ambiguous IDs near phrases like “national ID”/“מספר זהות”), **JSON-key-aware** redaction so structured payloads (`id_number`, `name`, …) are handled separately from prose, and a split into focused modules (`email`, `phone`, `israeliId`, `names`, `redact`) backed by a reversible token vault. Both tools thus touched the same solution file, and the second tool's output materially replaced the first's.

`src/security/injectionPatterns.ts` was shaped similarly: attack categories came out of the ChatGPT planning discussion, while the concrete rule catalog and its variations were written and repeatedly extended in Cursor as new corpus cases were tested. When Cursor's first multilingual rule missed an embedded `System: ignore…` payload, the rule set was rewritten rather than accepted as-is (see §4).

## 3. Three example prompts

### Code generation (Cursor)

> Implement the SecureLLM Gateway per plan: TypeScript strict, Express, MongoDB, Redis, OpenAI, seven security controls, Vitest tests per control, Docker Compose.

**What I did with the output:** Used it as the implementation blueprint and kept each control in its own module/middleware so it could be unit-tested in isolation.

### Security review (Cursor)

> we need to check we actually meet the corpus acceptance stuff from the brief — each INJ rule should hit 400 and show up in audit with the rule id, PII should go to the model redacted and only recoverable from audit, and if the model echoes injection we need 502 on output (can stub the reply). i think we only have unit tests on detectInjection right now, not the full http path. can you add whats missing?

**What I did with the output:** turned out it was right — we had pattern tests but not proving 400 + audit or pii vault over the real route. added `test/corpus/entries.ts` and `test/corpusAcceptance.test.ts` with supertest + mocked mongo/redis/provider.

### Debugging / design (ChatGPT)

> what are ways to reduce sensitive info and filter it in llm input? like names, emails, phones, israeli id number.
> cursor already wrote me something regex-based but i dont trust it.
> edge cases:
> - json field already looks redacted, e.g. `"name": "[REDACTED]"` — dont touch it again
> - if we treat every 9-digit number as national id we will redact random stuff (order ids, etc)
> - originals need to come back on the audit path only (tokens in redis?)
> how would you structure this without tons of false positives?

**What I did with the output:** used it to push back on composer's first pii module — added check-digit for il id, only redact ambiguous 9-digits near context like "national id", separate handling for json keys (`id_number`, `name`, …), skip values that already look like `[REDACTED]` or `[PII-…]`, split into `src/security/pii/*` + token vault.

## 4. What I rejected

1. **Pasting the whole PDF into an AI tool.** Appendix A contains real injection and exfiltration patterns; feeding them wholesale risks the model treating attacks as instructions. Rejected in favor of a sanitized brief plus verbal category descriptions (see §6).
2. **Composer's first PII implementation.** The initial rule-based PII module was naive — every 9-digit number treated as a national ID, every digit run as a phone — which would over-redact real traffic. I challenged it with ChatGPT and rewrote it into a structured, lower-false-positive design: check-digit validation for Israeli IDs, context-window gating for ambiguous numbers, JSON-key-aware redaction, and per-type modules behind a reversible token vault.
3. **The first multilingual injection rule.** Cursor's initial `INJ-IND-003` keyed only on an English translation wrapper, so a payload with the override written in the target language slipped through. Rewrote it to match both the translation-bait framing **and** the embedded `system: ignore…` instruction across English/Hebrew/Spanish/French, and added tests for each language.

## 5. What I would do with more time

1. **GitHub Actions CI** — run `npm test` and gitleaks on every push; AI could generate the workflow YAML from the existing scripts.
2. **Broader multilingual injection rules** — expand `INJ-IND-003` with ML-based or embedding-assisted detection; AI could help benchmark false-positive rates on benign multilingual chat.

## 6. First AI interaction on this challenge

**Tool:** ChatGPT

**First prompt (verbatim):**

> homework that I get during interview process, I want to explore it more, understand bkms to do it.
> I removed section with Apendix A
> they also asked to manage prompts.md, I will write code in cursor, but sometimes use you as one more source.
> now lets explore this pdf, possible problems and constraints

**Sanitization:** Before using AI, I removed Appendix A from the document because it contained prompt-injection and exfiltration examples. I treated the challenge brief as untrusted input and used AI only to discuss sanitized requirements, architecture, risks, and implementation plan.
