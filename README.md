# SecureLLM Gateway

Production-grade security layer that proxies LLM requests through authentication, rate limiting, prompt-injection detection, reversible PII redaction, output validation, and audit logging.

## Quick start

```bash
cp .env.example .env
# Optional: set OPENAI_API_KEY in .env for live LLM calls

docker compose up --build
```

Service listens on `http://localhost:3000`.

### Local dev (without Docker)

```bash
npm install
docker compose up -d mongo redis     # or point at your own Mongo/Redis

cp .env.example .env
# Edit .env for local hosts:
#   MONGODB_URI=mongodb://localhost:27017/securellm
#   REDIS_URL=redis://localhost:6379

npm run seed     # seeds client + admin keys into Mongo (reads .env)
npm run dev      # hot-reload dev server on PORT (reads .env)
```

> `npm run seed` and `npm run dev` load env via `--env-file=.env`, so a `.env` file must exist. `.env.example` defaults to the Docker service hostnames (`mongo`, `redis`); change them to `localhost` for local runs.

Default keys (change in production):

| Role   | Header value                 |
|--------|------------------------------|
| client | `client-dev-key-change-me`   |
| admin  | `admin-dev-key-change-me`    |

## API

### `POST /v1/chat`

Requires `x-api-key` (client or admin).

```json
{
  "model": "gpt-4o",
  "messages": [{ "role": "user", "content": "Hello" }],
  "max_tokens": 1024
}
```

### `GET /v1/audit?since=2026-01-01T00:00:00.000Z&limit=100`

Admin key only. Returns audit entries since timestamp (limit ≤ 500). Includes PII vault for audit-time recovery.

### `GET /healthz`

No auth. Reports Mongo, Redis, and OpenAI provider readiness.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGODB_URI` | yes | MongoDB connection string |
| `REDIS_URL` | yes | Redis connection string |
| `OPENAI_API_KEY` | no | If missing, service starts; `/v1/chat` returns 503 |
| `PORT` | no | Default `3000` |
| `DEFAULT_RATE_LIMIT` | no | Default `30` req/min per key |
| `TOKEN_VAULT_TTL_SECONDS` | no | PII vault TTL in Redis |

## Security architecture

### 1. Authentication

API keys are stored as SHA-256 hashes in MongoDB. Lookup uses constant-time comparison. Roles: `client` (chat) and `admin` (chat + audit).

### 2. Rate limiting

Per-key sliding window in Redis (sorted set). Default 30 requests/minute; overridable per key document.

### 3. Prompt-injection detection

Declarative rule catalog with stable IDs (`INJ-OVR-*`, `INJ-SYS-*`, `INJ-ROLE-*`, `INJ-IND-*`). Input is normalized (case, whitespace, leetspeak, URL/base64 decoding) before matching. Blocks with HTTP 400 and audits the firing rule.

### 4. PII redaction (inbound)

Detects email, Israeli and international phone numbers, and Israeli national ID (with check-digit validation). Replaces spans with reversible tokens; originals stored in Redis vault keyed by correlation ID—recoverable only via admin audit path.

### 5. Output validation (outbound)

Rejects LLM output containing `sk-…` keys, JWT-shaped strings, AWS access keys, or echoed injection patterns. Returns HTTP 502 when blocked.

### 6. Audit log

MongoDB record per request: timestamp, correlation ID, API key ID, model, request/response hashes, detected threats, latency, status (`allowed` | `blocked` | `error`).

### 7. Secrets handling

Provider keys only via environment variables. Pino log redaction for sensitive headers. `.gitleaks.toml` included for CI/scanning.

## Tests

```bash
npm test          # full Vitest suite
npm run typecheck # tsc --strict, no emit
```

Coverage includes per-control unit tests (auth, rate limit, injection, PII, output validation, normalization) plus `test/corpusAcceptance.test.ts` — an integration suite over the real Express app (with mocked Mongo/Redis/provider) that asserts, for every catalog rule and a variation of each:

- each `INJ-*` payload → HTTP 400 with an audit entry naming the firing rule;
- each `PII-*` payload → forwarded to the LLM redacted, with originals recoverable only through the admin audit path;
- output validation independently catches an LLM response that echoes any `INJ-*` payload (response stubbing) → HTTP 502 `OUT-ECHO-001`.

## Known limitations

- Multilingual injection detection covers a fixed keyword set (Hebrew, Spanish, French samples)—not all languages.
- Regex-based PII can false-positive on long digit sequences; Israeli ID uses check-digit validation to reduce noise.
- Only OpenAI (`gpt-4o`) is wired. `claude-3-5-sonnet` is an accepted request value but is **rejected with a clear `400`** ("Model not available") rather than silently served by another model — the audit log never misattributes which model answered.
- No streaming responses; synchronous chat completion only.
- Rate-limit tests use a mocked Redis client; integration tests against real Redis are not included.

## What this service does NOT protect against

- Novel injection techniques outside the rule catalog
- Multimodal (image/audio) payloads
- Insider threats with valid admin API keys
- Model-level adversarial attacks after sanitized input reaches the provider
- DDoS at the network edge (only per-key application rate limits)
