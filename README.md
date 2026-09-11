# agent-gateway

`agent-gateway` is the mandatory security boundary between intelligence and money.

## Role

The gateway accepts agent-originated canonical `FinancialIntent` requests and enforces:

1. credential + session authentication
2. canonical schema validation
3. mandate and capability verification
4. authoritative policy/risk linkage
5. DB-backed idempotency and replay protection
6. DB-backed rate and spend controls
7. approval routing for authoritative `REVIEW` / `CHALLENGE` / `DELAY` outcomes
8. append-only audit events with hash chaining
9. kill-switch and suspension controls

The gateway never invents policy/risk decisions and never executes blockchain transactions directly. It only forwards approved intents to deterministic downstream services.

## Canonical `/v1/intents` request

```json
{
  "intent": {
    "intentId": "intent-123",
    "actorType": "AGENT",
    "actorId": "agent-1",
    "action": "TRANSFER",
    "assetId": "USD",
    "amount": 25,
    "chainId": "SOLANA",
    "recipient": "merchant-42",
    "purpose": "settlement",
    "mandateId": "mandate-1",
    "policyVersion": "2026-09",
    "correlationId": "corr-123",
    "idempotencyKey": "idem-123",
    "expiresAt": "2026-09-11T00:00:00Z"
  },
  "execution": {
    "agentId": "agent-1",
    "capabilityId": "cap-1",
    "nonce": "nonce-123",
    "autonomyLevel": "A2",
    "executionRef": {
      "contract": "treasury-vault",
      "function": "transfer"
    }
  },
  "authority": {
    "policyDecisionId": "pol-123",
    "riskAssessmentId": "risk-123",
    "authorizationId": "auth-123",
    "outcome": "ALLOW"
  }
}
```

Responses retain `/v1` compatibility and return canonical envelopes with `contractVersion` and `schemaVersion`.

## Legacy compatibility

Legacy top-level fields are still accepted through an explicit adapter:

- `asset` -> `intent.assetId`
- `chain` -> `intent.chainId`
- `contract` -> `execution.executionRef.contract`
- `function` -> `execution.executionRef.function`
- `policyBinding.decisionRef` -> `authority.policyDecisionId`
- `riskLinkage.reference` -> `authority.riskAssessmentId`

Deprecated fields produce explicit `deprecationWarnings`. Legacy risk scores are ignored; authoritative policy outcomes are required.

## Authoritative policy-risk dependency

The gateway fails closed unless one of the following is true:

1. authoritative policy/risk references are supplied and validate against the contract, or
2. a deterministic lookup is available through `POLICY_RISK_LOOKUPS_JSON`.

The gateway stores policy decision IDs, risk assessment IDs, authorization IDs, outcomes, and policy versions verbatim.

## Supported canonical actions

- `PAY`
- `TRANSFER`
- `SWAP`
- `TRADE`
- `REBALANCE`
- `COLLECT`
- `OPEN_POSITION`
- `CLOSE_POSITION`

Unsupported downstream or capability combinations return deterministic reason codes.

## Security defaults

Required environment variables:

- `DATABASE_URL`
- `ADMIN_WRITE_TOKEN` or `ADMIN_TOKEN`

Optional scoped admin overrides:

- `ADMIN_READ_TOKEN`
- `KILLSWITCH_ADMIN_TOKEN`
- `APPROVAL_ADMIN_TOKEN`

All admin and agent authentication uses the standard bearer Authorization header. Startup fails if required secrets are missing.

## Persistence and audit guarantees

Persistent state is stored in SQL-backed repositories using:

- `agents`, `agent_credentials`, `agent_capabilities`, `agent_mandates`, `agent_sessions`, `agent_actions`
- `audit_events`, `audit_event_hashes`
- `authorization_events`

DB-backed guarantees include:

- agent-scoped idempotency keys
- deterministic replay buckets for nonces
- persistent rate/spend window checks
- append-only audit hash chains with integrity verification

## Migrations

- `001_init.sql` defines the base tables.
- `002_alignment.sql` adds canonical columns, audit provenance columns, and indexes for intent, correlation, idempotency, and replay lookups.
- Legacy columns remain in place and are deprecated; they are not dropped yet.

## API surface

- `POST /v1/intents`
- `POST /v1/intents/{intentId}/approve`
- `POST /v1/intents/{intentId}/cancel`
- `GET /v1/intents/{intentId}`
- `GET /v1/agents/{agentId}/status`
- `POST /v1/agents/{agentId}/suspend`
- `POST /v1/agents/{agentId}/revoke-credentials`
- `POST /v1/capabilities/{capabilityId}/revoke`
- `POST /v1/killswitch/activate`
- `POST /v1/killswitch/deactivate`
- `GET /v1/audit/events?intentId=...`

## Runbook notes

1. Activate the kill switch.
2. Suspend affected agents and revoke credentials/capabilities.
3. Review persisted audit events and verify the audit hash chain.
4. Resolve policy/risk linkage upstream before retrying failed intents.
5. Migrate callers to canonical payloads before removing legacy adapters.

## Development

```bash
go test ./...
go run ./cmd/server
```
