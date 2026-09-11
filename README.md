# agent-gateway

`agent-gateway` is the mandatory security boundary between intelligence and money.

## Role

The gateway accepts agent-originated `FinancialIntent` requests and enforces:

1. authentication
2. capability verification
3. schema validation
4. mandate enforcement
5. policy/risk linkage
6. approval routing
7. rate and spend limits
8. replay protection
9. append-only audit events
10. kill switch controls

The gateway never executes blockchain transactions directly. It only forwards approved intents to deterministic downstream services such as `pay`, `markets`, and `accounts`.

## Request pipeline

```text
Agent
  -> authenticate credential + session binding
  -> validate FinancialIntent schema and authority fields
  -> check mandate + capability + autonomy constraints
  -> bind policy decision reference + risk reference
  -> enforce idempotency, nonce freshness, rate limits, spend caps
  -> route to APPROVED | REVIEW | CHALLENGE | DELAY | QUARANTINE | DENIED | BLOCKED
  -> emit append-only audit events with hash chaining
  -> forward approved intents to deterministic execution services only
```

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

## Decision states and reason codes

Decision states:

- `APPROVED`
- `DENIED`
- `REVIEW`
- `CHALLENGE`
- `DELAY`
- `QUARANTINE`
- `CANCELLED`
- `BLOCKED`

Representative reason codes:

- `MALFORMED_INTENT`
- `MISSING_AUTHORITY_FIELDS`
- `MISSING_POLICY_BINDING`
- `ACTOR_MISMATCH`
- `INTENT_EXPIRED`
- `CAPABILITY_REVOKED_OR_EXPIRED`
- `MANDATE_REVOKED_OR_EXPIRED`
- `UNSUPPORTED_ACTION`
- `AUTONOMY_VIOLATION`
- `DUPLICATE_IDEMPOTENCY_KEY`
- `IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_PAYLOAD`
- `NONCE_REPLAYED`
- `STALE_NONCE`
- `RATE_LIMIT_EXCEEDED`
- `SPEND_LIMIT_EXCEEDED`
- `KILLSWITCH_ACTIVE`

## Kill switch operations

- Global kill switch blocks all new agent intents immediately.
- Agent suspension blocks only the targeted agent immediately.
- Credential revocation invalidates bound credentials immediately.
- Capability revocation prevents further use of revoked operations immediately.
- Kill switch deactivation requires the admin token and `X-High-Trust: true`.
- Kill switch and suspend flows emit downstream prevention signals plus audit events.

## Operational runbook

1. Activate `POST /v1/killswitch/activate`.
2. Suspend the affected agent with `POST /v1/agents/{agentId}/suspend`.
3. Revoke credentials with `POST /v1/agents/{agentId}/revoke-credentials`.
4. Revoke compromised capabilities with `POST /v1/capabilities/{capabilityId}/revoke`.
5. Review `GET /v1/audit/events?intentId=...` and verify hash-chain integrity in service checks.
6. Approve only explicitly reviewed intents through `POST /v1/intents/{intentId}/approve`.
7. Restore service through `POST /v1/killswitch/deactivate` on the high-trust path after containment.

## RFC mapping

- RFC-0007: gateway is the mandatory pre-execution security boundary.
- RFC-0005 dependency: `FinancialIntent` canonical authority, policy, and risk fields.
- Architecture dependency: downstream deterministic execution layers remain outside the gateway.

## Development

Run:

```bash
go test ./...
go run ./cmd/server
```
