# Architecture and security plan

> **Author:** [Victor Fang](https://VictorFang.com) ·
> [ztagent.ai](https://ztagent.ai) ·
> [X](https://X.com/vicfcs) ·
> [LinkedIn](https://www.linkedin.com/in/drvictorfang)

## Goal and non-goals

ztagent-core is the Apache-2.0 security gateway from [ztagent.ai](https://ztagent.ai).
It is a compact, self-hosted implementation for teams that need a consistent
security boundary around multiple model providers and orchestrators. It keeps
policy, detection, audit, and response replaceable behind small Python
interfaces.

It is not an LLM sandbox, malware scanner, DLP product, identity provider, WAF,
SIEM, or assurance certification. It does not claim to reliably identify every
prompt injection. Those concerns should integrate at deployment boundaries.

A commercial **ztagent Enterprise** edition is planned for organizations that
need vendor-supported controls beyond this core. Custom policy, tool, and
deployment work is available as consulting through [ztagent.ai](https://ztagent.ai).

## Request flow

```text
Client
  │  OIDC access token
  ▼
FastAPI API gateway ── body limits / secure headers
  │
  ├─ JWT verification ── JWKS, issuer, audience, expiry, fixed algorithms
  ├─ local containment check
  ├─ signature guardrails ── normalized input, bounded regex evaluation
  ├─ anomaly detector ── per-event heuristic + rolling 24-hour counters
  ├─ OPA PEP → PDP ── subject/action/resource; fail closed
  │
  ├─ model adapter ── OpenAI / Anthropic / OpenAI-compatible
  └─ tool registry ── allowlisted name / typed arguments / risk
          │
          ▼
    HMAC-chained JSONL audit → portal / external log shipper
          │
          ▼
    containment → local block / webhook / Keycloak session logout
```

All orchestrators should call the gateway, rather than model adapters or tool
handlers directly. Network policy should reinforce that design by allowing
model-provider and sensitive-tool egress only from the gateway workload.
The public endpoint accepts only `user` messages; trusted system instructions
must be injected by application code before calling the gateway.

## Threat coverage

| Threat | Prevent | Detect | Respond |
|---|---|---|---|
| Goal/prompt hijacking | Signatures, least privilege, OPA | Rule events, repeat counters | Block, contain identity |
| Tool misuse/excessive agency | Explicit registry, typed input, risk policy | Tool audit and denied decisions | Deny; require privileged role |
| Identity/privilege abuse | OIDC claim validation, role policy | Subject-linked audit/rate rules | Local block; revoke sessions |
| Data exfiltration | No prompts in OPA/audit, provider storage off | App-specific rules needed | Tool/model denial |
| Resource exhaustion | Body/context/output limits, provider timeout | Payload and 24-hour request rules | Rate block |
| Supply-chain/model endpoint swap | Model allowlist, pinned OPA image | Config review | Fail closed |
| Repudiation/log tampering | HMAC-chained events, fsync | Chain verification in portal | Preserve/export records |
| SSRF/arbitrary execution | No generic HTTP/shell tools | Registered tool audit | Tool deny/contain |
| Rogue or cascading agents | One mandatory boundary per call | Correlated request IDs | Disable identity/tool |

Important gaps are described below. Signature controls help with common,
high-signal attacks, but a model can still be manipulated using novel or
context-dependent instructions. Tool isolation and authorization are the hard
security boundaries.

## Detection and response behavior

1. Signature rules are trusted configuration. Inputs are NFKC-normalized and
   each regex has a timeout to reduce denial-of-service risk.
2. Any `block`/`contain` finding blocks immediately. Multiple lower-level
   findings can cross `block_score`.
3. SQLite is the small-deployment default for counters. Memory mode is useful
   for stateless containers but resets on restart and is per-process.
4. Repeated blocked requests can contain an identity. Local denial is applied
   before external response actions, so a webhook or Keycloak outage cannot
   restore access.
5. Human administrators may unblock a subject through the protected admin API.
   This action should be placed behind an approval workflow in higher-risk use.
6. Tool authorization intent is durably audited before a handler runs, followed
   by completion/error. Side-effecting handlers should also implement business
   idempotency because a process failure can leave execution outcome uncertain.

## Audit design

Events are JSONL envelopes. Each digest is:

```text
HMAC-SHA256(secret, previous_digest + "." + canonical_event_json)
```

This detects modification, deletion from the middle, and reordering when the
verifier has the complete file. It does not prevent deletion of the entire file,
truncation at the end without an externally stored checkpoint, or modification
by an attacker who obtains both file and HMAC key. Production deployments
should:

- send records to an append-only remote sink;
- store periodic final-digest checkpoints separately;
- keep the HMAC key in a secret manager, not `.env`;
- restrict filesystem access and rotate/archive logs;
- leave prompt logging disabled unless privacy review explicitly approves it.

## Extensibility points

- `ModelProvider`: add a provider without changing enforcement.
- `ToolRegistry`: register only business-specific capabilities.
- `CounterStore`: replace local state with Redis or a managed rate limiter.
- `OPAClient`: retain the PEP input contract while operating OPA as sidecar,
  daemon, or managed policy service.
- `ContainmentService`: route webhook events to SOAR, identity, ticketing, or
  approval systems.
- orchestrator adapters: LangChain is included; other harnesses can invoke
  `SecureAgentGateway.run` directly.

## Production deployment checklist

- Set `server.environment: production`; startup then rejects auth/OPA bypasses.
- Enable OIDC and use an API-specific audience. Accept only configured
  asymmetric signing algorithms.
- Terminate TLS at a hardened reverse proxy/API gateway. Bind the Python process
  to a private interface and sanitize forwarding headers there.
- Keep OPA local/private, load reviewed bundles, and monitor its health.
- Run as a non-root user with a read-only application filesystem and writable
  volumes only for state/audit (or use managed replacements).
- Place model and tools on destination allowlists. Sandbox code execution and
  require human approval for money movement, destructive changes, credential
  operations, or external communication.
- Use one worker with local SQLite/file state. For multiple workers/replicas,
  replace audit and counters with concurrency-safe shared services.
- Add application-specific DLP, output validation, malware/media scanning, data
  provenance, and safety evaluations.
- Keep dependencies/images patched, generate an SBOM, scan releases, and sign
  deployment artifacts.
- Exercise fail-closed behavior and containment in incident-response tests.

## Constructive scope choices

The first release deliberately avoids building a full agent loop. Agent loops
are orchestrator-specific and frequently create bypass paths. ztagent-core
instead owns a small gateway contract that LangChain and custom harnesses can
call.

It also avoids embedding Keycloak, OPA, Redis, a reverse proxy, and a JavaScript
build chain in one package. OPA has a minimal Compose service; identity and edge
gateways remain integrations. The portal is read-mostly and dependency-free.
These choices keep the trusted code base and operating burden small.

## Research basis

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Securing Agentic Applications Guide](https://genai.owasp.org/download/49059/)
- [NIST AI 600-1, Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [OPA integration guidance](https://www.openpolicyagent.org/docs/latest/integration/)
- [PyJWT usage and JWKS guidance](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [OpenAI Responses API migration guidance](https://developers.openai.com/api/docs/guides/migrate-to-responses)
- [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create)
