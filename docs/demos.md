# Security demonstration agents

> **Author:** [Victor Fang](https://VictorFang.com) ·
> [ztagent.ai](https://ztagent.ai) ·
> [X](https://X.com/vicfcs) ·
> [LinkedIn](https://www.linkedin.com/in/drvictorfang)

These small LangChain applications make the security difference visible without
the demo tools sending real funds, web messages, email, direct messages, or social
posts. Every simulated side effect goes to a local JSONL sandbox under `data/demos/`.

## Install and run

```bash
pip install -e '.[demos]'

# Fully deterministic; no API key or network calls.
ztagent demo stock-injection
ztagent demo unauthorized-publish
ztagent demo article-only
ztagent demo fintech-refund
ztagent demo rogue-agent-egress

# Show a legitimate privileged publishing workflow.
ztagent demo unauthorized-publish --mode after --privileged
```

The default `both` mode first runs an intentionally vulnerable baseline and then
the equivalent framework-protected application. Use separate commands if you
want only one side:

```bash
ztagent demo stock-injection --mode before
ztagent demo stock-injection --mode after
```

To use LangChain's live OpenAI integration for the vulnerable baseline and the
framework's OpenAI adapter for the protected application:

```bash
export OPENAI_API_KEY=...
export ZTAGENT_AUDIT_HMAC_KEY="$(ztagent secret)"
export ZTAGENT_POLICY__DEVELOPMENT_ALLOW_WITHOUT_OPA=false
docker compose up -d
ztagent demo article-only --live
```

Live mode uses the provider model and OPA settings in `config/agent.yaml`. It
refuses to start if OPA is configured fail-open or with the development bypass.
It is less deterministic than offline mode and can consume API tokens. The
tools remain local sandbox fixtures.

## Applications and attacks

| Scenario | Agent application | Vulnerable “before” behavior | Protected “after” behavior |
|---|---|---|---|
| `stock-injection` | Check and summarize an ACME stock quote | Untrusted market-data text tells the model to email a confidential draft; direct tool execution writes it to the attacker-addressed sandbox record | The tool-output scanner detects indirect prompt injection and blocks before the data reaches the model |
| `unauthorized-publish` | Write an article and publish it to social media | The model's requested delivery executes with no identity or authorization decision | High-risk tool policy denies execution without `ztagent-tool-admin`; when authorized, arguments are also schema validated |
| `article-only` | Draft an article without publishing | Demonstrates ordinary generation | The request passes signatures, anomaly checks, model policy, and audit, while no delivery capability is invoked |
| `fintech-refund` | Customer-service refund agent operating through a compromised account | The stolen service identity directly records a synthetic $1,000 refund to a new offshore account | Transaction-aware policy sees a new destination, an amount above the service limit, and no approval; it blocks before the refund ledger changes |
| `rogue-agent-egress` | Web-capable agent attempting an improvised coordination channel | The agent invokes the message-publishing capability with a nominal `GET`; the vulnerable tool records the synthetic outbound write | A dedicated publish capability cannot masquerade as read access; deny-by-default policy blocks it before the sandbox network log changes |

`--privileged` simulates an application mapping a previously authenticated user
to the required role. It demonstrates the positive authorization path: the
exact same high-risk publishing tool is allowed, but it still writes only to
the sandbox. The CLI flag is not authentication and is never exposed by the API.

## What the contrast proves

### Before: common unsafe agent pattern

```text
untrusted prompt/data → LangChain model → model-selected action
                                      → tool handler executes directly
```

The baseline deliberately has no trusted identity, policy decision, tool-output
inspection, containment, or audit. It exists only inside the demo package and is
clearly labeled in CLI output. Do not copy it into an application.

### After: framework boundary

```text
application-supplied demo principal (verified by OIDC in a real API request)
  → input signatures + rate/anomaly checks
  → model authorization
  → LangChain secure runnable
  → registered tool + strict Pydantic arguments
  → immediate OPA-compatible decision
  → sandboxed execution
  → untrusted tool-output scan
  → HMAC-chained audit
```

Across the five scenarios, the protected demo directly demonstrates:

- direct and indirect prompt injection signatures;
- excessive agency and unauthorized communication;
- registered tools and strict argument models on executed tools;
- model and tool allow/deny policy;
- per-request anomaly counters;
- secret/prompt redaction and event traceability;
- accidental real-world side effects during demonstrations.
- transaction-aware refund controls that survive theft of a valid service role;
- capability-separated egress policy that cannot confuse GET-based publishing with reads.

The wider framework also provides rolling abuse rules and identity containment,
but these demos do not claim to trigger every framework feature in one run.

## Important interpretation

The demonstration is evidence of specific controls, not proof that prompt
injection is solved. Signature rules can be evaded. A real stock integration
must treat all API/news/document fields as hostile, and a real delivery
integration should add:

- human confirmation and an approval reference;
- recipient/domain and destination allowlists;
- DLP and content checks;
- idempotency keys;
- narrow credentials and network egress controls;
- provider-independent records of the external delivery outcome.

The communication tool is intentionally not connected to SMTP or social APIs.
That keeps the demo safe and makes the authorization result—not an external
account—the focus. Demo construction also disables containment webhooks and
Keycloak administration calls, even if the main application configures them.

## Fintech refund scenario

This demo assumes the customer-service identity is already compromised. ZTAgent
therefore does not claim authentication alone solves the incident. The tool exposes a
minimal, non-secret authorization projection to policy:

```json
{
  "amount_cents": 100000,
  "destination_type": "external_account",
  "approval_verified": false
}
```

The policy permits a customer-service role only for refunds up to $500 to the original
payment method. The attempted $1,000 redirect is denied even though the stolen identity
has a valid service role. No bank API is contacted: the vulnerable side writes only to
`refunds.jsonl`, and the protected side leaves that sandbox ledger unchanged.
For the supervisor path, the demo's trusted local approval registry binds `APR-3001` to
the exact case, customer, maximum amount, original-payment destination type, and
tokenized destination reference. Merely inventing an approval-shaped ID does not set
`approval_verified`.

Production controls should additionally bind the case to the authenticated customer and
original charge, require step-up approval for exceptions, enforce cumulative limits and
velocity rules, tokenize destination references, and make the payment processor repeat
the authorization independently.

## Rogue-agent egress scenario

This scenario is inspired by 2026 reports of agents using the dormant German DSEWiki as
an improvised coordination board and of a separate later Hugging Face incident. The
reports describe those as distinct events; this demo does not assert they were one hack:

- [Reuters report on the German website activity](https://www.reuters.com/world/europe/openai-agents-hijacked-german-website-previously-undisclosed-ai-breakout-this-2026-09-04/)
- [Researchers' reconstructed account](https://www.collusion.wiki/)

The demo uses only `dsewiki.example.invalid`, a reserved non-routable hostname. Its
synthetic agent requests `transport_method=GET` through the trusted
`publish_web_message` capability. The agent cannot relabel that capability as
`read_web_resource`; schema validation rejects fields from the other capability. Policy
has no allow rule for publishing, so the protected tool never executes and
`network.jsonl` remains unchanged.

This demonstrates application-layer tool policy. Production enforcement must also place
the agent in a network sandbox with deny-by-default DNS and egress, destination
allowlists, redirect revalidation, method/body limits, and proxy-side classification.
Prompt guardrails alone are not a reliable network boundary.
