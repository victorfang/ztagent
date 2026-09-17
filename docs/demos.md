# Security demonstration agents

These small LangChain applications make the security difference visible without
sending real email, direct messages, or social posts. Every delivery goes to a
local JSONL sandbox under `data/demos/`.

## Install and run

```bash
pip install -e '.[demos]'

# Fully deterministic; no API key or network calls.
msa demo stock-injection
msa demo unauthorized-publish
msa demo article-only

# Show a legitimate privileged publishing workflow.
msa demo unauthorized-publish --mode after --privileged
```

The default `both` mode first runs an intentionally vulnerable baseline and then
the equivalent framework-protected application. Use separate commands if you
want only one side:

```bash
msa demo stock-injection --mode before
msa demo stock-injection --mode after
```

To use LangChain's live OpenAI integration for the vulnerable baseline and the
framework's OpenAI adapter for the protected application:

```bash
export OPENAI_API_KEY=...
export MSA_AUDIT_HMAC_KEY="$(msa secret)"
docker compose up -d
msa demo article-only --live
```

Live mode uses the provider model and OPA settings in `config/agent.yaml`. It is
less deterministic than offline mode and can consume API tokens. The tools
remain local sandbox fixtures.

## Applications and attacks

| Scenario | Agent application | Vulnerable “before” behavior | Protected “after” behavior |
|---|---|---|---|
| `stock-injection` | Check and summarize an ACME stock quote | Untrusted market-data text tells the model to email a confidential draft; direct tool execution writes it to the attacker-addressed sandbox record | The tool-output scanner detects indirect prompt injection and blocks before the data reaches the model |
| `unauthorized-publish` | Write an article and publish it to social media | The model's requested delivery executes with no identity or authorization decision | The high-risk delivery passes through schema validation and policy; it is denied without `msa-tool-admin` |
| `article-only` | Draft an article without publishing | Demonstrates ordinary generation | The request passes signatures, anomaly checks, model policy, and audit, while no delivery capability is invoked |

`--privileged` demonstrates the positive authorization path: the exact same
high-risk publishing tool is allowed, but it still writes only to the sandbox.

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
verified principal
  → input signatures + rate/anomaly checks
  → model authorization
  → LangChain secure runnable
  → registered tool + strict Pydantic arguments
  → immediate OPA-compatible decision
  → sandboxed execution
  → untrusted tool-output scan
  → HMAC-chained audit
```

The protected demo addresses:

- direct and indirect prompt injection signatures;
- excessive agency and unauthorized communication;
- unregistered tools and malformed/extra arguments;
- model and tool allow/deny policy;
- repeated abuse counters and identity containment;
- secret/prompt redaction and event traceability;
- accidental real-world side effects during demonstrations.

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
account—the focus.
