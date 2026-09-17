# ztagent-core

Open-source AI agent security gateway from **[ztagent.ai](https://ztagent.ai)**.

Author: **[Victor Fang](https://VictorFang.com)** ·
[X](https://X.com/vicfcs) ·
[LinkedIn](https://www.linkedin.com/in/drvictorfang)

`ztagent-core` puts one enforcement pipeline in front of model and tool calls.
It provides useful secure defaults without replacing your identity provider,
reverse proxy, model host, or SIEM.

## Editions and services

| Offering | What it is |
|---|---|
| **ztagent-core** (this repository) | Apache-2.0 foundation you can self-host, audit, and extend |
| **ztagent Enterprise** | Commercial edition for production organizations (coming) |
| **Consulting** | Custom policy, tools, threat modeling, and deployment help |

Use Core when you want a compact, inspectable security boundary. Enterprise is
planned for teams that need vendor-supported controls beyond the open-source
core. Until that ships, [ztagent.ai](https://ztagent.ai) offers consulting to
customize the gateway for your identity, policy, and tool landscape.

Contact: [ztagent.ai](https://ztagent.ai) · [VictorFang.com](https://VictorFang.com) ·
[LinkedIn](https://www.linkedin.com/in/drvictorfang)

> This is a security foundation, not a claim that signature matching makes an AI
> system completely safe. Prompt injection is not a solved problem. Layer the
> gateway with least-privilege tools, sandboxing, egress controls, human approval
> for consequential actions, and application-specific evaluation.

## What is included

- FastAPI-based API gateway with request limits and security headers
- OIDC JWT validation for Keycloak, Auth0, and compatible identity providers
- OPA policy enforcement point/client with fail-closed production defaults
- Registered, schema-validated tool gateway with risk metadata
- YAML signature rules with Unicode normalization and regex timeouts
- OpenAI Responses, Anthropic Messages, and OpenAI-compatible model APIs
- Optional LangChain `Runnable` adapter; the core remains orchestrator-neutral
- Stateless request heuristics and memory/SQLite rolling 24-hour counters
- HMAC-chained JSONL audit records with default secret/prompt redaction
- Local identity containment, optional webhook, and Keycloak session revocation
- Protected, dependency-free web administration portal
- Friendly project wizard and operational checks

## Quick start

Requires Python 3.11+ and, for policy enforcement, Docker or an OPA service.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Create a separate starter project, or use this repository's included example.
ztagent init my-agent
cd my-agent
cp .env.example .env
ztagent secret                         # put output in ZTAGENT_AUDIT_HMAC_KEY
set -a; source .env; set +a
docker compose up -d
ztagent check
ztagent serve
```

Open <http://127.0.0.1:8000/admin>. Development defaults disable authentication;
the portal therefore uses a development administrator. Production configuration
validation refuses disabled authentication or an OPA bypass.

Call the gateway:

```bash
curl http://127.0.0.1:8000/v1/agent/run \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_OIDC_TOKEN' \
  -d '{"messages":[{"role":"user","content":"Summarize this report"}]}'
```

## Provider setup

Set `provider.kind` in `config/agent.yaml`:

| Provider | `kind` | Key environment variable | Notes |
|---|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` | Uses `/v1/responses`, with storage disabled |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | Uses `/v1/messages` |
| Kimi/self-hosted | `openai-compatible` | configurable | Set the server's `/v1` `base_url` |

Models are deny-by-default: a requested model must appear in `allowed_models`.
API keys are read only from environment variables and are never returned or
written to audit events.

## Identity and policy

Configure the issuer, audience, JWKS URL, fixed asymmetric algorithms, and role
claim under `auth`. ztagent-core verifies signature, expiration, issued-at, issuer,
audience, and subject. Do not derive accepted JWT algorithms from a token.

The gateway is the policy enforcement point (PEP). It sends only identity,
roles, action, resource metadata, source IP, and request ID to OPA (the PDP).
Prompts and tool arguments are not sent to OPA. The starter Rego policy allows:

- authenticated model calls;
- low/medium-risk tools for authenticated identities;
- high-risk tools only for the `ztagent-tool-admin` role.

Tailor `policies/authz.rego` to tenant, model, tool, data classification, and
business approval requirements. OPA is bound to loopback in `compose.yaml`.

## Add a tool

```python
from pydantic import BaseModel
from ztagent_core.tools import ToolRegistry, ToolSpec


class LookupArgs(BaseModel):
    ticket_id: str


registry = ToolRegistry()
registry.register(
    ToolSpec(
        name="lookup_ticket",
        description="Read one support ticket",
        arguments=LookupArgs,
        handler=lambda args: {"id": args.ticket_id},
        risk="low",
    )
)
```

Pass the registry to `create_gateway(config, registry)`, then to
`create_app(config, gateway)`. Every `/v1/tools/{name}` request receives
authentication, signature scanning, OPA authorization, validation, and audit.
The registry intentionally has no shell, filesystem, or arbitrary HTTP tool.

## LangChain

```bash
pip install -e '.[langchain]'
```

```python
from ztagent_core.integrations import as_langchain_runnable

secure_node = as_langchain_runnable(gateway, principal)
result = await secure_node.ainvoke({"messages": [{"role": "user", "content": "Hello"}]})
```

The application must derive `principal` from a verified request; never accept
identity or roles from model output or untrusted chain state.

## Before/after demo agents

Install the demo extra and run three small LangChain applications:

```bash
pip install -e '.[demos]'
ztagent demo stock-injection
ztagent demo unauthorized-publish
ztagent demo article-only
```

Each command contrasts a deliberately vulnerable baseline with the protected
framework path. The examples cover an indirect prompt injection hidden in stock
data, unauthorized article publishing, and a safe article-only workflow.
Email, DM, and social actions always remain in a local JSONL sandbox.

Use `--live` to exercise the configured OpenAI API or stay with the default
deterministic offline model for a repeatable, credential-free security demo.
See [docs/demos.md](docs/demos.md) for expected output, the exact controls being
demonstrated, and important limitations.

## CLI

```text
ztagent init [DIRECTORY]   Generate config, signatures, Rego, Compose, and app files
ztagent secret             Generate a strong audit HMAC key
ztagent check              Validate configuration and signatures; flag dev bypasses
ztagent demo               Compare vulnerable and secured LangChain demo agents
ztagent serve              Start the gateway and portal
```

## Architecture and security scope

See [docs/architecture.md](docs/architecture.md) for the request flow, threat
coverage, design decisions, limitations, deployment checklist, and research
references. See [SECURITY.md](SECURITY.md) for vulnerability reporting and
operational security guidance. The
[blast-radius threat-modeling tutorial](docs/blast-radius-threat-modeling.md)
provides worked examples for the included agents.

## Development

```bash
pip install -e '.[dev]'
ruff check .
mypy
pytest
```

Apache-2.0 licensed (`ztagent-core`). Product site: [ztagent.ai](https://ztagent.ai).
