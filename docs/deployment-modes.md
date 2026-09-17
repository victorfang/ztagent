# ZTAgent Deployment Modes: API Gateway and Python SDK

> **Author:** [Victor Fang](https://VictorFang.com) ·
> [ztagent.ai](https://ztagent.ai) ·
> [X](https://X.com/vicfcs) ·
> [LinkedIn](https://www.linkedin.com/in/drvictorfang)

`ztagent-core` can be used in two supported ways:

1. as a deployable **AI security API gateway**;
2. as an embeddable **Python security SDK**.

Both modes use the same `SecureAgentGateway` enforcement pipeline. The
difference is where that pipeline runs and who is responsible for establishing
trusted identity.

## Important terminology

ZTAgent is an **application-layer AI security gateway**. It protects model calls
and registered tool execution with AI-specific controls: identity, policy,
prompt/tool-output detection, anomaly rules, audit, and containment.

It is not a replacement for an edge gateway or reverse proxy such as AWS API
Gateway, Azure API Management, Kong, Envoy, NGINX, or a cloud load balancer.
Production deployments should still place an edge component in front for TLS
termination, network-level rate limits, request routing, DDoS controls, and
forwarded-header sanitization.

## Mode 1: API gateway

Run the included FastAPI service:

```bash
export ZTAGENT_AUDIT_HMAC_KEY="$(ztagent secret)"
docker compose up -d
ztagent serve
```

The service exposes:

| Endpoint | Purpose |
|---|---|
| `POST /v1/agent/run` | Authenticate, authorize, inspect, and route a model request |
| `POST /v1/tools/{tool_name}` | Authenticate, authorize, validate, and execute a registered tool |
| `GET /health` | Process health |
| `GET /admin` | Protected administration portal |
| `/admin/api/*` | Role-protected audit and containment administration |

Example:

```bash
curl http://127.0.0.1:8000/v1/agent/run \
  -H 'Authorization: Bearer YOUR_OIDC_ACCESS_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"Summarize this report"}]}'
```

### What the API gateway mode provides

- one language-neutral HTTP boundary for Python, JavaScript, Java, Go, and other
  clients;
- OIDC bearer-token verification at ingress;
- request-body limits and HTTP security headers;
- one place to enforce model and tool policy;
- centralized audit, anomaly state, containment, and administration;
- provider credentials kept out of client applications.

### Best fit

Choose API gateway mode when:

- several applications, teams, languages, or agents share security policy;
- model credentials should be centralized;
- operations needs one service to monitor and contain;
- independent rollout of security controls is important;
- clients are not all Python.

### Production topology

```text
Internet / private clients
  → edge API gateway or reverse proxy
  → ztagent-core FastAPI service
      → OPA sidecar
      → model providers
      → registered tools
      → shared production audit/rate-limit backends
```

The included SQLite and JSONL backends are intended for one-process, small
deployments. Replace them with concurrency-safe shared services before running
multiple workers or replicas.

## Mode 2: Python SDK

Install and import the package directly:

```bash
pip install ztagent-core
```

Model-call example:

```python
from ztagent_core.api import create_gateway
from ztagent_core.auth import JWTAuthenticator
from ztagent_core.config import load_config
from ztagent_core.models import AgentRequest, Message

config = load_config("config/agent.yaml")
gateway = create_gateway(config)
authenticator = JWTAuthenticator(config.auth)

# The token must come from the application's authenticated request boundary.
principal = authenticator.verify(access_token)

response = await gateway.run(
    AgentRequest(
        messages=[Message(role="user", content="Summarize this report")]
    ),
    principal,
    source_ip=request_source_ip,
)
print(response.output)
```

Registered-tool example:

```python
from pydantic import BaseModel, ConfigDict

from ztagent_core.api import create_gateway
from ztagent_core.tools import ToolRegistry, ToolSpec


class TicketArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_id: str


registry = ToolRegistry()
registry.register(
    ToolSpec(
        name="lookup_ticket",
        description="Read one support ticket",
        arguments=TicketArguments,
        handler=lambda args: {"id": args.ticket_id, "status": "open"},
        risk="low",
    )
)

gateway = create_gateway(config, registry)
result = await gateway.execute_tool(
    "lookup_ticket",
    {"ticket_id": "TKT-123"},
    principal,
)
```

LangChain applications can use the supplied adapter:

```python
from ztagent_core.integrations import as_langchain_runnable

secure_node = as_langchain_runnable(gateway, principal)
result = await secure_node.ainvoke(
    {"messages": [{"role": "user", "content": "Draft a release note"}]}
)
```

### What SDK mode provides

- the same model/tool scanning, OPA decisions, anomaly rules, audit, and
  containment pipeline without an HTTP hop;
- Python-native models and extension points;
- straightforward integration with existing Python orchestrators and workers;
- application-controlled lifecycle and tool registration.

### Caller responsibilities

SDK mode does not automatically create an HTTP trust boundary. The embedding
application must:

- validate the access token and derive `Principal` from trusted claims;
- never accept `subject`, roles, tenant, or approval state from model output or
  untrusted request JSON;
- enforce request-size, edge rate, TLS, CSRF, and browser controls where
  applicable;
- ensure every model and tool path calls the SDK rather than provider clients or
  handlers directly;
- control provider/tool egress so a bypass cannot call them independently;
- use shared audit and rate-limit backends when multiple processes need one
  security state.

Constructing `Principal(subject="...", roles=...)` is appropriate in tests and
the offline demo, but it is not production authentication.

### Best fit

Choose SDK mode when:

- the agent is already a Python service or worker;
- low in-process latency matters;
- tool handlers are tightly coupled to application code;
- one team owns both the application and its security lifecycle;
- custom orchestrator integration is more important than a shared HTTP service.

## Mode 3: hybrid

A larger deployment can use both:

```text
external clients → ZTAgent API gateway → agent service
                                         └→ ZTAgent SDK before local tools
```

Use the API service for centralized ingress/model governance and the SDK at a
separate worker or tool trust boundary. Define clear ownership to avoid:

- duplicate model calls or tool execution;
- unrelated request IDs and duplicate audit events;
- inconsistent policies between gateway and worker;
- trusting identity headers that an untrusted client can forge.

Pass identity only over an authenticated service-to-service channel and
correlate decisions with an application trace ID. Each high-impact tool must
still authorize immediately before execution.

## Selection guide

| Requirement | API gateway | Python SDK |
|---|:---:|:---:|
| Non-Python clients | **Best** | No |
| Central provider credentials | **Best** | Per application |
| Central administration | **Best** | Custom/in-process |
| No internal HTTP hop | No | **Best** |
| Python-native customization | Good | **Best** |
| Ingress JWT verification included | **Yes** | Caller invokes/owns it |
| Request limits/security headers | **Yes** | Caller responsibility |
| Core model/tool security pipeline | **Yes** | **Yes** |
| OPA policy support | **Yes** | **Yes** |
| LangChain integration | Via HTTP or server code | **Direct** |

For most small Python-only projects, start with SDK mode. For multiple agents,
languages, teams, or centralized credentials, start with API gateway mode.

## Security rule that applies to both

Deployment mode does not change the fundamental boundary:

```text
untrusted request/data/model output
  → trusted identity and context
  → ZTAgent policy enforcement
  → registered, least-privilege operation
  → audit and response
```

If code can call a provider or tool handler around ZTAgent, the control is
optional and therefore bypassable. Reinforce the software path with credential
separation and network policy.
