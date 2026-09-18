# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""Project files emitted by the setup wizard."""

CONFIG_TEMPLATE = """# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

# ZTAgent configuration — secrets belong in the environment.
server:
  host: 127.0.0.1
  port: 8000
  environment: development
  admin_roles: [ztagent-admin]

auth:
  enabled: false  # Development only. Enable OIDC before production.
  issuer: https://keycloak.example/realms/agents
  audience: ztagent-core
  jwks_url: https://keycloak.example/realms/agents/protocol/openid-connect/certs
  algorithms: [RS256]
  role_claim: realm_access.roles

provider:
  kind: openai
  model: gpt-5-mini
  allowed_models: [gpt-5-mini]
  # api_key_env defaults to OPENAI_API_KEY or ANTHROPIC_API_KEY by provider.
  # For Kimi or another OpenAI-compatible server:
  # kind: openai-compatible
  # base_url: https://your-model-host/v1

policy:
  opa_url: http://127.0.0.1:8181
  decision_path: ztagent_core/authz/allow
  fail_open: false
  development_allow_without_opa: true  # Must be false in production.

guardrails:
  signatures_file: config/signatures.yaml
  regex_timeout_ms: 50
  max_prompt_chars: 100000
  block_score: 80

audit:
  path: data/audit.jsonl
  hmac_key_env: ZTAGENT_AUDIT_HMAC_KEY
  log_prompt_content: false

anomaly:
  enabled: true
  state_backend: sqlite
  sqlite_path: data/state.db
  requests_per_24h: 1000
  blocked_events_per_24h: 5

containment:
  enabled: true
  blocklist_path: data/blocked_identities.json
  # webhook_url: https://security-automation.example/contain
  # keycloak_admin_url: https://keycloak.example
  # keycloak_realm: agents
"""

SIGNATURES_TEMPLATE = r"""# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

version: 1
signatures:
  - id: pi.ignore-instructions
    description: Attempts to override prior or system instructions
    pattern: '(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?'
    category: prompt-injection
    severity: high
    action: block
    score: 90
  - id: pi.system-exfiltration
    description: Attempts to disclose hidden system or developer instructions
    pattern: >-
      (?:reveal|print|show|repeat|leak).{0,40}
      (?:system|developer|hidden)\s+(?:prompt|instructions?)
    category: prompt-exfiltration
    severity: high
    action: block
    score: 90
  - id: pi.role-impersonation
    description: Embedded role boundary or instruction marker
    pattern: '(?:^|\n)\s*(?:system|developer)\s*:\s*'
    category: prompt-injection
    severity: medium
    action: block
    score: 80
  - id: tool.shell-destructive
    description: Destructive shell command in a prompt or tool argument
    pattern: '(?:rm\s+-rf\s+[/~]|mkfs(?:\.|\s)|:\(\)\s*\{\s*:\|:&\s*\})'
    category: unsafe-tool-use
    severity: critical
    action: contain
    score: 100
"""

REGO_TEMPLATE = """# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

package ztagent_core.authz

import rego.v1

default allow := false

# Model requests require an authenticated subject.
allow if {
    input.action == "model.generate"
    input.subject != ""
}

# Low/medium-risk tools require an authenticated subject.
allow if {
    input.action == "tool.execute"
    input.subject != ""
    input.resource.risk in {"low", "medium"}
}

# High-risk tools require an explicit role.
allow if {
    input.action == "tool.execute"
    input.resource.risk == "high"
    "ztagent-tool-admin" in input.roles
}
"""

APP_TEMPLATE = '''# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""Starter ZTAgent application."""

from ztagent_core.api import create_app

app = create_app()
'''

ENV_TEMPLATE = """# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

# Generate with: ztagent secret
ZTAGENT_AUDIT_HMAC_KEY=replace-with-at-least-32-random-characters
OPENAI_API_KEY=
# ANTHROPIC_API_KEY=
# KEYCLOAK_ADMIN_TOKEN=
"""

COMPOSE_TEMPLATE = """# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

services:
  opa:
    image: openpolicyagent/opa:1.20.2-static
    command: ["run", "--server", "--log-format=json", "/policies"]
    ports: ["127.0.0.1:8181:8181"]
    volumes:
      - ./policies:/policies:ro
    read_only: true
    security_opt: ["no-new-privileges:true"]
    cap_drop: ["ALL"]
"""
