# ZTAgent Rule IR and Rule Packs

Author: Victor Fang  
Website: https://VictorFang.com  
X: https://X.com/vicfcs  
LinkedIn: https://www.linkedin.com/in/drvictorfang  
Project: https://ztagent.ai

ZTAgent uses one canonical, declarative Rule IR for built-in, community, private, and
commercial guardrails. A pack cannot execute Python. It contains validated YAML rules,
optional test/documentation data, a manifest, and—when supplied commercially—a detached
Ed25519 signature.

## Execution architecture

The gateway takes one immutable rule snapshot and applies it at four trust boundaries:

1. `model_input` before a provider receives messages.
2. `model_output` before generated text is returned.
3. `tool_input` before policy authorization and tool execution.
4. `tool_output` before untrusted tool data can be reused.

Every finding includes the stage and pack name, version, and digest. Duplicate rule IDs,
invalid expressions, incompatible versions, and required packs that fail validation stop
gateway startup. Regex evaluation has a bounded timeout and fails closed.

The existing `config/signatures.yaml` remains supported as the local legacy pack. Its
default stages are model input, tool input, and tool output. New packs should use explicit
stages.

## Canonical Rule IR v1

`rules.yaml`:

```yaml
schema_version: 1
rules:
  - id: acme.customer-support.block-policy-override
    description: Block attempts to override the support agent policy
    stages: [model_input, model_output, tool_input, tool_output]
    engine: regex                 # regex or phrase
    pattern: '(?:ignore|bypass).{0,30}(?:policy|instructions?)'
    category: prompt-injection
    severity: high               # low, medium, high, critical
    action: block                # log, block, contain
    score: 90
    enabled: true
    case_sensitive: false
    timeout_ms: 25               # optional; bounded at 1–1000 ms
    metadata:
      control: ACME-AI-04
```

Unknown fields are rejected. IDs must be unique across all active packs and must begin
with `<publisher>.<pack-name>.`. This gives audit events a stable global identity.
Run `ztagent pack schema rules` (or `manifest` / `signature`) to export the
machine-readable JSON Schema from the installed core version.

`phrase` treats the pattern as literal text. `regex` is more expressive but should be
used narrowly. Neither engine runs code or performs network access.

## Pack manifest

`pack.yaml`:

```yaml
schema_version: 1
name: customer-support
version: 1.0.0
publisher: acme
description: Guardrails for customer-support agents
license: Apache-2.0
compatibility:
  core: '>=0.1,<1'
  rule_ir: 1
contents:
  - path: rules.yaml
    sha256: 4a1f...64-lowercase-hex-characters...
    kind: rules
```

Generate each content hash with `sha256sum rules.yaml`, update the manifest, then run:

```bash
ztagent pack validate ./customer-support
ztagent pack build ./customer-support --output customer-support.ztpack
ztagent pack validate ./customer-support.ztpack
```

Only declared YAML, JSON, Markdown, or text content is accepted. Undeclared files,
symlinks, traversal paths, encrypted ZIP entries, oversized archives, excessive YAML
aliases, hash mismatches, and unsupported schema versions are rejected.

## Activate packs

Activation is explicit:

```yaml
guardrails:
  signatures_file: config/signatures.yaml
  packs:
    - path: packs/customer-support.ztpack
      required: true
      require_signature: false
  require_signed_packs: false
```

An optional pack may use `required: false`; a missing optional path is skipped. A present
but invalid pack is never skipped.

## Commercial packs

Commercial packs use exactly the same Rule IR. The difference is controlled distribution,
license terms, publisher provenance, and a detached signature—not a privileged runtime
plugin API. This keeps commercial content optional and prevents purchased packs from
gaining code-execution rights.

A downloaded commercial release consists of:

- `pack.ztpack`
- `pack.signature.json`
- a trusted publisher public key delivered through a separate, authenticated channel

Trust store:

```yaml
schema_version: 1
keys:
  ztagent-commercial-2026: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
```

Verify and install before activation:

```bash
ztagent pack validate pack.ztpack \
  --signature pack.signature.json \
  --trust-store config/trusted-publishers.yaml \
  --require-signature

ztagent pack install pack.ztpack \
  --signature pack.signature.json \
  --trust-store config/trusted-publishers.yaml \
  --require-signature
```

Installed versions are immutable and are not automatically activated. Point the
configuration at the installed `pack.ztpack` and detached signature, then set
`require_signature: true`. `require_signed_packs: true` enforces signatures for every
configured pack.

Signature document:

```json
{
  "format": "ztagent-pack-signature-v1",
  "key_id": "ztagent-commercial-2026",
  "algorithm": "ed25519",
  "digest": "64-lowercase-hex-characters",
  "signature": "base64-ed25519-signature"
}
```

The signature covers the canonical SHA-256 digest of the exact manifest and declared
contents, independent of ZIP metadata. Entitlement checks belong in the authenticated
download service. The runtime verifies integrity and publisher identity and does not
phone home, so a licensing outage cannot silently weaken enforcement.

## Current scope

Rule IR v1 deliberately supports deterministic phrase and regex rules. Model-based judges,
Colang import, remote catalog updates, revocation metadata, and native-code plugins should
arrive behind separate interfaces and threat models. They should not expand this data-only
pack format.
