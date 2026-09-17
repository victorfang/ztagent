# Security policy

> **Author:** [Victor Fang](https://VictorFang.com) ·
> [X](https://X.com/vicfcs) ·
> [LinkedIn](https://www.linkedin.com/in/drvictorfang)

## Reporting

Please report suspected vulnerabilities privately through the repository
owner's GitHub security advisory channel. Do not include secrets, customer data,
working production credentials, or exploit traffic against systems you do not
own. Allow the maintainer to assess and coordinate a fix before disclosure.

## Supported versions

Until a stable release, only the latest version on the default branch receives
security fixes.

## Secure operation

- Never commit `.env`, provider credentials, identity tokens, or audit HMAC keys.
- Keep authentication and fail-closed OPA enforcement enabled in production.
- Treat signature and Rego changes as security-sensitive code changes.
- Do not expose OPA, SQLite state, the blocklist, or audit files publicly.
- Put high-impact tools behind least-privilege credentials, isolation, and human
  approval. Do not register generic shell or unrestricted HTTP tools.
- Export audit records to an access-controlled, append-only remote system.
- Review the limitations and checklist in `docs/architecture.md`.

Automated detection does not make arbitrary agent behavior trustworthy. The
system that executes an action must enforce authorization independently of
natural-language model output.
