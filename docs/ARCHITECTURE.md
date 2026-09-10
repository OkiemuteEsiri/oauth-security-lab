# Architecture

## Purpose

`oauth-security-lab` is a defensive, offline assessment toolkit for reviewing exported OAuth 2.0 / OpenID Connect client configuration. It does not authenticate to live identity providers, request tokens, replay credentials, or exploit applications.

## Data flow

1. JSON inventory export enters the ingestion layer.
2. `OAuthClient` validates required fields and rejects invalid TTLs, environments, and client types.
3. The assessment engine evaluates explicit security controls.
4. Findings receive deterministic IDs, contextual risk scores, evidence, impact, remediation, validation criteria, and ATT&CK context where relevant.
5. The reporting layer renders a stakeholder-readable Markdown assessment.

## Modules

- `models.py` — immutable client/finding data contracts.
- `io.py` — strict JSON ingestion.
- `engine.py` — deterministic control evaluation and scoring.
- `report.py` — executive/technical Markdown rendering.
- `cli.py` — offline operator interface.

## Control coverage

Current controls include exact redirect URI governance, HTTPS redirects, PKCE for public clients, implicit grant retirement, password-grant retirement, refresh-token rotation, access-token lifetime, confidential-client secret governance, and ownership.

## Risk model

Risk is intentionally transparent rather than statistical. Each control has a base score. Production exposure adds contextual weight and missing ownership adds governance weight. Scores are bounded at 100 and converted to Critical/High/Medium/Low severity.

## Safety boundary

The project evaluates configuration metadata only. It contains no credential capture, token interception, phishing, brute force, consent abuse, redirect exploitation, or live target interaction.
