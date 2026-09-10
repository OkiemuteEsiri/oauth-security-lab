# OAuth Security Lab

Defensive OAuth 2.0 / OpenID Connect configuration assessment toolkit for reviewing exported client registrations, identifying risky identity configuration, prioritizing remediation, and validating closure without interacting with live identity providers.

## Problem statement

OAuth/OIDC deployments often accumulate legacy grant types, weak redirect URI governance, excessive token lifetimes, missing PKCE, unmanaged client secrets, and unclear ownership. These weaknesses can increase the impact of token theft, credential exposure, or authorization-flow abuse even when the identity provider itself is functioning correctly.

This project converts exported configuration metadata into deterministic, explainable security findings suitable for engineering triage and governance review.

## Architecture

```text
JSON client inventory
        |
        v
 strict ingestion + validation
        |
        v
 control evaluation engine
        |
        +--> contextual risk scoring
        +--> deterministic finding IDs
        +--> evidence / impact / remediation
        +--> closure validation criteria
        |
        v
 Markdown assessment report
```

See `docs/ARCHITECTURE.md` for component design and `docs/METHODOLOGY.md` for remediation/revalidation methodology.

## Implemented controls

- exact redirect URI governance / wildcard detection
- HTTPS redirect enforcement for production clients
- PKCE requirement for public clients
- implicit grant retirement
- Resource Owner Password Credentials grant retirement
- refresh-token rotation
- access-token lifetime review
- confidential-client secret lifecycle governance
- application ownership and accountability

## Usage

```bash
python -m oauth_audit.cli data/sample_clients.json --output oauth-assessment.md
```

The supplied dataset is synthetic and uses reserved/example-style hostnames. The tool performs no network requests.

## Risk model

Each control has a transparent base score. Production configuration adds contextual weight, and missing ownership adds governance weight. Scores are bounded at 100 and classified as:

| Score | Severity |
|---:|---|
| 85–100 | Critical |
| 65–84 | High |
| 40–64 | Medium |
| 0–39 | Low |

The model is intentionally explainable rather than presented as a statistical probability of compromise.

## MITRE ATT&CK context

Relevant defensive mappings include:

- **T1528 — Steal Application Access Token**
- **T1078 — Valid Accounts**
- **T1552 — Unsecured Credentials**
- **T1557 — Adversary-in-the-Middle**

Mappings provide threat-model context only. They do not claim exploitation occurred.

## Testing

`tests/test_engine.py` covers secure baselines, PKCE, redirect governance, legacy grants, excessive token lifetime, secret governance, duplicate input rejection, and deterministic IDs.

GitHub Actions performs source compilation, the unit-test suite, an offline CLI smoke test, and generated-report validation using read-only repository permissions.

## Remediation and validation workflow

1. Export approved client configuration.
2. Run the assessment and assign owners to findings.
3. Remediate configuration in the identity platform through normal change control.
4. Export configuration again.
5. Rerun the same controls.
6. Use each finding's explicit validation criterion before closure.

## Skills demonstrated

- OAuth 2.0 / OIDC security architecture
- identity and access security engineering
- secure configuration assessment
- risk-based prioritization
- deterministic Python engineering
- defensive reporting and remediation governance
- unit testing and CI/CD quality gates

## Limitations

This repository does not test live authorization servers, inspect real tokens, verify provider-specific cryptography, assess user consent UX, or evaluate downstream API authorization. It is a configuration-posture project, not an exploitation framework.

## Safety

No credentials, token capture, phishing, redirect exploitation, password attacks, consent abuse, or production targeting are included. Use only synthetic or explicitly authorized exported configuration data.

## Roadmap

- provider-neutral policy profiles
- OIDC-specific controls for response modes and signing requirements
- machine-readable JSON/SARIF output
- configuration-drift comparison
- control exceptions with expiry and approval metadata
- provider adapters that consume offline exports rather than live credentials
