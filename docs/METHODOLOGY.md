# Assessment and Validation Methodology

## Assessment sequence

1. Export or construct an approved OAuth/OIDC client inventory.
2. Validate client identifiers, environment, redirect URIs, grant types, token lifetimes, ownership, and client classification.
3. Run the offline assessment engine.
4. Triage findings by contextual risk score and production exposure.
5. Assign remediation ownership and target dates.
6. Re-export the configuration after changes and rerun the same controls.

## Remediation principles

- Prefer Authorization Code flow with PKCE for public clients.
- Use exact pre-registered redirect URIs and HTTPS in production.
- Remove legacy implicit and resource-owner-password flows.
- Keep bearer-token lifetimes proportionate to business and operational need.
- Rotate refresh tokens and detect reuse where the identity platform supports it.
- Manage confidential-client credentials in an approved secret lifecycle.
- Maintain accountable business and technical ownership for every client.

## Validation evidence

A finding should only be closed when configuration evidence demonstrates the control change and a safe validation proves the deprecated behavior is rejected. The report includes a validation statement for each control to make closure criteria explicit.

## MITRE ATT&CK context

Mappings such as T1528 (Steal Application Access Token), T1078 (Valid Accounts), T1552 (Unsecured Credentials), and T1557 (Adversary-in-the-Middle) are used to explain defensive relevance. They do not assert exploitation or compromise.

## Limitations

This project does not evaluate provider-specific implementation defects, cryptographic library vulnerabilities, consent-screen UX, runtime session behavior, API authorization logic, or actual token contents. Those require separate authorized testing and telemetry.
