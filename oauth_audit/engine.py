from __future__ import annotations

import hashlib
from typing import Iterable, List

from .models import Finding, OAuthClient


def _severity(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _finding(client: OAuthClient, control: str, base: int, evidence: str, impact: str, remediation: str, validation: str, mitre: tuple[str, ...]) -> Finding:
    prod_bonus = 12 if client.environment == "prod" else 0
    owner_bonus = 8 if not client.owner.strip() else 0
    score = min(100, base + prod_bonus + owner_bonus)
    stable = hashlib.sha256(f"{client.client_id}:{control}".encode()).hexdigest()[:12]
    return Finding(f"OAUTH-{stable}", client.client_id, control, _severity(score), score, evidence, impact, remediation, validation, mitre)


def assess_client(client: OAuthClient) -> List[Finding]:
    findings: List[Finding] = []
    if client.wildcard_redirects:
        findings.append(_finding(client, "OAUTH-REDIRECT-WILDCARD", 78, "Wildcard redirect URI matching is enabled.", "Loose redirect matching can enable authorization responses to reach unintended endpoints.", "Replace wildcard matching with exact, pre-registered redirect URIs.", "Confirm authorization requests are rejected for every non-registered redirect URI.", ("T1528",)))
    if client.allow_http_redirects and client.environment == "prod":
        findings.append(_finding(client, "OAUTH-REDIRECT-HTTPS", 72, "Production client permits non-HTTPS redirect URIs.", "Authorization codes or tokens may be exposed over an unprotected transport path.", "Require HTTPS redirect URIs in production, except standards-defined loopback cases where applicable.", "Verify production redirect URIs use approved HTTPS endpoints only.", ("T1557",)))
    if client.client_type == "public" and not client.pkce_required:
        findings.append(_finding(client, "OAUTH-PKCE", 76, "Public client does not require PKCE.", "Intercepted authorization codes have weaker binding to the initiating client.", "Require Authorization Code flow with PKCE using S256.", "Attempt an authorization exchange without a valid code_verifier and confirm rejection.", ("T1528",)))
    if client.implicit_enabled:
        findings.append(_finding(client, "OAUTH-IMPLICIT", 62, "Implicit grant is enabled.", "Browser-delivered tokens increase exposure and bypass modern authorization-code protections.", "Disable implicit grant and use Authorization Code with PKCE.", "Confirm response_type=token requests are rejected.", ("T1528",)))
    if client.resource_owner_password_enabled:
        findings.append(_finding(client, "OAUTH-ROPC", 82, "Resource Owner Password Credentials grant is enabled.", "Applications directly handling user passwords expand credential exposure and weaken modern authentication controls.", "Disable the password grant and use browser-based authorization flows.", "Confirm password-grant token requests are rejected.", ("T1078",)))
    if not client.rotate_refresh_tokens:
        findings.append(_finding(client, "OAUTH-REFRESH-ROTATION", 58, "Refresh-token rotation is disabled.", "A stolen long-lived refresh token may remain reusable for its lifetime.", "Enable refresh-token rotation and reuse detection where supported.", "Redeem an old refresh token after rotation and confirm it is invalidated.", ("T1528",)))
    if client.access_token_ttl_minutes > 60:
        findings.append(_finding(client, "OAUTH-ACCESS-TTL", 45, f"Access-token TTL is {client.access_token_ttl_minutes} minutes.", "Long-lived bearer tokens increase the usable window after token disclosure.", "Reduce access-token lifetime according to application and operational requirements.", "Issue a token and verify the exp claim reflects the approved lifetime.", ("T1528",)))
    if client.client_type == "confidential" and not client.confidential_secret_managed:
        findings.append(_finding(client, "OAUTH-SECRET-GOVERNANCE", 70, "Confidential client secret is not marked as managed.", "Poor secret lifecycle controls increase risk of stale, exposed, or unrotated credentials.", "Use a managed secret store, rotation policy, ownership, and expiry monitoring.", "Verify secret storage, rotation evidence, and client continuity after rotation.", ("T1552",)))
    if not client.owner.strip():
        findings.append(_finding(client, "OAUTH-OWNERSHIP", 35, "No accountable application owner is recorded.", "Unowned clients are harder to remediate, review, and retire.", "Assign a business and technical owner with periodic recertification.", "Verify ownership metadata and review cadence are documented.", ()))
    return sorted(findings, key=lambda f: (-f.risk_score, f.finding_id))


def assess_clients(clients: Iterable[OAuthClient]) -> List[Finding]:
    seen = set()
    results: List[Finding] = []
    for client in clients:
        if client.client_id in seen:
            raise ValueError(f"duplicate client_id: {client.client_id}")
        seen.add(client.client_id)
        results.extend(assess_client(client))
    return sorted(results, key=lambda f: (-f.risk_score, f.client_id, f.finding_id))
