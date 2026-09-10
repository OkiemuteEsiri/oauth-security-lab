from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    client_type: str
    redirect_uris: Tuple[str, ...]
    grant_types: Tuple[str, ...]
    pkce_required: bool
    rotate_refresh_tokens: bool
    access_token_ttl_minutes: int
    refresh_token_ttl_days: int
    owner: str
    environment: str
    audience: str
    allow_http_redirects: bool = False
    wildcard_redirects: bool = False
    implicit_enabled: bool = False
    resource_owner_password_enabled: bool = False
    confidential_secret_managed: bool = True

    def __post_init__(self) -> None:
        if not self.client_id.strip():
            raise ValueError("client_id is required")
        if self.client_type not in {"public", "confidential"}:
            raise ValueError("client_type must be public or confidential")
        if self.environment not in {"dev", "test", "prod"}:
            raise ValueError("environment must be dev, test, or prod")
        if self.access_token_ttl_minutes <= 0 or self.refresh_token_ttl_days <= 0:
            raise ValueError("token TTL values must be positive")
        if not self.redirect_uris:
            raise ValueError("at least one redirect URI is required")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    client_id: str
    control: str
    severity: str
    risk_score: int
    evidence: str
    impact: str
    remediation: str
    validation: str
    mitre_attack: Tuple[str, ...] = field(default_factory=tuple)
