from __future__ import annotations

import json
from pathlib import Path

from .models import OAuthClient


def load_clients(path: str | Path) -> list[OAuthClient]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    clients: list[OAuthClient] = []
    for item in raw:
        clients.append(OAuthClient(
            client_id=item["client_id"],
            client_type=item["client_type"],
            redirect_uris=tuple(item["redirect_uris"]),
            grant_types=tuple(item["grant_types"]),
            pkce_required=bool(item["pkce_required"]),
            rotate_refresh_tokens=bool(item["rotate_refresh_tokens"]),
            access_token_ttl_minutes=int(item["access_token_ttl_minutes"]),
            refresh_token_ttl_days=int(item["refresh_token_ttl_days"]),
            owner=item.get("owner", ""),
            environment=item["environment"],
            audience=item.get("audience", ""),
            allow_http_redirects=bool(item.get("allow_http_redirects", False)),
            wildcard_redirects=bool(item.get("wildcard_redirects", False)),
            implicit_enabled=bool(item.get("implicit_enabled", False)),
            resource_owner_password_enabled=bool(item.get("resource_owner_password_enabled", False)),
            confidential_secret_managed=bool(item.get("confidential_secret_managed", True)),
        ))
    return clients
