import unittest

from oauth_audit.engine import assess_client, assess_clients
from oauth_audit.models import OAuthClient


def client(**overrides):
    values = dict(
        client_id="app-1",
        client_type="public",
        redirect_uris=("https://app.example.test/callback",),
        grant_types=("authorization_code",),
        pkce_required=True,
        rotate_refresh_tokens=True,
        access_token_ttl_minutes=30,
        refresh_token_ttl_days=7,
        owner="App Team",
        environment="prod",
        audience="api",
    )
    values.update(overrides)
    return OAuthClient(**values)


class EngineTests(unittest.TestCase):
    def test_secure_baseline_has_no_findings(self):
        self.assertEqual(assess_client(client()), [])

    def test_public_client_without_pkce_is_high_risk(self):
        findings = assess_client(client(pkce_required=False))
        self.assertEqual(findings[0].control, "OAUTH-PKCE")
        self.assertGreaterEqual(findings[0].risk_score, 65)

    def test_wildcard_redirect_is_detected(self):
        controls = {f.control for f in assess_client(client(wildcard_redirects=True))}
        self.assertIn("OAUTH-REDIRECT-WILDCARD", controls)

    def test_password_grant_is_detected(self):
        controls = {f.control for f in assess_client(client(resource_owner_password_enabled=True))}
        self.assertIn("OAUTH-ROPC", controls)

    def test_long_access_token_ttl_is_detected(self):
        controls = {f.control for f in assess_client(client(access_token_ttl_minutes=180))}
        self.assertIn("OAUTH-ACCESS-TTL", controls)

    def test_unmanaged_confidential_secret_is_detected(self):
        c = client(client_type="confidential", confidential_secret_managed=False)
        controls = {f.control for f in assess_client(c)}
        self.assertIn("OAUTH-SECRET-GOVERNANCE", controls)

    def test_duplicate_client_ids_fail_closed(self):
        with self.assertRaises(ValueError):
            assess_clients([client(), client()])

    def test_finding_ids_are_deterministic(self):
        a = assess_client(client(pkce_required=False))[0].finding_id
        b = assess_client(client(pkce_required=False))[0].finding_id
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
