"""
Hidden parameter discovery via response diffing.
Finds hidden GET/POST params, headers, and cookies that change app behavior.
"""

import requests
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Huge list of common hidden parameters
PARAM_WORDLIST = [
    # Auth / session
    "id", "uid", "user_id", "userid", "user", "username", "login", "email",
    "password", "pass", "passwd", "token", "auth", "key", "api_key", "apikey",
    "secret", "session", "sid", "jwt", "access_token", "refresh_token",
    # Debug / admin
    "debug", "test", "admin", "internal", "dev", "staging", "verbose",
    "trace", "log", "mode", "env", "environment", "config", "setup",
    "install", "reset", "delete", "remove", "drop", "truncate",
    # Data / IDOR
    "account", "account_id", "profile", "profile_id", "order", "order_id",
    "item", "item_id", "product", "product_id", "invoice", "doc", "document",
    "file", "filename", "path", "dir", "folder", "report", "export",
    # Injection points
    "q", "query", "search", "s", "keyword", "term", "filter", "sort",
    "order", "orderby", "sort_by", "group", "group_by", "limit", "offset",
    "page", "p", "pg", "num", "count", "size", "per_page", "start", "end",
    # Redirect / SSRF
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnto", "return_to", "next", "next_url", "goto",
    "go", "to", "target", "dest", "destination", "redir", "out", "link",
    "continue", "continue_url", "forward", "ref", "referrer", "callback",
    "cb", "webhook", "hook", "notify_url", "postback",
    # File / template
    "file", "template", "tpl", "theme", "layout", "view", "include",
    "require", "load", "read", "fetch", "source", "src", "content",
    "body", "text", "data", "input", "output", "format", "type",
    # Misc
    "lang", "language", "locale", "country", "region", "currency",
    "action", "act", "do", "cmd", "command", "op", "operation", "func",
    "function", "method", "handler", "controller", "module", "plugin",
    "component", "widget", "service", "api", "version", "v", "ver",
    "channel", "source", "medium", "campaign", "tag", "label", "category",
    "name", "title", "description", "comment", "message", "msg", "note",
    "subject", "preview", "render", "display", "show", "hide", "visible",
    "enabled", "disabled", "active", "status", "state", "role", "permission",
    "scope", "grant", "allow", "deny", "block", "whitelist", "blacklist",
    "ip", "host", "port", "server", "proxy", "origin", "domain",
    "x-forwarded-for", "x-forwarded-host", "x-real-ip", "x-original-url",
    "x-rewrite-url", "x-custom-ip-authorization",
]

HEADER_WORDLIST = [
    "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Originating-IP",
    "X-Remote-IP", "X-Client-IP", "X-Remote-Addr", "True-Client-IP",
    "CF-Connecting-IP", "X-Forwarded-Proto", "X-Forwarded-Scheme",
    "X-Frame-Options", "X-Api-Key", "X-Auth-Token", "Authorization",
    "X-Debug", "X-Debug-Token", "X-Debug-Mode", "X-Test", "X-Internal",
    "X-Admin", "X-Bypass", "X-Override", "X-Method-Override",
    "X-HTTP-Method-Override", "X-Request-Id", "X-Correlation-Id",
    "X-Trace-Id", "X-Amz-Date", "X-Api-Version", "X-Requested-With",
    "Origin", "Referer", "Host",
]

COOKIE_WORDLIST = [
    "admin", "debug", "test", "role", "user", "auth", "session", "token",
    "isAdmin", "is_admin", "isLoggedIn", "is_logged_in", "privilege",
    "access_level", "user_role", "internal", "dev", "staging", "bypass",
    "language", "lang", "theme", "mode", "dark_mode", "beta", "feature_flag",
]


def _baseline_response(url, method="GET"):
    """Get baseline response for diffing."""
    try:
        if method == "GET":
            r = requests.get(url, timeout=10, headers=HDR, verify=False)
        else:
            r = requests.post(url, timeout=10, headers=HDR, verify=False)
        return {
            "status": r.status_code,
            "len": len(r.text),
            "headers": dict(r.headers),
            "body_hash": hashlib.md5(r.text.encode()).hexdigest(),
            "body": r.text,
        }
    except Exception:
        return None


def _response_differs(r, baseline, threshold=50):
    """Check if response differs significantly from baseline."""
    if not baseline or not r:
        return False, []
    diffs = []
    if r.status_code != baseline["status"]:
        diffs.append(f"status: {baseline['status']} → {r.status_code}")
    len_diff = abs(len(r.text) - baseline["len"])
    if len_diff > threshold:
        diffs.append(f"length: {baseline['len']} → {len(r.text)} (Δ{len_diff})")
    body_hash = hashlib.md5(r.text.encode()).hexdigest()
    if body_hash != baseline["body_hash"] and len_diff <= threshold:
        diffs.append("content changed (same length)")
    # Check for new headers
    for h in r.headers:
        if h.lower() not in [k.lower() for k in baseline["headers"]]:
            diffs.append(f"new header: {h}: {r.headers[h][:60]}")
    return len(diffs) > 0, diffs


def param_mine(target, method="GET", stream_callback=None):
    """
    Discover hidden parameters by fuzzing and comparing responses.
    Tests GET params, POST params, headers, and cookies.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("paramminer_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base_url = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 Mining hidden parameters on {base_url}")
    start = time.time()
    findings = []

    # Get baseline
    _emit("📊 Establishing baseline response...")
    bl = _baseline_response(base_url, method)
    if not bl:
        return format_unreachable_error(target, resolution)

    _emit(f"  Baseline: status={bl['status']}, length={bl['len']}")

    # ── Phase 1: GET/POST Parameter fuzzing ──
    _emit(f"🔍 Testing {len(PARAM_WORDLIST)} parameters ({method})...")
    tested = 0

    def _test_param(param):
        canary = f"pm{int(time.time())%9999}"
        try:
            if method == "GET":
                r = requests.get(f"{base_url}?{param}={canary}", timeout=6, headers=HDR, verify=False)
            else:
                r = requests.post(base_url, data={param: canary}, timeout=6, headers=HDR, verify=False)
            differs, diffs = _response_differs(r, bl)
            if differs:
                return {"type": "param", "name": param, "method": method, "diffs": diffs, "status": r.status_code}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_test_param, p): p for p in PARAM_WORDLIST}
        for future in as_completed(futures):
            tested += 1
            if tested % 30 == 0:
                _emit(f"  Params: {tested}/{len(PARAM_WORDLIST)} tested, {len(findings)} hits...")
            result = future.result()
            if result:
                findings.append(result)
                _emit(f"  ✅ HIT: ?{result['name']} changes response ({', '.join(result['diffs'][:2])})")

    # ── Phase 2: Header fuzzing ──
    _emit(f"🔍 Testing {len(HEADER_WORDLIST)} headers...")

    def _test_header(header):
        try:
            custom_hdr = {**HDR, header: "127.0.0.1"}
            r = requests.get(base_url, timeout=6, headers=custom_hdr, verify=False)
            differs, diffs = _response_differs(r, bl)
            if differs:
                return {"type": "header", "name": header, "diffs": diffs, "status": r.status_code}
        except Exception:
            pass
        # Try with different values
        for val in ["admin", "true", "1", "localhost", "internal"]:
            try:
                custom_hdr = {**HDR, header: val}
                r = requests.get(base_url, timeout=6, headers=custom_hdr, verify=False)
                differs, diffs = _response_differs(r, bl)
                if differs:
                    return {"type": "header", "name": header, "value": val, "diffs": diffs, "status": r.status_code}
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_test_header, h): h for h in HEADER_WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                _emit(f"  ✅ HIT: Header '{result['name']}' changes response ({', '.join(result['diffs'][:2])})")

    # ── Phase 3: Cookie fuzzing ──
    _emit(f"🍪 Testing {len(COOKIE_WORDLIST)} cookies...")

    def _test_cookie(cookie):
        for val in ["true", "1", "admin"]:
            try:
                r = requests.get(base_url, timeout=6, headers=HDR, cookies={cookie: val}, verify=False)
                differs, diffs = _response_differs(r, bl)
                if differs:
                    return {"type": "cookie", "name": cookie, "value": val, "diffs": diffs, "status": r.status_code}
            except Exception:
                pass
        return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_test_cookie, c): c for c in COOKIE_WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                _emit(f"  ✅ HIT: Cookie '{result['name']}={result.get('value','')}' changes response")

    # ── Phase 4: Interesting value testing on found params ──
    interesting_values = {
        "debug": ["true", "1", "on", "yes"],
        "admin": ["true", "1"],
        "test": ["true", "1"],
        "role": ["admin", "root", "superuser"],
        "id": ["1", "0", "-1", "999999"],
        "user_id": ["1", "0", "admin"],
        "format": ["json", "xml", "csv"],
        "callback": ["test", "alert(1)"],
    }

    param_findings = [f for f in findings if f["type"] == "param"]
    for pf in param_findings:
        name = pf["name"]
        if name in interesting_values:
            for val in interesting_values[name]:
                try:
                    if method == "GET":
                        r = requests.get(f"{base_url}?{name}={val}", timeout=6, headers=HDR, verify=False)
                    else:
                        r = requests.post(base_url, data={name: val}, timeout=6, headers=HDR, verify=False)
                    differs, diffs = _response_differs(r, bl)
                    if differs:
                        pf.setdefault("interesting_values", []).append({"value": val, "diffs": diffs})
                except Exception:
                    pass

    elapsed = time.time() - start

    # Format output
    lines = [
        f"HIDDEN PARAMETER MINING for {base_url}",
        f"{'='*60}",
        f"Tested: {len(PARAM_WORDLIST)} params, {len(HEADER_WORDLIST)} headers, {len(COOKIE_WORDLIST)} cookies",
        f"Found: {len(findings)} hidden parameters in {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if not findings:
        lines.append("No hidden parameters found that change application behavior.")
        return "\n".join(lines)

    # Group by type
    for ftype, label in [("param", "HIDDEN PARAMETERS"), ("header", "SENSITIVE HEADERS"), ("cookie", "SENSITIVE COOKIES")]:
        group = [f for f in findings if f["type"] == ftype]
        if group:
            lines.append(f"📋 {label} ({len(group)} found)")
            lines.append("-" * 40)
            for f in group:
                diffs_str = ", ".join(f["diffs"][:3])
                if ftype == "param":
                    lines.append(f"  🔴 ?{f['name']} — {diffs_str}")
                    if f.get("interesting_values"):
                        for iv in f["interesting_values"]:
                            lines.append(f"     → {f['name']}={iv['value']}: {', '.join(iv['diffs'][:2])}")
                elif ftype == "header":
                    lines.append(f"  🔴 {f['name']}: {f.get('value', '127.0.0.1')} — {diffs_str}")
                else:
                    lines.append(f"  🔴 Cookie {f['name']}={f.get('value', 'true')} — {diffs_str}")
            lines.append("")

    # Security implications
    lines.append("SECURITY IMPLICATIONS")
    lines.append("-" * 40)
    debug_params = [f for f in findings if f["name"] in ("debug", "test", "verbose", "trace", "internal", "dev")]
    if debug_params:
        lines.append("  ⚠️ DEBUG/TEST parameters found — may expose sensitive info or bypass security")
    auth_params = [f for f in findings if f["name"] in ("admin", "role", "isAdmin", "privilege", "access_level")]
    if auth_params:
        lines.append("  ⚠️ AUTH/ROLE parameters found — possible privilege escalation")
    redirect_params = [f for f in findings if f["name"] in ("url", "redirect", "next", "goto", "callback")]
    if redirect_params:
        lines.append("  ⚠️ REDIRECT parameters found — test for SSRF and open redirect")
    header_findings = [f for f in findings if f["type"] == "header"]
    if header_findings:
        ip_headers = [f for f in header_findings if "ip" in f["name"].lower() or "forward" in f["name"].lower()]
        if ip_headers:
            lines.append("  ⚠️ IP-spoofing headers accepted — possible ACL bypass / admin access")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "param_mine",
        "description": "Discover hidden GET/POST parameters, headers, and cookies that change application behavior. Fuzzes 150+ common param names, 35+ headers, and 30+ cookies against a target URL by comparing response differences. Finds debug params, auth bypass headers (X-Forwarded-For, X-Original-URL), hidden API params, IDOR vectors, and more.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to mine parameters on"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method for parameter testing. Default: GET"
                }
            },
            "required": ["target"]
        }
    }
}
