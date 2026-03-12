"""
Security header analysis — checks for missing/misconfigured HTTP security headers.
Also detects server info leakage and cookie security issues.
"""

import requests
import time
from urllib.parse import urlparse

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": "Missing HSTS — MitM downgrade attacks possible. Attacker on same network can strip HTTPS.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "desc": "Missing CSP — XSS exploitation is trivial without it. No restrictions on script sources.",
        "fix": "Add restrictive CSP: script-src 'self'; object-src 'none'; base-uri 'self'",
        "cwe": "CWE-1021",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "Missing X-Frame-Options — clickjacking attacks possible. Page can be iframed.",
        "fix": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "desc": "Missing X-Content-Type-Options — MIME-sniffing attacks possible.",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-16",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Missing Referrer-Policy — URLs with sensitive data may leak via Referer header.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "desc": "Missing Permissions-Policy — browser features not restricted (camera, mic, geolocation).",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "cwe": "CWE-16",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "desc": "Missing X-XSS-Protection — legacy XSS filter not enabled (mainly for older IE).",
        "fix": "Add: X-XSS-Protection: 1; mode=block (or rely on CSP instead)",
        "cwe": "CWE-79",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "desc": "Missing COOP — page may be vulnerable to cross-origin attacks via window references.",
        "fix": "Add: Cross-Origin-Opener-Policy: same-origin",
        "cwe": "CWE-346",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "desc": "Missing CORP — resources may be loaded by other origins.",
        "fix": "Add: Cross-Origin-Resource-Policy: same-origin",
        "cwe": "CWE-346",
    },
}

# Headers that leak server info
INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Runtime", "X-Version", "X-Generator", "X-Drupal-Cache",
    "X-Varnish", "X-Cache", "Via", "X-Backend-Server",
    "X-Served-By", "X-Litespeed-Cache", "X-Turbo-Charged-By",
]

# Dangerous CSP directives
DANGEROUS_CSP = {
    "unsafe-inline": "Allows inline scripts — XSS still exploitable",
    "unsafe-eval": "Allows eval() — XSS escalation via eval",
    "data:": "Allows data: URIs in scripts — XSS via data:text/html",
    "*.googleapis.com": "Google APIs CDN — JSONP callback abuse possible",
    "*.google.com": "Broad Google domain — potential CSP bypass via JSONP",
    "*.cloudflare.com": "Broad Cloudflare — CDN hosting arbitrary JS",
    "*.amazonaws.com": "AWS — attacker-controlled S3 bucket can host JS",
    "blob:": "Allows blob: URIs — can be used to bypass CSP",
    "*": "Wildcard — CSP is effectively disabled",
}


def header_audit(target, stream_callback=None):
    """Audit HTTP security headers, cookie security, and server info leakage."""
    def _emit(msg):
        if stream_callback:
            stream_callback("headeraudit_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 Auditing security headers: {base}")
    start = time.time()

    try:
        r = requests.get(base, timeout=10, headers=HDR, verify=False, allow_redirects=True)
    except Exception:
        return format_unreachable_error(target, resolution)

    headers = dict(r.headers)
    findings = []
    score = 100  # Start at 100, deduct for each issue

    # ── Check security headers ──
    _emit("🔍 Checking security headers...")
    for header, info in SECURITY_HEADERS.items():
        present = False
        for h in headers:
            if h.lower() == header.lower():
                present = True
                header_val = headers[h]
                break

        if not present:
            findings.append({
                "type": "missing_header",
                "header": header,
                "severity": info["severity"],
                "desc": info["desc"],
                "fix": info["fix"],
                "cwe": info["cwe"],
            })
            deduction = {"HIGH": 15, "MEDIUM": 10, "LOW": 5}[info["severity"]]
            score -= deduction
            sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}[info["severity"]]
            _emit(f"  {sev_icon} Missing: {header}")

    # ── Analyze CSP if present ──
    csp = None
    for h in headers:
        if h.lower() == "content-security-policy":
            csp = headers[h]
            break

    if csp:
        _emit("🔍 Analyzing Content-Security-Policy...")
        for dangerous, reason in DANGEROUS_CSP.items():
            if dangerous in csp:
                findings.append({
                    "type": "weak_csp",
                    "directive": dangerous,
                    "severity": "MEDIUM" if dangerous != "*" else "HIGH",
                    "desc": f"CSP contains '{dangerous}': {reason}",
                    "csp": csp[:200],
                })
                score -= 5
                _emit(f"  🟡 Weak CSP: '{dangerous}' — {reason}")

        # Check for report-uri / report-to (good practice)
        if "report-" not in csp.lower():
            findings.append({
                "type": "csp_no_reporting",
                "severity": "INFO",
                "desc": "CSP has no report-uri/report-to — violations won't be logged",
            })

    # ── Server info leakage ──
    _emit("🔍 Checking for server info leakage...")
    for h in INFO_LEAK_HEADERS:
        for rh in headers:
            if rh.lower() == h.lower():
                val = headers[rh]
                findings.append({
                    "type": "info_leak",
                    "header": rh,
                    "value": val,
                    "severity": "LOW",
                    "desc": f"Server info leaked: {rh}: {val}",
                })
                score -= 2
                _emit(f"  ⚪ Info leak: {rh}: {val}")
                break

    # ── Cookie security ──
    _emit("🍪 Checking cookie security...")
    cookies = r.headers.get("Set-Cookie", "")
    if cookies:
        # Could be multiple Set-Cookie headers
        cookie_headers = [v for k, v in r.raw.headers.items() if k.lower() == "set-cookie"] if hasattr(r, 'raw') else [cookies]
        if not cookie_headers:
            cookie_headers = [cookies]

        for cookie_str in cookie_headers:
            cookie_name = cookie_str.split("=")[0].strip()
            flags = cookie_str.lower()

            if "secure" not in flags:
                findings.append({
                    "type": "cookie_insecure",
                    "cookie": cookie_name,
                    "severity": "MEDIUM",
                    "desc": f"Cookie '{cookie_name}' missing Secure flag — sent over HTTP",
                    "cwe": "CWE-614",
                })
                score -= 5
                _emit(f"  🟡 Cookie '{cookie_name}' missing Secure flag")

            if "httponly" not in flags:
                findings.append({
                    "type": "cookie_no_httponly",
                    "cookie": cookie_name,
                    "severity": "MEDIUM",
                    "desc": f"Cookie '{cookie_name}' missing HttpOnly flag — accessible via JavaScript (XSS → session theft)",
                    "cwe": "CWE-1004",
                })
                score -= 5
                _emit(f"  🟡 Cookie '{cookie_name}' missing HttpOnly flag")

            if "samesite" not in flags:
                findings.append({
                    "type": "cookie_no_samesite",
                    "cookie": cookie_name,
                    "severity": "LOW",
                    "desc": f"Cookie '{cookie_name}' missing SameSite — CSRF possible",
                    "cwe": "CWE-352",
                })
                score -= 3

    # ── Additional checks ──
    # Check for HTTPS redirect
    if base.startswith("https://"):
        try:
            http_url = base.replace("https://", "http://", 1)
            r_http = requests.get(http_url, timeout=5, headers=HDR, verify=False, allow_redirects=False)
            if r_http.status_code not in (301, 302, 307, 308):
                findings.append({
                    "type": "no_https_redirect",
                    "severity": "MEDIUM",
                    "desc": "HTTP does not redirect to HTTPS — traffic can be intercepted",
                })
                score -= 10
        except Exception:
            pass

    score = max(0, score)
    elapsed = time.time() - start

    # ── Format output ──
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    grade_color = {"A+": "🟢", "A": "🟢", "B": "🟡", "C": "🟠", "D": "🔴", "F": "🔴"}

    lines = [
        f"SECURITY HEADER AUDIT for {base}",
        f"{'='*60}",
        f"Security Score: {grade_color.get(grade, '⚪')} {score}/100 (Grade: {grade})",
        f"Findings: {len(findings)} issues in {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if not findings:
        lines.append("✅ All security headers properly configured!")
        return "\n".join(lines)

    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        group = [f for f in findings if f.get("severity") == sev]
        if group:
            icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪", "INFO": "ℹ️"}[sev]
            lines.append(f"{icon} {sev} ({len(group)})")
            lines.append("-" * 40)
            for f in group:
                if f["type"] == "missing_header":
                    lines.append(f"  Missing: {f['header']}")
                    lines.append(f"    Impact: {f['desc']}")
                    lines.append(f"    Fix: {f['fix']}")
                    lines.append(f"    CWE: {f['cwe']}")
                elif f["type"] == "weak_csp":
                    lines.append(f"  Weak CSP directive: {f['directive']}")
                    lines.append(f"    Impact: {f['desc']}")
                elif f["type"] == "info_leak":
                    lines.append(f"  Info leak: {f['header']}: {f['value']}")
                elif f["type"].startswith("cookie_"):
                    lines.append(f"  {f['desc']}")
                else:
                    lines.append(f"  {f['desc']}")
                lines.append("")

    lines.append(f"Verify: curl -sI '{base}' | grep -iE 'strict|content-security|x-frame|x-content|server|x-powered'")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "header_audit",
        "description": "Audit HTTP security headers for a target. Checks for missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and more. Analyzes CSP for dangerous directives (unsafe-inline, unsafe-eval). Checks cookie security (Secure, HttpOnly, SameSite). Detects server info leakage. Gives a security score (A+ to F).",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to audit"
                }
            },
            "required": ["target"]
        }
    }
}
