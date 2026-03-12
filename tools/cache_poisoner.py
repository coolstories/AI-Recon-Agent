"""
Web cache poisoning & deception scanner.
Tests for cache key manipulation, unkeyed headers/params, CDN poisoning.
Critical for targets behind CDNs like Cloudflare, Akamai, Fastly (YouTube, Apple).
"""

import requests
import time
import hashlib
import re
import random
import string
from urllib.parse import urlparse, urlencode, quote

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Headers that may be unkeyed by caches
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Host", "evil.com"),
    ("X-Forwarded-Server", "evil.com"),
    ("X-HTTP-Dest", "evil.com"),
    ("X-Forwarded-Port", "1337"),
    ("Forwarded", "host=evil.com"),
    ("Transfer-Encoding", "chunked"),
    ("X-Custom-Header", "cache-poison-test"),
    ("Origin", "https://evil.com"),
    ("Accept-Language", "evil"),
    ("Cookie", "poison=true"),
    ("X-Real-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("Fastly-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-Amz-Website-Redirect-Location", "https://evil.com"),
]

# Parameters that may be unkeyed
UNKEYED_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid",
    "callback", "cb", "jsonp", "_", "__", "cachebust",
    "ref", "referrer", "source", "origin",
    "lang", "language", "locale", "hl",
    "x", "y", "z", "debug", "test", "preview",
]


def _rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _detect_cache(url):
    """Detect if response is cached and by what CDN."""
    cache_info = {"is_cached": False, "cdn": None, "headers": {}}
    try:
        r = requests.get(url, headers=HDR, timeout=10, verify=False)
        h = {k.lower(): v for k, v in r.headers.items()}

        # Cache indicators
        cache_headers = {
            "x-cache": h.get("x-cache", ""),
            "x-cache-status": h.get("x-cache-status", ""),
            "cf-cache-status": h.get("cf-cache-status", ""),
            "x-varnish": h.get("x-varnish", ""),
            "x-fastly-request-id": h.get("x-fastly-request-id", ""),
            "x-served-by": h.get("x-served-by", ""),
            "age": h.get("age", ""),
            "via": h.get("via", ""),
            "x-cdn": h.get("x-cdn", ""),
            "x-akamai-request-id": h.get("x-akamai-request-id", ""),
            "cache-control": h.get("cache-control", ""),
        }
        cache_info["headers"] = {k: v for k, v in cache_headers.items() if v}

        # Detect CDN
        if "cf-cache-status" in h:
            cache_info["cdn"] = "Cloudflare"
        elif "x-fastly-request-id" in h or "fastly" in h.get("via", "").lower():
            cache_info["cdn"] = "Fastly"
        elif "x-akamai" in str(h) or "akamai" in h.get("via", "").lower():
            cache_info["cdn"] = "Akamai"
        elif "x-varnish" in h:
            cache_info["cdn"] = "Varnish"
        elif "cloudfront" in h.get("via", "").lower() or "cloudfront" in h.get("x-cache", "").lower():
            cache_info["cdn"] = "CloudFront"
        elif "x-cache" in h:
            cache_info["cdn"] = "Unknown CDN"

        # Check if cached
        for indicator in ["hit", "HIT"]:
            for val in cache_headers.values():
                if indicator in str(val):
                    cache_info["is_cached"] = True
                    break

        if h.get("age") and int(h.get("age", "0")) > 0:
            cache_info["is_cached"] = True

    except Exception:
        pass
    return cache_info


def _test_cache_poison_header(url, header_name, header_value, canary):
    """Test if an unkeyed header poisons the cache."""
    # Add cache buster to isolate our test
    bust = _rand_str(12)
    test_url = f"{url}?_cb={bust}"

    try:
        # Request 1: Poison with custom header
        poison_headers = {**HDR, header_name: header_value}
        r1 = requests.get(test_url, headers=poison_headers, timeout=8, verify=False)

        if canary in r1.text or header_value in r1.text:
            # The header value is reflected — now check if it's cached
            time.sleep(0.5)
            # Request 2: Normal request (no custom header)
            r2 = requests.get(test_url, headers=HDR, timeout=8, verify=False)

            if canary in r2.text or header_value in r2.text:
                return {
                    "vulnerable": True,
                    "header": header_name,
                    "reflected": True,
                    "cached": True,
                    "desc": f"Header '{header_name}' is reflected AND cached — cache poisoning confirmed!",
                }
            else:
                return {
                    "vulnerable": False,
                    "header": header_name,
                    "reflected": True,
                    "cached": False,
                    "desc": f"Header '{header_name}' is reflected but NOT cached",
                }
    except Exception:
        pass
    return {"vulnerable": False, "header": header_name, "reflected": False, "cached": False}


def _test_cache_deception(base_url):
    """Test for web cache deception (accessing cached private pages)."""
    findings = []

    # Common authenticated endpoints
    auth_paths = ["/account", "/profile", "/settings", "/dashboard", "/my", "/me", "/user"]

    for path in auth_paths:
        for ext in [".css", ".js", ".png", ".jpg", ".ico", ".svg", "/nonexistent.css", "/..%2f..%2fstatic.css"]:
            test_url = f"{base_url}{path}{ext}"
            try:
                r = requests.get(test_url, headers=HDR, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 200:
                    # Check cache headers
                    cache_status = r.headers.get("x-cache", "") or r.headers.get("cf-cache-status", "") or r.headers.get("x-cache-status", "")
                    if "hit" in cache_status.lower() or r.headers.get("age", ""):
                        findings.append({
                            "url": test_url,
                            "path": f"{path}{ext}",
                            "cached": True,
                            "size": len(r.text),
                            "desc": f"Web cache deception: {path}{ext} is cached with status 200",
                        })
                        break
            except Exception:
                pass

    return findings


def _test_unkeyed_params(url):
    """Test for parameters that are ignored by cache key."""
    findings = []
    canary = f"CACHETEST{_rand_str(8)}"

    for param in UNKEYED_PARAMS:
        bust = _rand_str(12)
        test_url = f"{url}?_cb={bust}&{param}={canary}"
        try:
            # Request with param
            r1 = requests.get(test_url, headers=HDR, timeout=5, verify=False)
            if canary in r1.text:
                # Param is reflected — check if it's cached without the param
                time.sleep(0.3)
                clean_url = f"{url}?_cb={bust}"
                r2 = requests.get(clean_url, headers=HDR, timeout=5, verify=False)
                if canary in r2.text:
                    findings.append({
                        "param": param,
                        "reflected": True,
                        "cached": True,
                        "desc": f"Parameter '{param}' is unkeyed and reflected — cache poisoning via param!",
                    })
        except Exception:
            pass
    return findings


def cache_poison(target, stream_callback=None):
    """
    Test for web cache poisoning and web cache deception vulnerabilities.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("cache_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 Cache Poisoning Scanner: {base}")
    start = time.time()
    findings = []

    # Phase 1: Detect caching
    _emit("🔍 Phase 1: Detecting cache infrastructure...")
    cache_info = _detect_cache(base)

    if cache_info["cdn"]:
        _emit(f"  CDN detected: {cache_info['cdn']}")
    if cache_info["is_cached"]:
        _emit(f"  Response IS cached")
    if cache_info["headers"]:
        for h, v in cache_info["headers"].items():
            _emit(f"  {h}: {v}")

    # Phase 2: Unkeyed header testing
    _emit(f"🔨 Phase 2: Testing {len(UNKEYED_HEADERS)} unkeyed headers...")
    canary = f"POISON{_rand_str(8)}"

    for header_name, header_value in UNKEYED_HEADERS:
        result = _test_cache_poison_header(base, header_name, header_value, canary)
        if result["reflected"]:
            if result["vulnerable"]:
                _emit(f"  🔴 CACHE POISON: {header_name} is reflected AND cached!")
                findings.append({
                    "type": "cache_poison_header",
                    "severity": "CRITICAL",
                    "header": header_name,
                    "value": header_value,
                    "desc": result["desc"],
                    "cwe": "CWE-444",
                })
            else:
                _emit(f"  🟡 Reflected: {header_name} (not cached)")
                findings.append({
                    "type": "reflected_header",
                    "severity": "LOW",
                    "header": header_name,
                    "desc": result["desc"],
                })

    # Phase 3: Unkeyed parameter testing
    _emit(f"🔨 Phase 3: Testing {len(UNKEYED_PARAMS)} unkeyed parameters...")
    param_findings = _test_unkeyed_params(base)
    for pf in param_findings:
        if pf["cached"]:
            _emit(f"  🔴 CACHE POISON via param: {pf['param']}")
            findings.append({
                "type": "cache_poison_param",
                "severity": "HIGH",
                "param": pf["param"],
                "desc": pf["desc"],
                "cwe": "CWE-444",
            })

    # Phase 4: Web cache deception
    _emit("🔨 Phase 4: Testing web cache deception...")
    deception = _test_cache_deception(base)
    for d in deception:
        _emit(f"  🔴 Cache deception: {d['path']}")
        findings.append({
            "type": "cache_deception",
            "severity": "HIGH",
            "path": d["path"],
            "url": d["url"],
            "desc": d["desc"],
            "cwe": "CWE-525",
        })

    # Phase 5: Path-based cache poisoning
    _emit("🔨 Phase 5: Testing path-based poisoning...")
    path_payloads = [
        f"/..%2f{_rand_str(6)}",
        f"/%2e%2e/{_rand_str(6)}",
        f"/static/../{_rand_str(6)}",
        f"/{_rand_str(6)}.js",
        f"/{_rand_str(6)}.css",
    ]
    for payload in path_payloads:
        try:
            test_url = f"{base}{payload}"
            r = requests.get(test_url, headers=HDR, timeout=5, verify=False)
            if r.status_code == 200:
                cache_hit = r.headers.get("x-cache", "") or r.headers.get("cf-cache-status", "")
                if "hit" in cache_hit.lower():
                    findings.append({
                        "type": "path_normalization",
                        "severity": "MEDIUM",
                        "path": payload,
                        "desc": f"Path {payload} returns cached 200 — possible path-based cache poisoning",
                    })
                    _emit(f"  🟡 Path cached: {payload}")
        except Exception:
            pass

    elapsed = time.time() - start

    # Format output
    lines = [
        f"CACHE POISONING SCAN for {base}",
        f"{'='*60}",
        f"CDN: {cache_info.get('cdn', 'None detected')} | Cached: {cache_info['is_cached']}",
        f"Findings: {len(findings)} | Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]

    if critical:
        lines.append("🔴 CRITICAL — CACHE POISONING CONFIRMED")
        lines.append("-" * 40)
        for f in critical:
            lines.append(f"  {f['desc']}")
            if f.get("header"):
                lines.append(f"  PoC: curl -H '{f['header']}: {f.get('value', 'evil.com')}' '{base}'")
                lines.append(f"  Then: curl '{base}' (poisoned response served to all users)")
            lines.append(f"  CWE: {f.get('cwe', 'CWE-444')}")
            lines.append(f"  Impact: Any user visiting {base} gets attacker-controlled content")
            lines.append(f"  CVSS: 9.0+ (Critical)")
            lines.append("")

    if high:
        lines.append("🟠 HIGH FINDINGS")
        lines.append("-" * 40)
        for f in high:
            lines.append(f"  [{f['type']}] {f['desc']}")
            if f.get("url"):
                lines.append(f"  URL: {f['url']}")
        lines.append("")

    if not findings:
        lines.append("No cache poisoning vulnerabilities found.")
        if cache_info["cdn"]:
            lines.append(f"CDN ({cache_info['cdn']}) appears to properly key all headers and parameters.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "cache_poison",
        "description": "Test for web cache poisoning and web cache deception. Detects CDN/cache infrastructure (Cloudflare, Fastly, Akamai, CloudFront, Varnish), tests 20+ unkeyed headers and 25+ unkeyed parameters for cache key manipulation, checks for web cache deception (accessing cached private pages), and path-based cache poisoning. Critical for sites behind CDNs.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test for cache poisoning"
                }
            },
            "required": ["target"]
        }
    }
}
