"""
JavaScript file analyzer — finds secrets, API keys, endpoints, source maps, and sensitive data.
Crawls JS files from a target and mines them for security-relevant information.
"""

import requests
import re
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Regex patterns for secret detection. `group` indicates which capture group contains
# the credential value; 0 means the full match.
SECRET_PATTERNS = [
    {"name": "AWS Access Key", "pattern": r'(?:AKIA|ASIA)[A-Z0-9]{16}', "group": 0},
    {"name": "AWS Secret Key", "pattern": r'(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "group": 1},
    {"name": "Google API Key", "pattern": r'AIza[0-9A-Za-z\-_]{35}', "group": 0},
    {"name": "Google OAuth", "pattern": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "group": 0},
    {"name": "GitHub Token", "pattern": r'gh[ps]_[A-Za-z0-9_]{36}', "group": 0},
    {"name": "GitHub OAuth", "pattern": r'gho_[A-Za-z0-9]{36}', "group": 0},
    {"name": "Slack Token", "pattern": r'xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}', "group": 0},
    {"name": "Slack Webhook", "pattern": r'hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}', "group": 0},
    {"name": "Stripe Secret Key", "pattern": r'sk_live_[0-9a-zA-Z]{24,}', "group": 0},
    {"name": "Stripe Publishable Key", "pattern": r'pk_live_[0-9a-zA-Z]{24,}', "group": 0},
    {"name": "Mailgun API Key", "pattern": r'key-[0-9a-zA-Z]{32}', "group": 0},
    {"name": "Twilio Account SID", "pattern": r'AC[a-f0-9]{32}', "group": 0},
    {"name": "Twilio Auth Token", "pattern": r'(?:twilio.*auth.*token|TWILIO_AUTH)\s*[=:]\s*["\']?([a-f0-9]{32})', "group": 1},
    {"name": "SendGrid API Key", "pattern": r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "group": 0},
    # UUID-like values are often identifiers (request/session/resource IDs), not API credentials.
    {"name": "UUID-like Identifier", "pattern": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "group": 0},
    {"name": "Firebase", "pattern": r'(?:firebase|FIREBASE)[A-Za-z0-9_]*\s*[=:]\s*["\']([A-Za-z0-9\-_]+)["\']', "group": 1},
    {"name": "JWT Token", "pattern": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+', "group": 0},
    {"name": "Bearer Token", "pattern": r'[Bb]earer\s+[A-Za-z0-9\-_.~+/]+=*', "group": 0},
    {"name": "Basic Auth", "pattern": r'[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}', "group": 0},
    {"name": "Private Key", "pattern": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "group": 0},
    {"name": "Password in URL", "pattern": r'(?:https?://)[^:]+:([^@]+)@[^\s"\'<>]+', "group": 1},
    {"name": "Hardcoded Password", "pattern": r'(?:password|passwd|pwd|secret|token|api_?key)\s*[=:]\s*["\']([^"\']{6,})["\']', "group": 1},
    {"name": "Email Address", "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "group": 0},
    {"name": "Internal IP", "pattern": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', "group": 0},
    {"name": "S3 Bucket", "pattern": r'[a-z0-9.-]+\.s3[.-](?:us|eu|ap|sa|ca|me|af)-?[a-z]*-?\d*\.amazonaws\.com', "group": 0},
    {"name": "S3 Bucket Path", "pattern": r's3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', "group": 0},
    {"name": "Telegram Bot Token", "pattern": r'\d{8,10}:[A-Za-z0-9_-]{35}', "group": 0},
    {"name": "Discord Webhook", "pattern": r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', "group": 0},
    {"name": "Supabase Key", "pattern": r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "group": 0},
    {"name": "Mapbox Token", "pattern": r'pk\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "group": 0},
]

HIGH_CONFIDENCE_SECRET_TYPES = {
    "AWS Access Key", "AWS Secret Key", "Google API Key", "GitHub Token", "GitHub OAuth",
    "Slack Token", "Slack Webhook", "Stripe Secret Key", "SendGrid API Key",
    "Telegram Bot Token", "Discord Webhook", "Twilio Auth Token", "JWT Token",
}

LOW_CONFIDENCE_SECRET_TYPES = {
    "UUID-like Identifier", "Email Address", "Internal IP", "S3 Bucket", "S3 Bucket Path",
}

VALIDATION_HINTS = {
    "Google API Key": "Test with a low-impact Google API request and inspect error/quota response.",
    "GitHub Token": "curl -sH \"Authorization: token TOKEN\" https://api.github.com/user",
    "Slack Token": "curl -s \"https://slack.com/api/auth.test?token=TOKEN\"",
    "Stripe Secret Key": "curl -s https://api.stripe.com/v1/charges -u KEY:",
    "Telegram Bot Token": "curl -s \"https://api.telegram.org/botTOKEN/getMe\"",
    "AWS Access Key": "Pair with a matching secret and run aws sts get-caller-identity.",
}

# Patterns for API endpoints
ENDPOINT_PATTERNS = [
    r'["\']/(api/[^\s"\'<>{}]+)["\']',
    r'["\']/(v[0-9]+/[^\s"\'<>{}]+)["\']',
    r'["\']/(rest/[^\s"\'<>{}]+)["\']',
    r'["\']/(graphql[^\s"\'<>{}]*)["\']',
    r'["\']/(admin[^\s"\'<>{}]*)["\']',
    r'["\']/(internal[^\s"\'<>{}]*)["\']',
    r'["\']/(debug[^\s"\'<>{}]*)["\']',
    r'["\']/(test[^\s"\'<>{}]*)["\']',
    r'["\']/(swagger[^\s"\'<>{}]*)["\']',
    r'["\']/(openapi[^\s"\'<>{}]*)["\']',
    r'["\']/(\.env[^\s"\'<>{}]*)["\']',
    r'["\']/(config[^\s"\'<>{}]*)["\']',
    r'["\']/(backup[^\s"\'<>{}]*)["\']',
    r'["\']/(upload[^\s"\'<>{}]*)["\']',
    r'["\']/(download[^\s"\'<>{}]*)["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
    r'XMLHttpRequest[^}]*open\s*\([^,]*,\s*["\']([^"\']+)["\']',
    r'(?:href|src|action)\s*=\s*["\']([^"\']*(?:api|admin|internal|config|upload|graphql)[^"\']*)["\']',
]

# Patterns for sensitive config/data
CONFIG_PATTERNS = {
    "Database Connection": r'(?:mongodb|mysql|postgres|redis|amqp)://[^\s"\'<>]+',
    "Webhook URL": r'https?://[^\s"\'<>]*(?:webhook|hook|callback|notify)[^\s"\'<>]*',
    "Internal Service": r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|staging|dev)[^\s"\'<>]*',
    "Cloud Metadata": r'169\.254\.169\.254',
    "Debug Mode": r'(?:debug|DEBUG)\s*[=:]\s*(?:true|True|1|yes)',
    "Source Map": r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
    "TODO/FIXME": r'(?:TODO|FIXME|HACK|XXX|BUG)\s*:?\s*(.{10,80})',
}


def _clean_secret_value(value):
    if value is None:
        return ""
    return str(value).strip().strip('"').strip("'")


def _looks_like_noise(value):
    v = (value or "").strip().lower()
    if not v:
        return True
    if len(v) < 6:
        return True
    if v in {"true", "false", "null", "undefined", "none"}:
        return True
    if v.startswith("${") and v.endswith("}"):
        return True
    if any(t in v for t in ["your_api_key", "changeme", "example", "<token>", "replace_me"]):
        return True
    return False


def _classify_secret(secret_type, value, surrounding_text):
    v = _clean_secret_value(value)
    context = (surrounding_text or "").lower()
    confidence = "medium"
    note = ""
    normalized_type = secret_type
    validation_hint = VALIDATION_HINTS.get(secret_type, "")

    if secret_type in HIGH_CONFIDENCE_SECRET_TYPES:
        confidence = "high"
    elif secret_type in LOW_CONFIDENCE_SECRET_TYPES:
        confidence = "low"

    if secret_type == "UUID-like Identifier":
        heroku_hints = ("heroku", "api.heroku.com", "heroku_api_key", "heroku-key", "x-heroku")
        if any(h in context for h in heroku_hints):
            normalized_type = "Heroku API Key (contextual candidate)"
            confidence = "medium"
            note = (
                "UUID format appears near Heroku-specific context. Could be a Heroku key, "
                "but format-only evidence is insufficient without successful API validation."
            )
            validation_hint = (
                "curl -sn -H \"Authorization: Bearer KEY\" "
                "-H \"Accept: application/vnd.heroku+json; version=3\" https://api.heroku.com/apps"
            )
        else:
            normalized_type = "UUID-like Identifier"
            confidence = "low"
            note = (
                "Generic UUID value detected. This is usually an identifier "
                "(request/session/resource ID), not an API credential."
            )
            validation_hint = "Do not claim credential exposure from UUID format alone."

    if secret_type == "Bearer Token":
        normalized_type = "Bearer Token Candidate"
        note = "Generic bearer-format value; validity and scope require endpoint-specific testing."

    if secret_type == "Email Address":
        note = "Likely contact metadata, not an authentication secret by itself."

    return {
        "type": normalized_type,
        "value": v[:120],
        "confidence": confidence,
        "note": note,
        "validation_hint": validation_hint,
    }


def _discover_js_files(base_url):
    """Find all JS files from the main page and linked pages."""
    js_files = set()
    domain = urlparse(base_url).netloc

    try:
        r = requests.get(base_url, timeout=10, headers=HDR, verify=False)
        html = r.text

        # Find script tags
        for src in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(base_url, src)
            js_files.add(full)

        # Find JS in link preload
        for href in re.findall(r'<link[^>]*href=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
            full = urljoin(base_url, href)
            js_files.add(full)

        # Check common JS paths
        common_paths = [
            "/bundle.js", "/main.js", "/app.js", "/index.js", "/vendor.js",
            "/chunk.js", "/runtime.js", "/static/js/main.js", "/static/js/bundle.js",
            "/assets/js/app.js", "/js/app.js", "/js/main.js",
            "/dist/bundle.js", "/build/bundle.js", "/build/static/js/main.js",
            "/_next/static/chunks/main.js", "/_next/static/chunks/webpack.js",
            "/wp-includes/js/jquery/jquery.js", "/wp-content/themes/theme/js/app.js",
        ]
        for path in common_paths:
            full = urljoin(base_url, path)
            try:
                r = requests.head(full, timeout=3, headers=HDR, verify=False)
                if r.status_code == 200 and "javascript" in r.headers.get("Content-Type", ""):
                    js_files.add(full)
            except Exception:
                pass

    except Exception:
        pass

    return list(js_files)


def js_analyze(target, stream_callback=None):
    """
    Analyze JavaScript files from a target for secrets, API keys, endpoints, and sensitive data.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("jsanalyzer_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 Analyzing JavaScript files from: {base}")
    start = time.time()

    # Discover JS files
    _emit("🔍 Discovering JavaScript files...")
    js_files = _discover_js_files(base)
    _emit(f"  Found {len(js_files)} JS files")

    if not js_files:
        lines = [
            f"JS ANALYSIS for {base}",
            f"{'='*50}",
            "No JavaScript files found.",
        ]
        if fallback_note:
            lines = [fallback_note, ""] + lines
        return "\n".join(lines)

    # Analyze each file
    all_secrets = []
    all_endpoints = []
    all_configs = []
    source_maps = []
    total_size = 0

    def _analyze_file(js_url):
        results = {"secrets": [], "endpoints": [], "configs": [], "source_map": None, "size": 0}
        try:
            r = requests.get(js_url, timeout=10, headers=HDR, verify=False)
            if r.status_code != 200:
                return results
            js_content = r.text
            results["size"] = len(js_content)

            # Search for secrets
            for detector in SECRET_PATTERNS:
                name = detector["name"]
                pattern = detector["pattern"]
                group = int(detector.get("group", 0) or 0)
                match_count = 0
                for match in re.finditer(pattern, js_content, re.I):
                    if match_count >= 3:  # Limit matches per pattern
                        break
                    raw_value = match.group(group if group > 0 else 0)
                    raw_value = _clean_secret_value(raw_value)
                    if _looks_like_noise(raw_value):
                        continue

                    snippet_start = max(0, match.start() - 120)
                    snippet_end = min(len(js_content), match.end() + 120)
                    context = js_content[snippet_start:snippet_end]
                    classified = _classify_secret(name, raw_value, context)
                    classified["file"] = js_url
                    results["secrets"].append(classified)
                    match_count += 1

            # Search for endpoints
            for pattern in ENDPOINT_PATTERNS:
                matches = re.findall(pattern, js_content)
                for match in matches[:10]:
                    if len(match) > 3 and not match.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.ico')):
                        full_url = urljoin(base, match) if not match.startswith("http") else match
                        results["endpoints"].append({"url": full_url, "raw": match, "file": js_url})

            # Search for configs
            for name, pattern in CONFIG_PATTERNS.items():
                matches = re.findall(pattern, js_content)
                for match in matches[:3]:
                    results["configs"].append({
                        "type": name,
                        "value": str(match)[:120],
                        "file": js_url,
                    })

            # Check for source maps
            sm_match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_content)
            if sm_match:
                sm_url = sm_match.group(1)
                if not sm_url.startswith("data:"):
                    results["source_map"] = urljoin(js_url, sm_url)

        except Exception:
            pass
        return results

    _emit(f"📂 Analyzing {len(js_files)} files...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_analyze_file, url): url for url in js_files[:50]}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 5 == 0:
                _emit(f"  Analyzed {done}/{len(js_files)} files...")
            results = future.result()
            all_secrets.extend(results["secrets"])
            all_endpoints.extend(results["endpoints"])
            all_configs.extend(results["configs"])
            total_size += results["size"]
            if results["source_map"]:
                source_maps.append(results["source_map"])

    # Deduplicate endpoints
    seen_endpoints = set()
    unique_endpoints = []
    for ep in all_endpoints:
        if ep["url"] not in seen_endpoints:
            seen_endpoints.add(ep["url"])
            unique_endpoints.append(ep)

    elapsed = time.time() - start

    # Verify source maps are accessible
    accessible_maps = []
    for sm_url in source_maps[:5]:
        try:
            r = requests.head(sm_url, timeout=5, headers=HDR, verify=False)
            if r.status_code == 200:
                accessible_maps.append(sm_url)
        except Exception:
            pass

    # Format output
    lines = [
        f"JAVASCRIPT ANALYSIS for {base}",
        f"{'='*60}",
        f"Files: {len(js_files)} | Total size: {total_size/1024:.0f} KB | Time: {elapsed:.1f}s",
        f"Secrets: {len(all_secrets)} | Endpoints: {len(unique_endpoints)} | Configs: {len(all_configs)}\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if all_secrets:
        lines.append("🔴 SECRETS & API KEYS FOUND")
        lines.append("-" * 40)
        by_conf = {"high": 0, "medium": 0, "low": 0}
        for s in all_secrets:
            conf = str(s.get("confidence", "medium")).lower()
            if conf not in by_conf:
                conf = "medium"
            by_conf[conf] += 1
            lines.append(f"  [{s['type']}] {s['value']}")
            lines.append(f"    Confidence: {conf.upper()}")
            note = str(s.get("note", "") or "").strip()
            if note:
                lines.append(f"    Note: {note}")
            hint = str(s.get("validation_hint", "") or "").strip()
            if hint:
                lines.append(f"    Validation hint: {hint}")
            lines.append(f"    File: {s['file']}")
        lines.append(
            f"  Confidence summary: HIGH={by_conf['high']} | "
            f"MEDIUM={by_conf['medium']} | LOW={by_conf['low']}"
        )
        lines.append("")

    if accessible_maps:
        lines.append("🔴 ACCESSIBLE SOURCE MAPS (full source code exposure)")
        lines.append("-" * 40)
        for sm in accessible_maps:
            lines.append(f"  📂 {sm}")
            lines.append(f"    Download: curl -o sourcemap.json '{sm}'")
        lines.append("")

    if unique_endpoints:
        lines.append(f"📋 API ENDPOINTS DISCOVERED ({len(unique_endpoints)})")
        lines.append("-" * 40)
        # Categorize
        admin_eps = [e for e in unique_endpoints if any(k in e["url"].lower() for k in ["admin", "internal", "debug", "config", "swagger"])]
        api_eps = [e for e in unique_endpoints if any(k in e["url"].lower() for k in ["api", "v1", "v2", "rest", "graphql"])]
        other_eps = [e for e in unique_endpoints if e not in admin_eps and e not in api_eps]

        if admin_eps:
            lines.append("  ⚠️ Admin/Internal endpoints:")
            for e in admin_eps[:15]:
                lines.append(f"    {e['url']}")
        if api_eps:
            lines.append("  🔗 API endpoints:")
            for e in api_eps[:20]:
                lines.append(f"    {e['url']}")
        if other_eps:
            lines.append(f"  📎 Other endpoints ({len(other_eps)}):")
            for e in other_eps[:10]:
                lines.append(f"    {e['url']}")
        lines.append("")

    if all_configs:
        lines.append("⚙️ CONFIGURATION & SENSITIVE DATA")
        lines.append("-" * 40)
        for c in all_configs:
            lines.append(f"  [{c['type']}] {c['value']}")
            lines.append(f"    File: {c['file']}")
        lines.append("")

    if not all_secrets and not unique_endpoints and not all_configs:
        lines.append("No secrets, endpoints, or sensitive data found in JavaScript files.")

    # Recommendations
    if all_secrets or accessible_maps:
        lines.append("RECOMMENDED ACTIONS")
        lines.append("-" * 40)
        if all_secrets:
            lines.append("  1. Prioritize HIGH/MEDIUM confidence secrets for validation first")
            lines.append("  2. Treat LOW confidence UUID-only matches as identifiers until proven otherwise")
            lines.append("  3. Validate each candidate with provider-specific read-only checks")
        if accessible_maps:
            lines.append("  4. Download source maps and review full source code")
        if unique_endpoints:
            lines.append(f"  5. Run exploit_target on discovered API endpoints")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "js_analyze",
        "description": "Analyze JavaScript files from a target website for secrets (AWS keys, API tokens, passwords, JWTs), API endpoints, source maps, database connection strings, and internal service URLs. Discovers JS files automatically and mines them for security-relevant data. Critical for finding hardcoded credentials and hidden API routes.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to analyze JS files from"
                }
            },
            "required": ["target"]
        }
    }
}
