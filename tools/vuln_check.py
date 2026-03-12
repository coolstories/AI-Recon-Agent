import requests
import re
import ssl
import socket
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def check_exposed_paths(base_url: str, scan_profile: str = "standard", stream_callback=None) -> str:
    """Actively probe a target for exposed sensitive files, admin panels, and misconfigurations.
    
    Args:
        base_url: Target URL to scan
        stream_callback: Optional callback(event_type, data) for streaming progress
    """
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
    base_url = base_url.rstrip("/")

    findings = []
    tested = 0
    
    if stream_callback:
        stream_callback("vuln_scan_start", {"target": base_url})

    # 1. Sensitive files and directories
    sensitive_paths = [
        # Admin panels
        ("/wp-admin/", "WordPress Admin Panel"),
        ("/wp-login.php", "WordPress Login"),
        ("/administrator/", "Joomla Admin"),
        ("/admin/", "Admin Panel"),
        ("/admin/login", "Admin Login"),
        ("/phpmyadmin/", "phpMyAdmin"),
        ("/adminer.php", "Adminer DB Manager"),
        ("/cpanel", "cPanel"),
        ("/webmail", "Webmail"),
        # Information disclosure
        ("/.git/HEAD", "Exposed .git Repository"),
        ("/.git/config", "Exposed .git Config"),
        ("/.env", "Exposed .env File (credentials)"),
        ("/.htaccess", "Exposed .htaccess"),
        ("/.htpasswd", "Exposed .htpasswd"),
        ("/robots.txt", "Robots.txt"),
        ("/sitemap.xml", "Sitemap"),
        ("/readme.html", "WordPress Readme (version disclosure)"),
        ("/license.txt", "License File"),
        ("/wp-json/", "WordPress REST API"),
        ("/wp-json/wp/v2/users", "WordPress User Enumeration"),
        ("/xmlrpc.php", "WordPress XML-RPC (brute force vector)"),
        ("/wp-cron.php", "WordPress Cron (DDoS vector)"),
        ("/wp-config.php.bak", "WordPress Config Backup"),
        ("/wp-config.php~", "WordPress Config Editor Backup"),
        ("/debug.log", "Debug Log"),
        ("/error.log", "Error Log"),
        ("/server-status", "Apache Server Status"),
        ("/server-info", "Apache Server Info"),
        ("/.well-known/security.txt", "Security Policy"),
        ("/api/", "API Endpoint"),
        ("/api/v1/", "API v1 Endpoint"),
        ("/graphql", "GraphQL Endpoint"),
        ("/swagger.json", "Swagger API Docs"),
        ("/api-docs", "API Documentation"),
        # Backup files
        ("/backup.sql", "SQL Backup"),
        ("/backup.zip", "Backup Archive"),
        ("/db.sql", "Database Dump"),
        ("/dump.sql", "Database Dump"),
    ]

    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"}

    total_paths = len(sensitive_paths)

    def _probe_path(path, description):
        local_findings = []
        try:
            url = base_url + path
            resp = requests.get(
                url,
                headers=headers,
                timeout=6,
                allow_redirects=False,
                verify=False,
            )

            status = resp.status_code
            size = len(resp.content)

            if status == 200:
                # Verify it's a real finding, not a custom 404
                if _is_real_finding(path, resp):
                    severity = _classify_severity(path)
                    snippet = _extract_snippet(resp.text, path)
                    local_findings.append({
                        "path": path,
                        "description": description,
                        "status": status,
                        "size": size,
                        "severity": severity,
                        "url": url,
                        "snippet": snippet,
                    })
            elif status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if path in ("/wp-admin/", "/administrator/", "/admin/", "/phpmyadmin/"):
                    # Redirect to login = admin panel exists
                    local_findings.append({
                        "path": path,
                        "description": f"{description} (redirects to login)",
                        "status": status,
                        "size": 0,
                        "severity": "HIGH",
                        "url": url,
                        "snippet": f"Redirects to: {location}",
                    })
            elif status == 403:
                if path in ("/.git/HEAD", "/.env", "/.htpasswd"):
                    local_findings.append({
                        "path": path,
                        "description": f"{description} (403 Forbidden — exists but blocked)",
                        "status": status,
                        "size": 0,
                        "severity": "MEDIUM",
                        "url": url,
                        "snippet": "Server returns 403 — file exists but access denied",
                    })
        except requests.exceptions.Timeout:
            return []
        except Exception:
            return []
        return local_findings

    # Probe paths in parallel to keep scans responsive.
    with ThreadPoolExecutor(max_workers=18) as executor:
        futures = {
            executor.submit(_probe_path, path, description): path
            for path, description in sensitive_paths
        }
        for future in as_completed(futures):
            tested += 1
            findings.extend(future.result())
            if stream_callback and (tested % 5 == 0 or tested == total_paths):
                stream_callback("vuln_scan_progress", {
                    "tested": tested,
                    "total": total_paths,
                    "current_path": futures[future]
                })

    # 2. Check security headers
    if stream_callback:
        stream_callback("vuln_scan_progress", {
            "tested": tested,
            "total": total_paths,
            "current_path": "Checking security headers..."
        })
    header_findings = _check_security_headers(base_url, headers)

    # 3. Check for directory listing
    if stream_callback:
        stream_callback("vuln_scan_progress", {
            "tested": tested,
            "total": total_paths,
            "current_path": "Checking directory listing..."
        })
    dir_listing = _check_directory_listing(base_url, headers)

    # 4. Login attack surface / brute-force chance indicators
    if stream_callback:
        stream_callback("vuln_scan_progress", {
            "tested": tested,
            "total": total_paths,
            "current_path": "Checking login attack surface..."
        })
    login_findings = _check_login_attack_surface(base_url, headers)

    # 5. Hardcoded password / credentials in page & JS
    if stream_callback:
        stream_callback("vuln_scan_progress", {
            "tested": tested,
            "total": total_paths,
            "current_path": "Checking hardcoded password candidates..."
        })
    hardcoded_creds, hardcoded_stats = _check_hardcoded_credentials(
        base_url, headers, scan_profile=scan_profile
    )

    total_findings = len(findings) + len(header_findings) + (1 if dir_listing else 0) + len(login_findings) + len(hardcoded_creds)
    if stream_callback:
        stream_callback("vuln_scan_done", {"tested": tested, "findings": total_findings})

    # Build report
    output = []
    output.append(f"=== Active Vulnerability Scan: {base_url} ===")
    output.append(f"Tested {tested} paths\n")

    if findings:
        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

        output.append(f"Found {len(findings)} exposed path(s):\n")
        for f in findings:
            output.append(f"[{f['severity']}] {f['description']}")
            output.append(f"  URL: {f['url']}")
            output.append(f"  Status: {f['status']} | Size: {f['size']} bytes")
            if f["snippet"]:
                output.append(f"  Evidence: {f['snippet']}")
            output.append("")
    else:
        output.append("No exposed sensitive paths found.\n")

    if header_findings:
        output.append("--- Security Header Issues ---")
        for hf in header_findings:
            output.append(f"  [{hf['severity']}] {hf['issue']}")
        output.append("")

    if dir_listing:
        output.append(f"--- Directory Listing ---")
        output.append(dir_listing)
        output.append("")

    output.append("--- Login Attack Surface (login chances) ---")
    if login_findings:
        for lf in login_findings:
            output.append(f"  [{lf['severity']}] Login endpoint: {lf['url']} (HTTP {lf['status']})")
            output.append(f"    Indicators: {', '.join(lf['indicators'])}")
            output.append("    What attacker could realistically do: Try credential stuffing/password spraying if backend lockout and throttling are weak.")
    else:
        output.append("  No obvious login forms/endpoints detected in common paths.")
    output.append("")

    output.append("--- Hardcoded Password / Credential Candidates ---")
    output.append(
        "  Coverage: "
        f"profile={hardcoded_stats.get('profile', 'standard')}, "
        f"sources_discovered={hardcoded_stats.get('sources_discovered', 0)}, "
        f"sources_fetched={hardcoded_stats.get('sources_fetched', 0)}, "
        f"sources_failed={hardcoded_stats.get('sources_failed', 0)}, "
        f"bytes_scanned={hardcoded_stats.get('bytes_scanned', 0)}"
    )
    if hardcoded_creds:
        for cred in hardcoded_creds[:20]:
            output.append(f"  [{cred['severity']}] {cred['kind']} in {cred['source']}")
            output.append(f"    Evidence: {cred['evidence']}")
            output.append("    What attacker could realistically do: Test candidate credentials against exposed login/auth endpoints if the values are valid.")
    else:
        output.append("  No obvious hardcoded password candidates found in sampled HTML/JS assets.")
    output.append("")

    return "\n".join(output)


def _is_real_finding(path, resp):
    """Verify a 200 response is a real finding and not a custom 404 page."""
    text = resp.text.lower()
    size = len(resp.content)

    # Very small responses are likely empty/error
    if size < 10 and path not in ("/.env", "/.htpasswd"):
        return False

    # Check for common custom 404 indicators
    custom_404_phrases = ["page not found", "404", "not found", "does not exist", "no page"]
    if any(phrase in text[:500] for phrase in custom_404_phrases) and size < 5000:
        return False

    # Git HEAD should start with "ref: "
    if path == "/.git/HEAD":
        return text.strip().startswith("ref:")

    # Git config should contain [core]
    if path == "/.git/config":
        return "[core]" in text

    # .env should contain KEY=VALUE patterns
    if path == "/.env":
        return bool(re.search(r'[A-Z_]+=', resp.text))

    # WordPress readme should contain "wordpress"
    if path == "/readme.html":
        return "wordpress" in text

    # XML-RPC should contain xmlrpc
    if path == "/xmlrpc.php":
        return "xml-rpc" in text or "xmlrpc" in text

    # WP REST API should return JSON
    if "/wp-json" in path:
        return "application/json" in resp.headers.get("Content-Type", "")

    # SQL files
    if path.endswith(".sql"):
        return "create table" in text[:1000] or "insert into" in text[:1000]

    return True


def _classify_severity(path):
    """Classify the severity of a finding based on the path."""
    critical = ["/.git/HEAD", "/.git/config", "/.env", "/.htpasswd",
                "/backup.sql", "/db.sql", "/dump.sql", "/wp-config.php.bak",
                "/wp-config.php~"]
    high = ["/wp-admin/", "/wp-login.php", "/administrator/", "/admin/",
            "/phpmyadmin/", "/adminer.php", "/xmlrpc.php",
            "/wp-json/wp/v2/users", "/backup.zip"]
    medium = ["/debug.log", "/error.log", "/server-status", "/server-info",
              "/.htaccess", "/readme.html", "/wp-cron.php", "/graphql",
              "/swagger.json", "/api-docs"]

    if path in critical:
        return "CRITICAL"
    elif path in high:
        return "HIGH"
    elif path in medium:
        return "MEDIUM"
    return "INFO"


def _extract_snippet(text, path):
    """Extract a relevant snippet from the response for evidence."""
    if not text:
        return ""

    if path == "/.git/HEAD":
        return text.strip()[:100]
    elif path == "/.env":
        # Mask values but show keys
        lines = text.strip().split("\n")[:5]
        masked = []
        for line in lines:
            if "=" in line:
                key = line.split("=")[0]
                masked.append(f"{key}=***REDACTED***")
            else:
                masked.append(line[:50])
        return " | ".join(masked)
    elif "/wp-json/wp/v2/users" in path:
        try:
            import json
            users = json.loads(text)
            if isinstance(users, list):
                names = [u.get("slug", u.get("name", "?")) for u in users[:5]]
                return f"Exposed users: {', '.join(names)}"
        except Exception:
            pass
    elif path == "/robots.txt":
        disallows = [l.strip() for l in text.split("\n") if l.strip().lower().startswith("disallow")]
        if disallows:
            return " | ".join(disallows[:5])
    elif path == "/readme.html":
        version_match = re.search(r'Version\s+([\d.]+)', text)
        if version_match:
            return f"WordPress version disclosed: {version_match.group(1)}"

    return text[:150].strip().replace("\n", " ")


def _looks_like_login_page(path, text):
    """Heuristic detection for login pages."""
    t = (text or "").lower()
    path_hint = any(k in (path or "").lower() for k in ("login", "signin", "auth", "account"))
    has_password = bool(re.search(r'type=["\']password["\']', t))
    has_user_field = bool(re.search(r'name=["\'][^"\']*(user|email|login|account)[^"\']*["\']', t))
    has_login_terms = any(k in t for k in ("log in", "login", "sign in", "username", "password"))
    return (has_password and (has_user_field or has_login_terms)) or (path_hint and has_password)


def _check_login_attack_surface(base_url, headers):
    """Discover login surfaces and basic anti-automation indicators."""
    login_paths = [
        "/login", "/signin", "/auth/login", "/user/login", "/account/login",
        "/admin/login", "/wp-login.php", "/administrator/index.php",
        "/oauth/authorize", "/sso/login",
    ]
    findings = []
    seen = set()

    for path in login_paths:
        url = base_url + path
        try:
            resp = requests.get(url, headers=headers, timeout=6, verify=False, allow_redirects=False)
        except Exception:
            continue

        status = resp.status_code
        body = resp.text or ""
        location = (resp.headers.get("Location") or "").strip()

        if status in (301, 302, 303, 307, 308):
            if "login" in location.lower() or "signin" in location.lower():
                target = urljoin(base_url + "/", location)
                key = (target, status)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "url": target,
                        "status": status,
                        "severity": "INFO",
                        "indicators": ["Redirected into login workflow"],
                    })
            continue

        if status not in (200, 401, 403):
            continue
        if not _looks_like_login_page(path, body):
            continue

        indicators = []
        if re.search(r'type=["\']password["\']', body, re.I):
            indicators.append("Password field detected")
        if re.search(r'(g-recaptcha|hcaptcha|captcha)', body, re.I):
            indicators.append("CAPTCHA marker detected")
        else:
            indicators.append("No CAPTCHA marker detected")
        if re.search(r'name=["\'](?:csrf|_token|authenticity_token|csrf_token)["\']', body, re.I):
            indicators.append("CSRF token field detected")
        else:
            indicators.append("No obvious CSRF token field detected")

        rate_limit_headers = [
            "X-RateLimit-Limit", "X-RateLimit-Remaining",
            "RateLimit-Limit", "RateLimit-Remaining", "Retry-After",
        ]
        if any(h in resp.headers for h in rate_limit_headers):
            indicators.append("Rate-limit headers present")
            severity = "INFO"
        else:
            indicators.append("No explicit rate-limit headers detected")
            severity = "MEDIUM"

        key = (url, status)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "url": url,
            "status": status,
            "severity": severity,
            "indicators": indicators,
        })

    return findings


def _mask_secret(value):
    v = str(value or "")
    if len(v) <= 6:
        return "***"
    return f"{v[:2]}***{v[-2:]}"


def _is_placeholder_secret(value):
    v = str(value or "").strip().lower()
    if not v:
        return True
    placeholders = {
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "your_password", "your-token", "changeme", "change_me", "example",
        "sample", "test", "null", "undefined", "true", "false", "none",
        "********", "******",
    }
    if v in placeholders:
        return True
    if len(v) < 4:
        return True
    return False


def _fetch_text_with_retries(url, headers, timeout, retries):
    last_error = ""
    for _ in range(max(1, retries + 1)):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
            return resp, ""
        except requests.exceptions.Timeout:
            last_error = "timeout"
            continue
        except Exception as e:
            last_error = str(e)
            break
    return None, last_error


def _check_hardcoded_credentials(base_url, headers, scan_profile="standard"):
    """Deterministic client-side credential pattern scan (HTML + JS assets)."""
    profile = (scan_profile or "standard").strip().lower()
    deep = profile == "deep"
    timeout = 8 if deep else 6
    retries = 2 if deep else 1
    max_inline = 10 if deep else 4
    max_external = 36 if deep else 12
    max_inline_chars = 400000 if deep else 200000
    max_js_chars = 700000 if deep else 300000
    max_findings = 60 if deep else 30

    findings = []
    stats = {
        "profile": "deep" if deep else "standard",
        "sources_discovered": 0,
        "sources_fetched": 0,
        "sources_failed": 0,
        "bytes_scanned": 0,
    }

    root_resp, _ = _fetch_text_with_retries(base_url, headers, timeout=timeout, retries=retries)
    if not root_resp or root_resp.status_code != 200:
        return findings, stats
    html = root_resp.text or ""

    scripts_to_scan = []

    inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.I | re.S)
    for idx, snippet in enumerate(inline_scripts[:max_inline], start=1):
        if snippet and len(snippet) > 40:
            text = snippet[:max_inline_chars]
            scripts_to_scan.append((f"inline-script-{idx}", text))
            stats["sources_discovered"] += 1
            stats["sources_fetched"] += 1
            stats["bytes_scanned"] += len(text)

    srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.I)
    normalized_srcs = sorted(set(urljoin(base_url + "/", src.strip()) for src in srcs if src.strip()))

    if deep and normalized_srcs:
        p = urlparse(base_url)
        base = f"{p.scheme}://{p.netloc}"
        for suffix in ("/app.js", "/main.js", "/bundle.js", "/static/js/main.js", "/assets/app.js"):
            cand = base + suffix
            if cand not in normalized_srcs:
                normalized_srcs.append(cand)
        normalized_srcs = sorted(set(normalized_srcs))

    for js_url in normalized_srcs[:max_external]:
        stats["sources_discovered"] += 1
        resp, _ = _fetch_text_with_retries(js_url, headers, timeout=timeout, retries=retries)
        if not resp:
            stats["sources_failed"] += 1
            continue
        if resp.status_code != 200:
            stats["sources_failed"] += 1
            continue
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "javascript" not in ctype and ".js" not in js_url.lower():
            continue
        body = (resp.text or "")[:max_js_chars]
        scripts_to_scan.append((js_url, body))
        stats["sources_fetched"] += 1
        stats["bytes_scanned"] += len(body)

    if not scripts_to_scan:
        return findings, stats

    cred_patterns = [
        ("Hardcoded Password", re.compile(r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\']([^"\']{4,120})["\']')),
        ("Hardcoded Username", re.compile(r'(?i)\b(username|user|login|email)\b\s*[:=]\s*["\']([^"\']{2,120})["\']')),
    ]

    seen = set()
    for source, content in scripts_to_scan:
        for kind, pattern in cred_patterns:
            for match in pattern.findall(content):
                key, value = match[0], match[1]
                if _is_placeholder_secret(value):
                    continue
                evidence = f"{key}=\"{_mask_secret(value)}\""
                fp = (kind, source, evidence)
                if fp in seen:
                    continue
                seen.add(fp)
                severity = "HIGH" if kind == "Hardcoded Password" else "MEDIUM"
                findings.append({
                    "kind": kind,
                    "source": source,
                    "severity": severity,
                    "evidence": evidence,
                })
                if len(findings) >= max_findings:
                    findings.sort(key=lambda x: (x["severity"] != "HIGH", x["source"], x["evidence"]))
                    return findings, stats

    findings.sort(key=lambda x: (x["severity"] != "HIGH", x["source"], x["evidence"]))
    return findings, stats


def _check_security_headers(base_url, headers):
    """Check for missing or misconfigured security headers."""
    findings = []
    try:
        resp = requests.get(base_url, headers=headers, timeout=10, verify=False)
        h = resp.headers

        checks = [
            ("Strict-Transport-Security", "HSTS missing — no HTTPS enforcement", "HIGH"),
            ("Content-Security-Policy", "CSP missing — XSS protection weakened", "MEDIUM"),
            ("X-Frame-Options", "X-Frame-Options missing — clickjacking risk", "MEDIUM"),
            ("X-Content-Type-Options", "X-Content-Type-Options missing — MIME sniffing risk", "LOW"),
            ("X-XSS-Protection", "X-XSS-Protection missing", "LOW"),
            ("Referrer-Policy", "Referrer-Policy missing — referrer leakage", "LOW"),
            ("Permissions-Policy", "Permissions-Policy missing", "LOW"),
        ]

        for header, issue, severity in checks:
            if header not in h:
                findings.append({"severity": severity, "issue": issue})

        # Check HSTS value if present
        hsts = h.get("Strict-Transport-Security", "")
        if hsts and "max-age" in hsts:
            try:
                max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                if max_age < 31536000:
                    findings.append({"severity": "MEDIUM", "issue": f"HSTS max-age too low ({max_age}s, should be ≥31536000)"})
            except Exception:
                pass

        # Check for server version disclosure
        server = h.get("Server", "")
        if server and any(v in server for v in ["/", "."]):
            findings.append({"severity": "LOW", "issue": f"Server version disclosed: {server}"})

        x_powered = h.get("X-Powered-By", "")
        if x_powered:
            findings.append({"severity": "LOW", "issue": f"X-Powered-By disclosed: {x_powered}"})

    except Exception:
        pass

    return findings


def _check_directory_listing(base_url, headers):
    """Check common directories for directory listing."""
    dirs_to_check = ["/images/", "/uploads/", "/wp-content/uploads/", "/css/", "/js/", "/assets/"]
    for d in dirs_to_check:
        try:
            resp = requests.get(base_url + d, headers=headers, timeout=8, verify=False, allow_redirects=False)
            if resp.status_code == 200 and "index of" in resp.text.lower():
                return f"[MEDIUM] Directory listing enabled at {base_url}{d}"
        except Exception:
            continue
    return ""


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "check_exposed_paths",
        "description": "Actively scan a website for exposed sensitive files, admin panels, backups, .git repos, .env files, API endpoints, and security header misconfigurations. Also checks login attack-surface indicators (captcha/rate-limit signals) and samples client-side code for hardcoded password/credential patterns. Probes 50+ common paths and verifies each finding is real (not a custom 404). Returns severity-rated findings with evidence. Use this AFTER initial recon to actively verify vulnerabilities.",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {
                    "type": "string",
                    "description": "The base URL to scan, e.g. 'https://example.com' or 'example.com'"
                },
                "scan_profile": {
                    "type": "string",
                    "enum": ["standard", "deep"],
                    "description": "Optional credential-scan depth. Use deep for deterministic broader JS credential checks."
                }
            },
            "required": ["base_url"]
        }
    }
}
