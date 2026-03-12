"""
Subdomain enumeration — passive (crt.sh, DNS) + active (brute force).
Finds hidden subdomains, checks for takeover, resolves IPs.
"""

import requests
import socket
import json
import time
import re
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}

# Common subdomain wordlist for brute forcing
SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
    "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum",
    "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
    "exchange", "app", "gov", "2tty", "vps", "govyty", "hgfgdf",
    "news", "1702", "log", "mx2", "cdn1", "cdn2", "dns", "dns1",
    "dns2", "info", "staging", "stage", "beta", "alpha", "demo",
    "preview", "pre", "prod", "production", "internal", "intranet",
    "old", "new", "backup", "db", "database", "mysql", "postgres",
    "mongo", "redis", "elastic", "kibana", "grafana", "prometheus",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "jira", "confluence", "wiki", "docs", "doc", "help", "helpdesk",
    "status", "monitor", "monitoring", "nagios", "zabbix", "cacti",
    "sentry", "logs", "elk", "splunk", "vault", "consul", "docker",
    "k8s", "kubernetes", "rancher", "registry", "repo", "npm",
    "pypi", "maven", "nexus", "artifactory", "sonar", "sonarqube",
    "proxy", "gateway", "lb", "loadbalancer", "haproxy", "nginx",
    "apache", "tomcat", "iis", "cpanel", "plesk", "whm", "webmin",
    "panel", "dashboard", "console", "manage", "management", "mgmt",
    "sso", "auth", "oauth", "login", "signin", "signup", "register",
    "account", "accounts", "user", "users", "profile", "my",
    "static", "assets", "media", "images", "img", "files", "upload",
    "uploads", "download", "downloads", "cdn3", "edge", "origin",
    "api2", "api3", "v1", "v2", "v3", "rest", "graphql", "ws",
    "websocket", "socket", "chat", "messaging", "push", "notify",
    "notification", "webhook", "hooks", "callback", "worker",
    "queue", "mq", "rabbitmq", "kafka", "celery", "cron", "job",
    "task", "scheduler", "analytics", "tracking", "pixel", "tag",
    "ads", "ad", "marketing", "crm", "erp", "hr", "finance",
    "billing", "payment", "pay", "checkout", "cart", "order",
    "invoice", "report", "reports", "data", "bi", "warehouse",
    "etl", "airflow", "spark", "hadoop", "s3", "storage", "bucket",
    "archive", "sandbox", "uat", "qa", "testing", "perf", "load",
    "stress", "canary", "blue", "green", "release", "deploy",
]

# CNAME fingerprints for subdomain takeover
TAKEOVER_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "cloudfront.net": ("CloudFront", "Bad request"),
    "azurewebsites.net": ("Azure", "404 Web Site not found"),
    "trafficmanager.net": ("Azure Traffic Manager", ""),
    "cloudapp.net": ("Azure", ""),
    "blob.core.windows.net": ("Azure Blob", "BlobNotFound"),
    "shopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "surge.sh": ("Surge", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "pantheon.io": ("Pantheon", "404 error unknown site"),
    "zendesk.com": ("Zendesk", "Help Center Closed"),
    "teamwork.com": ("Teamwork", "Oops - We didn't find your site"),
    "helpjuice.com": ("Helpjuice", "We could not find what you're looking for"),
    "helpscoutdocs.com": ("HelpScout", "No settings were found for this company"),
    "cargo.site": ("Cargo", "404 Not Found"),
    "statuspage.io": ("Statuspage", "You are being redirected"),
    "tumblr.com": ("Tumblr", "There's nothing here"),
    "wordpress.com": ("WordPress", "Do you want to register"),
    "feedpress.me": ("Feedpress", "The feed has not been found"),
    "unbounce.com": ("Unbounce", "The requested URL was not found"),
    "readme.io": ("Readme.io", "Project doesnt exist"),
    "fly.dev": ("Fly.io", ""),
    "netlify.app": ("Netlify", "Not Found"),
    "vercel.app": ("Vercel", ""),
    "pages.dev": ("Cloudflare Pages", ""),
    "render.com": ("Render", ""),
    "railway.app": ("Railway", ""),
}


def _iter_with_thread_fallback(items, worker_fn, max_workers, emit=None, warning=None):
    """Run worker_fn concurrently when possible; fallback to sequential on thread exhaustion."""
    seq_items = list(items)
    if not seq_items:
        return

    try:
        with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as executor:
            futures = {executor.submit(worker_fn, item): item for item in seq_items}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    yield item, future.result(), None
                except Exception as exc:
                    yield item, None, exc
    except RuntimeError as exc:
        if "can't start new thread" not in str(exc).lower():
            raise
        if emit:
            emit(warning or "  ⚠️ Thread limit reached; switching to sequential mode.")
        for item in seq_items:
            try:
                yield item, worker_fn(item), None
            except Exception as item_exc:
                yield item, None, item_exc


def _resolve(subdomain, record_type="A"):
    """Resolve DNS record."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(subdomain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []


def _check_cname_takeover(subdomain):
    """Check if subdomain has a dangling CNAME (takeover opportunity)."""
    cnames = _resolve(subdomain, "CNAME")
    if not cnames:
        return None

    cname = cnames[0].rstrip(".")
    for fingerprint, (provider, error_text) in TAKEOVER_FINGERPRINTS.items():
        if fingerprint in cname:
            # Check if the CNAME target resolves
            target_ips = _resolve(cname, "A")
            if not target_ips:
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "provider": provider,
                    "status": "VULNERABLE — CNAME target does not resolve",
                    "severity": "HIGH",
                }
            # Check if the page shows an error
            if error_text:
                try:
                    r = requests.get(f"http://{subdomain}", timeout=5, headers=HDR, verify=False)
                    if error_text.lower() in r.text.lower():
                        return {
                            "subdomain": subdomain,
                            "cname": cname,
                            "provider": provider,
                            "status": f"LIKELY VULNERABLE — Error page matches: '{error_text}'",
                            "severity": "HIGH",
                        }
                except Exception:
                    pass
            return {
                "subdomain": subdomain,
                "cname": cname,
                "provider": provider,
                "status": "CNAME points to third-party — verify manually",
                "severity": "MEDIUM",
            }
    return None


def subdomain_enumerate(target, mode="passive", stream_callback=None):
    """
    Enumerate subdomains for a target domain.
    
    mode: 'passive' (crt.sh + DNS only), 'active' (passive + brute force), 'full' (all techniques)
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("subdomain_progress", {"message": msg})

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    # Strip www
    if domain.startswith("www."):
        domain = domain[4:]

    _emit(f"🎯 Enumerating subdomains for: {domain}")
    found = set()
    details = {}
    start = time.time()

    # ── Phase 1: crt.sh (Certificate Transparency) ──
    _emit("📜 Querying Certificate Transparency logs (crt.sh)...")
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15, headers=HDR)
        if r.status_code == 200:
            entries = r.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        found.add(sub)
            _emit(f"  crt.sh: {len(found)} unique subdomains from CT logs")
    except Exception as e:
        _emit(f"  crt.sh error: {e}")

    # ── Phase 2: Common DNS records ──
    _emit("🔍 Checking common DNS records...")
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        records = _resolve(domain, rtype)
        if records:
            _emit(f"  {rtype}: {', '.join(records[:3])}")

    # ── Phase 3: Active brute force ──
    if mode in ("active", "full"):
        _emit(f"🔨 Brute forcing {len(SUBDOMAIN_WORDLIST)} subdomains...")
        brute_found = 0

        def _check_sub(word):
            sub = f"{word}.{domain}"
            ips = _resolve(sub, "A")
            if ips:
                return sub, ips
            return None, None

        done = 0
        for _, result, _ in _iter_with_thread_fallback(
            SUBDOMAIN_WORDLIST,
            _check_sub,
            max_workers=24,
            emit=_emit,
            warning="  ⚠️ Thread limit reached; brute-force switched to sequential checks.",
        ):
            done += 1
            if done % 50 == 0:
                _emit(f"  Brute force: {done}/{len(SUBDOMAIN_WORDLIST)} checked, {brute_found} found...")
            sub, ips = result or (None, None)
            if sub:
                found.add(sub)
                brute_found += 1
                details[sub] = {"ips": ips}

        _emit(f"  Brute force found {brute_found} additional subdomains")

    # ── Phase 4: Resolve all found subdomains ──
    _emit(f"📡 Resolving {len(found)} subdomains...")
    resolved = []
    live_http = []

    def _resolve_and_check(sub):
        ips = _resolve(sub, "A")
        if not ips:
            return None
        # Quick HTTP check
        http_status = None
        title = ""
        for scheme in ["https", "http"]:
            try:
                r = requests.get(f"{scheme}://{sub}", timeout=4, headers=HDR, verify=False, allow_redirects=True)
                http_status = r.status_code
                # Extract title
                import re
                t = re.search(r'<title[^>]*>([^<]+)</title>', r.text, re.I)
                if t:
                    title = t.group(1).strip()[:60]
                break
            except Exception:
                continue
        return {"subdomain": sub, "ips": ips, "http_status": http_status, "title": title}

    for _, result, _ in _iter_with_thread_fallback(
        found,
        _resolve_and_check,
        max_workers=16,
        emit=_emit,
        warning="  ⚠️ Thread limit reached; host resolution switched to sequential checks.",
    ):
        if result:
            resolved.append(result)
            if result["http_status"]:
                live_http.append(result)

    # ── Phase 5: Takeover checks ──
    _emit("🔓 Checking for subdomain takeover...")
    takeovers = []
    for sub in list(found)[:50]:
        result = _check_cname_takeover(sub)
        if result:
            takeovers.append(result)
            _emit(f"  ⚠️ POTENTIAL TAKEOVER: {result['subdomain']} → {result['cname']} ({result['provider']})")

    elapsed = time.time() - start
    resolved.sort(key=lambda x: x["subdomain"])

    # Format output
    lines = [
        f"SUBDOMAIN ENUMERATION for {domain}",
        f"{'='*60}",
        f"Mode: {mode} | Found: {len(found)} | Resolved: {len(resolved)} | Live HTTP: {len(live_http)} | Time: {elapsed:.1f}s\n",
    ]

    if live_http:
        lines.append("LIVE WEB SERVICES (attack targets)")
        lines.append("-" * 40)
        for r in sorted(live_http, key=lambda x: x["subdomain"]):
            status_icon = "🟢" if r["http_status"] == 200 else "🟡"
            lines.append(f"  {status_icon} {r['subdomain']} [{r['http_status']}] — {r['title']}")
            lines.append(f"     IP: {', '.join(r['ips'])}")
        lines.append("")

    if takeovers:
        lines.append("⚠️ SUBDOMAIN TAKEOVER CANDIDATES")
        lines.append("-" * 40)
        for t in takeovers:
            lines.append(f"  🔴 {t['subdomain']} → {t['cname']} ({t['provider']})")
            lines.append(f"     Status: {t['status']}")
        lines.append("")

    # Non-HTTP resolved
    non_http = [r for r in resolved if not r["http_status"]]
    if non_http:
        lines.append(f"OTHER RESOLVED SUBDOMAINS ({len(non_http)})")
        lines.append("-" * 40)
        for r in non_http[:30]:
            lines.append(f"  {r['subdomain']} → {', '.join(r['ips'])}")
        lines.append("")

    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 40)
    if live_http:
        lines.append(f"  1. Run exploit_target type='auto' on each live subdomain")
        lines.append(f"  2. Run run_nuclei on all {len(live_http)} live hosts")
        lines.append(f"  3. Run run_ffuf for hidden directories on each")
    if takeovers:
        lines.append(f"  4. Verify subdomain takeover on {len(takeovers)} candidates")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "subdomain_enum",
        "description": "Enumerate subdomains using Certificate Transparency (crt.sh), DNS brute force, and active resolution. Checks each subdomain for HTTP services and subdomain takeover vulnerabilities. Use mode='active' for brute force, 'passive' for CT logs only.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain (e.g., 'example.com')"
                },
                "mode": {
                    "type": "string",
                    "enum": ["passive", "active", "full"],
                    "description": "Enumeration mode. passive=CT logs+DNS, active=passive+brute force, full=all techniques"
                }
            },
            "required": ["target"]
        }
    }
}
