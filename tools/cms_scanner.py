"""
CMS detection and vulnerability scanner.
Identifies WordPress, Joomla, Drupal, Magento, etc. and checks for known vulns.
"""

import requests
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

CMS_FINGERPRINTS = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/", "/xmlrpc.php", "/wp-json/wp/v2/"],
        "headers": ["x-powered-by: wordpress", "link: <.*wp-json"],
        "body": ['<meta name="generator" content="WordPress', "wp-content/", "wp-includes/", "/wp-json/"],
        "version_paths": [
            ("/readme.html", r'Version\s+([\d.]+)'),
            ("/feed/", r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>'),
            ("/wp-links-opml.php", r'generator="WordPress/([\d.]+)"'),
        ],
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/", "/templates/", "/api/index.php/v1/config/application"],
        "headers": [],
        "body": ['<meta name="generator" content="Joomla', "com_content", "/media/jui/"],
        "version_paths": [
            ("/administrator/manifests/files/joomla.xml", r'<version>([\d.]+)</version>'),
            ("/language/en-GB/en-GB.xml", r'<version>([\d.]+)</version>'),
        ],
    },
    "Drupal": {
        "paths": ["/core/", "/sites/default/", "/user/login", "/node/1", "/admin/config"],
        "headers": ["x-generator: drupal", "x-drupal-cache"],
        "body": ['<meta name="Generator" content="Drupal', "Drupal.settings", "sites/default/files"],
        "version_paths": [
            ("/CHANGELOG.txt", r'Drupal\s+([\d.]+)'),
            ("/core/CHANGELOG.txt", r'Drupal\s+([\d.]+)'),
        ],
    },
    "Magento": {
        "paths": ["/admin/", "/downloader/", "/skin/frontend/", "/js/mage/"],
        "headers": ["x-magento-"],
        "body": ["Mage.Cookies", "magento", "/skin/frontend/"],
        "version_paths": [
            ("/magento_version", r'([\d.]+)'),
        ],
    },
    "Shopify": {
        "paths": [],
        "headers": ["x-shopify-stage", "x-shopid"],
        "body": ["cdn.shopify.com", "Shopify.theme", "myshopify.com"],
        "version_paths": [],
    },
    "Laravel": {
        "paths": [],
        "headers": ["set-cookie: laravel_session"],
        "body": ["laravel", "csrf-token"],
        "version_paths": [],
    },
    "Django": {
        "paths": ["/admin/login/"],
        "headers": ["set-cookie: csrftoken", "set-cookie: django"],
        "body": ["csrfmiddlewaretoken", "django"],
        "version_paths": [],
    },
    "Express/Node.js": {
        "paths": [],
        "headers": ["x-powered-by: express"],
        "body": [],
        "version_paths": [],
    },
    "ASP.NET": {
        "paths": [],
        "headers": ["x-aspnet-version", "x-powered-by: asp.net"],
        "body": ["__VIEWSTATE", "__EVENTTARGET", "asp.net"],
        "version_paths": [],
    },
    "Ruby on Rails": {
        "paths": [],
        "headers": ["x-powered-by: phusion", "set-cookie: _session_id"],
        "body": ["csrf-token", "data-turbo"],
        "version_paths": [],
    },
    "Next.js": {
        "paths": ["/_next/"],
        "headers": ["x-powered-by: next.js"],
        "body": ["__NEXT_DATA__", "_next/static", "nextjs"],
        "version_paths": [],
    },
    "Nuxt.js": {
        "paths": ["/_nuxt/"],
        "headers": [],
        "body": ["__NUXT__", "_nuxt/"],
        "version_paths": [],
    },
}

# Known vulnerable versions (sample — agent should use lookup_cve for full list)
KNOWN_VULNS = {
    "WordPress": {
        "6.4": ["CVE-2023-39999 (Contributor+ arbitrary shortcode execution)"],
        "6.3": ["CVE-2023-38000 (Stored XSS via navigation block)"],
        "6.2": ["CVE-2023-22622 (unauthenticated blind SSRF via DNS rebinding)"],
        "5.": ["Multiple critical CVEs — update immediately"],
        "4.": ["Extremely outdated — dozens of critical RCE and SQLi CVEs"],
    },
    "Joomla": {
        "4.2": ["CVE-2023-23752 (unauthenticated info disclosure — DB creds)"],
        "3.": ["Multiple critical CVEs including RCE"],
    },
    "Drupal": {
        "9.": ["Check for Drupalgeddon variants"],
        "8.": ["CVE-2019-6340 (RCE via REST)"],
        "7.": ["CVE-2018-7600 Drupalgeddon2 (unauthenticated RCE)"],
    },
}

# WordPress-specific checks
WP_VULN_PATHS = [
    ("/wp-json/wp/v2/users", "User enumeration via REST API"),
    ("/wp-json/wp/v2/posts?per_page=100", "Post listing (may contain drafts)"),
    ("/wp-json/wp/v2/pages?per_page=100", "Page listing"),
    ("/wp-json/wp/v2/settings", "Settings disclosure"),
    ("/wp-json/wp/v2/media?per_page=100", "Media enumeration"),
    ("/wp-json/wp/v2/search?search=", "Search endpoint"),
    ("/?rest_route=/wp/v2/users", "User enum (alt route)"),
    ("/xmlrpc.php", "XML-RPC (brute force, pingback SSRF)"),
    ("/wp-config.php.bak", "Config backup"),
    ("/wp-config.php~", "Config backup (vim)"),
    ("/wp-config.php.save", "Config backup (nano)"),
    ("/wp-config.php.swp", "Config swap file"),
    ("/wp-config.php.old", "Old config"),
    ("/.wp-config.php.swp", "Hidden swap file"),
    ("/wp-content/debug.log", "Debug log (may contain errors/paths)"),
    ("/wp-content/uploads/", "Upload directory listing"),
    ("/readme.html", "Version disclosure"),
    ("/license.txt", "WP license (confirms WP)"),
    ("/wp-content/plugins/", "Plugin directory listing"),
    ("/wp-content/themes/", "Theme directory listing"),
    ("/wp-admin/install.php", "Installation script"),
    ("/wp-admin/setup-config.php", "Setup script"),
    ("/.htaccess", "Apache config"),
    ("/wp-content/uploads/wc-logs/", "WooCommerce logs"),
]


def _clean_wp_slug(value):
    """Normalize plugin/theme slugs and drop obvious noise."""
    slug = re.sub(r"[^a-z0-9._-]", "", (value or "").strip().lower())
    if not slug:
        return ""
    if slug in {"*", ",", ".", "-", "_", "null", "undefined"}:
        return ""
    if len(slug) < 2:
        return ""
    return slug


def _classify_wp_exposure(path):
    critical_paths = {
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/wp-config.php.save",
        "/wp-config.php.swp",
        "/wp-config.php.old",
        "/.wp-config.php.swp",
    }
    high_paths = {
        "/wp-json/wp/v2/users",
        "/?rest_route=/wp/v2/users",
        "/xmlrpc.php",
        "/wp-admin/setup-config.php",
        "/wp-admin/install.php",
        "/wp-content/debug.log",
        "/wp-content/uploads/wc-logs/",
    }
    medium_paths = {
        "/readme.html",
        "/license.txt",
        "/wp-json/wp/v2/media?per_page=100",
        "/wp-json/wp/v2/posts?per_page=100",
        "/wp-json/wp/v2/pages?per_page=100",
        "/wp-content/uploads/",
        "/wp-content/plugins/",
        "/wp-content/themes/",
    }

    if path in critical_paths:
        return "CRITICAL"
    if path in high_paths:
        return "HIGH"
    if path in medium_paths:
        return "MEDIUM"
    return "LOW"


def cms_scan(target, stream_callback=None):
    """Detect CMS, version, and check for known vulnerabilities."""
    def _emit(msg):
        if stream_callback:
            stream_callback("cms_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 CMS Detection & Vulnerability Scan: {base}")
    start = time.time()

    # Fetch main page
    try:
        r = requests.get(base, timeout=10, headers=HDR, verify=False, allow_redirects=True)
    except Exception:
        return format_unreachable_error(target, resolution)

    main_html = r.text.lower()
    main_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
    detected_cms = []

    # ── Phase 1: CMS Detection ──
    _emit("🔍 Fingerprinting CMS...")
    for cms_name, fp in CMS_FINGERPRINTS.items():
        confidence = 0

        # Check response body
        for pattern in fp["body"]:
            if pattern.lower() in main_html:
                confidence += 30

        # Check headers
        for h_pattern in fp["headers"]:
            for hk, hv in main_headers.items():
                if h_pattern.lower() in f"{hk}: {hv}":
                    confidence += 25

        # Check known paths
        for path in fp["paths"][:3]:
            try:
                rp = requests.get(f"{base}{path}", timeout=5, headers=HDR, verify=False, allow_redirects=False)
                if rp.status_code in (200, 301, 302, 403):
                    confidence += 20
            except Exception:
                pass

        if confidence >= 30:
            detected_cms.append({"name": cms_name, "confidence": min(confidence, 100), "version": None})

    if not detected_cms:
        _emit("  No known CMS detected — may be custom-built")

    # ── Phase 2: Version Detection ──
    for cms in detected_cms:
        _emit(f"  ✅ Detected: {cms['name']} (confidence: {cms['confidence']}%)")
        fp = CMS_FINGERPRINTS.get(cms["name"], {})
        for path, regex in fp.get("version_paths", []):
            try:
                rv = requests.get(f"{base}{path}", timeout=5, headers=HDR, verify=False)
                match = re.search(regex, rv.text)
                if match:
                    cms["version"] = match.group(1)
                    _emit(f"    Version: {cms['version']}")
                    break
            except Exception:
                pass

    # ── Phase 3: CMS-specific vulnerability checks ──
    findings = []
    wp_detected = any(c["name"] == "WordPress" for c in detected_cms)

    if wp_detected:
        _emit("🔨 Running WordPress-specific vulnerability checks...")

        def _check_wp_path(path_info):
            path, desc = path_info
            try:
                r = requests.get(f"{base}{path}", timeout=6, headers=HDR, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 50:
                    # Verify it's not just a generic 200
                    if "404" not in r.text[:200].lower() and "not found" not in r.text[:200].lower():
                        sev = _classify_wp_exposure(path)
                        return {"path": path, "desc": desc, "status": r.status_code, "size": len(r.text),
                                "preview": r.text[:200], "severity": sev}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(_check_wp_path, p): p for p in WP_VULN_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    _emit(f"  🔴 Found: {result['path']} — {result['desc']}")

        # Plugin/theme enumeration
        _emit("  Enumerating plugins and themes...")
        plugins_found = set()
        themes_found = set()

        # From HTML
        html_for_slug_enum = r.text if hasattr(r, "text") else main_html
        for match in re.findall(r'/wp-content/plugins/([^/]+)/', html_for_slug_enum):
            cleaned = _clean_wp_slug(match)
            if cleaned:
                plugins_found.add(cleaned)
        for match in re.findall(r'/wp-content/themes/([^/]+)/', html_for_slug_enum):
            cleaned = _clean_wp_slug(match)
            if cleaned:
                themes_found.add(cleaned)

        # Common vulnerable plugins
        vuln_plugins = [
            "contact-form-7", "elementor", "woocommerce", "wp-file-manager",
            "wpforms-lite", "classic-editor", "akismet", "jetpack",
            "all-in-one-seo-pack", "wordfence", "wp-super-cache",
            "really-simple-ssl", "yoast-seo", "w3-total-cache",
            "updraftplus", "duplicator", "loginizer", "nextgen-gallery",
            "revslider", "js_composer", "theme-jesuspended",
        ]
        for plugin in vuln_plugins:
            if plugin not in plugins_found:
                try:
                    rp = requests.get(f"{base}/wp-content/plugins/{plugin}/readme.txt", timeout=3, headers=HDR, verify=False)
                    if rp.status_code == 200 and ("stable tag" in rp.text.lower() or "contributors" in rp.text.lower()):
                        plugins_found.add(plugin)
                        ver_match = re.search(r'Stable tag:\s*([\d.]+)', rp.text, re.I)
                        ver = ver_match.group(1) if ver_match else "unknown"
                        _emit(f"  📦 Plugin: {plugin} (v{ver})")
                except Exception:
                    pass

    # ── Phase 4: Known CVE check ──
    vuln_matches = []
    for cms in detected_cms:
        if cms["version"] and cms["name"] in KNOWN_VULNS:
            for ver_prefix, cves in KNOWN_VULNS[cms["name"]].items():
                if cms["version"].startswith(ver_prefix):
                    vuln_matches.extend(cves)

    # ── Phase 5: Technology stack detection ──
    _emit("🔍 Detecting technology stack...")
    tech_stack = []
    tech_checks = {
        "jQuery": (r'jquery[.-](\d+\.\d+[\.\d]*)', main_html),
        "Bootstrap": (r'bootstrap[.-](\d+\.\d+[\.\d]*)', main_html),
        "React": (r'react', main_html),
        "Angular": (r'ng-app|angular', main_html),
        "Vue.js": (r'vue[.-](\d+)?', main_html),
        "PHP": (r'x-powered-by.*php/([\d.]+)', str(main_headers)),
        "Nginx": (r'server.*nginx/([\d.]+)', str(main_headers)),
        "Apache": (r'server.*apache/([\d.]+)', str(main_headers)),
        "IIS": (r'server.*iis/([\d.]+)', str(main_headers)),
        "Cloudflare": (r'server.*cloudflare', str(main_headers)),
    }
    for tech, (pattern, text) in tech_checks.items():
        match = re.search(pattern, text, re.I)
        if match:
            ver = match.group(1) if match.lastindex else ""
            tech_stack.append(f"{tech} {ver}".strip())

    elapsed = time.time() - start

    # ── Format output ──
    lines = [
        f"CMS & TECHNOLOGY SCAN for {base}",
        f"{'='*60}",
        f"Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if detected_cms:
        lines.append("📋 DETECTED CMS")
        lines.append("-" * 40)
        for cms in detected_cms:
            ver_str = f" v{cms['version']}" if cms['version'] else ""
            lines.append(f"  {cms['name']}{ver_str} (confidence: {cms['confidence']}%)")
        lines.append("")
    else:
        lines.append("No known CMS detected (likely custom-built)\n")

    if tech_stack:
        lines.append("⚙️ TECHNOLOGY STACK")
        lines.append("-" * 40)
        for tech in tech_stack:
            lines.append(f"  {tech}")
        lines.append("")

    if vuln_matches:
        lines.append("🔴 KNOWN VULNERABILITIES (version-based)")
        lines.append("-" * 40)
        for v in vuln_matches:
            lines.append(f"  ⚠️ {v}")
        lines.append("")

    if findings:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda item: (sev_order.get(item.get("severity", "LOW"), 4), item.get("path", "")))
        lines.append(f"🔴 EXPOSED PATHS ({len(findings)} found)")
        lines.append("-" * 40)
        for f in findings:
            lines.append(f"  [{f.get('severity', 'LOW')}] {f['path']} — {f['desc']}")
            lines.append(f"    Status: {f['status']}, Size: {f['size']} bytes")
            if "user" in f['path'].lower() and f.get('preview'):
                lines.append(f"    Preview: {f['preview'][:100]}...")
        lines.append("")
        severe_findings = [f for f in findings if f.get("severity") in {"CRITICAL", "HIGH"}]
        if severe_findings:
            lines.append(f"🚨 HIGH-IMPACT VERIFIED LEADS ({len(severe_findings)})")
            lines.append("-" * 40)
            for f in severe_findings:
                lines.append(f"  [{f['severity']}] {f['path']} — {f['desc']}")
            lines.append("")

    if wp_detected:
        if plugins_found:
            lines.append(f"📦 WORDPRESS PLUGINS ({len(plugins_found)})")
            lines.append("-" * 40)
            for p in sorted(plugins_found):
                lines.append(f"  {p}")
            lines.append("")
        if themes_found:
            lines.append(f"🎨 WORDPRESS THEMES ({len(themes_found)})")
            lines.append("-" * 40)
            for t in sorted(themes_found):
                lines.append(f"  {t}")
            lines.append("")

    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 40)
    next_steps = []
    if detected_cms:
        cms_name = detected_cms[0]["name"]
        ver = detected_cms[0].get("version", "")
        if ver:
            next_steps.append(f"Run: lookup_cve software='{cms_name}' version='{ver}'")
        next_steps.append(f"Run: run_nuclei target='{base}' severity='critical,high,medium'")
    if wp_detected:
        next_steps.append(f"Run: run_wpscan target='{base}' scan_profile='aggressive_enum'")
    next_steps.append(f"Run: check_exposed_paths base_url='{base}'")
    next_steps.append("Run: js_analyze to find secrets in JavaScript")
    next_steps.append("Run: param_mine to find hidden parameters")

    for idx, step in enumerate(next_steps, 1):
        lines.append(f"  {idx}. {step}")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "cms_scan",
        "description": "Detect CMS (WordPress, Joomla, Drupal, Magento, Shopify, Laravel, Django, Next.js, etc.), extract version, enumerate plugins/themes, and check for known vulnerabilities. For WordPress: enumerates users via REST API, checks xmlrpc.php, debug.log, config backups, plugin versions, and known CVEs. Also detects web server and technology stack.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to scan"
                }
            },
            "required": ["target"]
        }
    }
}
