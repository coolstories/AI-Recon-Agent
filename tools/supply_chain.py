"""
Supply chain & third-party analysis — CDN integrity, dependency confusion,
exposed package manifests, third-party JS risk, SRI validation.
Targets like YouTube/Apple use hundreds of third-party resources.
"""

import requests
import re
import time
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Known vulnerable JS libraries (version ranges)
KNOWN_VULN_LIBS = {
    "jquery": {
        "pattern": r'jquery[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "1.": "Multiple XSS (CVE-2020-11022, CVE-2020-11023, CVE-2019-11358)",
            "2.": "Prototype pollution, XSS (CVE-2020-11022)",
            "3.0": "Prototype pollution (CVE-2019-11358)",
            "3.1": "Prototype pollution (CVE-2019-11358)",
            "3.2": "Prototype pollution (CVE-2019-11358)",
            "3.3": "Prototype pollution (CVE-2019-11358)",
            "3.4": "Prototype pollution (CVE-2019-11358)",
        },
    },
    "angular": {
        "pattern": r'angular[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "1.": "Template injection, sandbox escape, XSS",
        },
    },
    "lodash": {
        "pattern": r'lodash[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "4.17.": "Prototype pollution (CVE-2020-28500, CVE-2021-23337) if < 4.17.21",
        },
    },
    "moment": {
        "pattern": r'moment[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "2.": "ReDoS (CVE-2022-31129) if < 2.29.4",
        },
    },
    "bootstrap": {
        "pattern": r'bootstrap[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "3.": "XSS via data-attributes (CVE-2019-8331) if < 3.4.1",
            "4.0": "XSS via tooltip/popover (CVE-2019-8331)",
            "4.1": "XSS (CVE-2019-8331) if < 4.1.2",
        },
    },
    "dompurify": {
        "pattern": r'dompurify[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "2.": "mXSS bypass (multiple CVEs) if < 2.4.0",
        },
    },
    "handlebars": {
        "pattern": r'handlebars[.\-/]v?(\d+\.\d+\.\d+)',
        "vulns": {
            "4.": "Prototype pollution RCE (CVE-2021-23383) if < 4.7.7",
        },
    },
}

# Package manifest files that leak dependency info
MANIFEST_PATHS = [
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/pom.xml", "/build.gradle", "/build.gradle.kts",
    "/go.mod", "/go.sum",
    "/Cargo.toml", "/Cargo.lock",
    "/pubspec.yaml", "/pubspec.lock",
    "/mix.exs", "/mix.lock",
    "/bower.json", "/bower_components/",
    "/node_modules/.package-lock.json",
    "/.npmrc", "/.yarnrc", "/.yarnrc.yml",
    "/shrinkwrap.yaml", "/pnpm-lock.yaml",
]


def _extract_third_party_resources(base_url):
    """Extract all third-party JS, CSS, fonts, iframes from a page."""
    resources = {"scripts": [], "styles": [], "iframes": [], "fonts": [], "images": []}
    domain = urlparse(base_url).netloc

    try:
        r = requests.get(base_url, headers=HDR, timeout=15, verify=False)
        html = r.text

        # Extract script src
        for src in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(base_url, src)
            parsed = urlparse(full)
            if parsed.netloc and parsed.netloc != domain:
                has_sri = bool(re.search(
                    r'<script[^>]*src=["\']' + re.escape(src) + r'["\'][^>]*integrity=["\']',
                    html, re.I
                ))
                resources["scripts"].append({"url": full, "domain": parsed.netloc, "sri": has_sri})

        # Extract link href (CSS, fonts)
        for match in re.finditer(r'<link[^>]*href=["\']([^"\']+)["\'][^>]*>', html, re.I):
            href = match.group(1)
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.netloc and parsed.netloc != domain:
                tag = match.group(0)
                has_sri = "integrity=" in tag
                if "stylesheet" in tag or ".css" in href:
                    resources["styles"].append({"url": full, "domain": parsed.netloc, "sri": has_sri})
                elif "font" in tag or any(ext in href for ext in [".woff", ".woff2", ".ttf", ".otf"]):
                    resources["fonts"].append({"url": full, "domain": parsed.netloc})

        # Extract iframes
        for src in re.findall(r'<iframe[^>]*src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(base_url, src)
            parsed = urlparse(full)
            if parsed.netloc and parsed.netloc != domain:
                resources["iframes"].append({"url": full, "domain": parsed.netloc})

    except Exception:
        pass

    return resources


def _check_sri(resources):
    """Check Subresource Integrity on third-party resources."""
    findings = []
    for script in resources.get("scripts", []):
        if not script["sri"]:
            findings.append({
                "type": "missing_sri",
                "severity": "MEDIUM",
                "resource": script["url"],
                "domain": script["domain"],
                "desc": f"Third-party script from {script['domain']} loaded WITHOUT Subresource Integrity",
            })
    for style in resources.get("styles", []):
        if not style["sri"]:
            findings.append({
                "type": "missing_sri_css",
                "severity": "LOW",
                "resource": style["url"],
                "domain": style["domain"],
                "desc": f"Third-party CSS from {style['domain']} loaded without SRI",
            })
    return findings


def _check_vuln_libraries(base_url, resources):
    """Check for known vulnerable JS libraries."""
    findings = []
    checked = set()

    # Check inline and third-party scripts
    all_urls = [s["url"] for s in resources.get("scripts", [])]

    # Also check first-party scripts
    try:
        r = requests.get(base_url, headers=HDR, timeout=10, verify=False)
        for src in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', r.text, re.I):
            full = urljoin(base_url, src)
            if full not in all_urls:
                all_urls.append(full)
        # Check inline JS too
        for lib_name, lib_info in KNOWN_VULN_LIBS.items():
            match = re.search(lib_info["pattern"], r.text, re.I)
            if match:
                version = match.group(1)
                key = f"{lib_name}-{version}"
                if key not in checked:
                    checked.add(key)
                    for ver_prefix, vuln_desc in lib_info["vulns"].items():
                        if version.startswith(ver_prefix):
                            findings.append({
                                "type": "vuln_library",
                                "severity": "HIGH",
                                "library": lib_name,
                                "version": version,
                                "desc": f"{lib_name} {version}: {vuln_desc}",
                                "source": "inline",
                            })
    except Exception:
        pass

    # Check each JS file
    for url in all_urls[:20]:
        try:
            r = requests.get(url, headers=HDR, timeout=8, verify=False)
            content = r.text[:50000]  # First 50KB
            for lib_name, lib_info in KNOWN_VULN_LIBS.items():
                match = re.search(lib_info["pattern"], content, re.I)
                if match:
                    version = match.group(1)
                    key = f"{lib_name}-{version}"
                    if key not in checked:
                        checked.add(key)
                        for ver_prefix, vuln_desc in lib_info["vulns"].items():
                            if version.startswith(ver_prefix):
                                findings.append({
                                    "type": "vuln_library",
                                    "severity": "HIGH",
                                    "library": lib_name,
                                    "version": version,
                                    "desc": f"{lib_name} {version}: {vuln_desc}",
                                    "source": url,
                                })
        except Exception:
            pass

    return findings


def _check_manifests(base_url):
    """Check for exposed package manifests."""
    findings = []

    def _check(path):
        try:
            r = requests.get(f"{base_url}{path}", headers=HDR, timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 20:
                if "404" not in r.text[:200].lower() and "not found" not in r.text[:200].lower():
                    # Verify it looks like a real manifest
                    if any(k in r.text[:500] for k in [
                        '"name"', '"version"', '"dependencies"', "require",
                        "gem ", "source", "dependencies:", "module", "package",
                    ]):
                        return {
                            "path": path,
                            "size": len(r.text),
                            "preview": r.text[:300],
                        }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_check, p): p for p in MANIFEST_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append({
                    "type": "exposed_manifest",
                    "severity": "MEDIUM",
                    "path": result["path"],
                    "size": result["size"],
                    "preview": result["preview"],
                    "desc": f"Package manifest exposed: {result['path']} ({result['size']} bytes)",
                })

    return findings


def _analyze_csp_for_supply_chain(base_url):
    """Check CSP for third-party domains that could be hijacked."""
    findings = []
    try:
        r = requests.get(base_url, headers=HDR, timeout=10, verify=False)
        csp = ""
        for h in r.headers:
            if h.lower() == "content-security-policy":
                csp = r.headers[h]
                break

        if csp:
            # Extract allowed domains
            domains = re.findall(r'https?://([^\s;,\'\"]+)', csp)
            wildcards = re.findall(r'\*\.([^\s;,\'\"]+)', csp)

            for wc in wildcards:
                findings.append({
                    "type": "csp_wildcard",
                    "severity": "MEDIUM",
                    "domain": f"*.{wc}",
                    "desc": f"CSP allows wildcard *.{wc} — any subdomain can serve scripts",
                })

            # Check for CDN domains that allow user uploads
            risky_cdns = ["cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                         "raw.githubusercontent.com", "gist.github.com",
                         "pastebin.com", "hastebin.com"]
            for cdn in risky_cdns:
                if cdn in csp:
                    findings.append({
                        "type": "csp_risky_cdn",
                        "severity": "HIGH",
                        "domain": cdn,
                        "desc": f"CSP allows {cdn} — attacker can host malicious JS and it will execute",
                    })
    except Exception:
        pass
    return findings


def supply_chain_scan(target, stream_callback=None):
    """
    Comprehensive supply chain and third-party security analysis.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("supplychain_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 Supply Chain Analysis: {base}")
    start = time.time()
    all_findings = []

    # Phase 1: Extract third-party resources
    _emit("🔍 Phase 1: Extracting third-party resources...")
    resources = _extract_third_party_resources(base)

    total = sum(len(v) for v in resources.values())
    _emit(f"  Scripts: {len(resources['scripts'])} | CSS: {len(resources['styles'])} | "
          f"iFrames: {len(resources['iframes'])} | Fonts: {len(resources['fonts'])}")

    # Unique third-party domains
    all_domains = set()
    for rtype in resources.values():
        for r in rtype:
            all_domains.add(r.get("domain", ""))
    all_domains.discard("")
    _emit(f"  Third-party domains: {len(all_domains)}")

    # Phase 2: SRI checks
    _emit("🔍 Phase 2: Checking Subresource Integrity...")
    sri_findings = _check_sri(resources)
    all_findings.extend(sri_findings)
    no_sri = len([f for f in sri_findings if f["type"] == "missing_sri"])
    if no_sri:
        _emit(f"  ⚠️ {no_sri} scripts loaded WITHOUT SRI")

    # Phase 3: Vulnerable libraries
    _emit("🔍 Phase 3: Checking for vulnerable JS libraries...")
    vuln_findings = _check_vuln_libraries(base, resources)
    all_findings.extend(vuln_findings)
    for vf in vuln_findings:
        _emit(f"  🔴 {vf['desc']}")

    # Phase 4: Exposed manifests
    _emit("🔍 Phase 4: Checking for exposed package manifests...")
    manifest_findings = _check_manifests(base)
    all_findings.extend(manifest_findings)
    for mf in manifest_findings:
        _emit(f"  🟡 {mf['desc']}")

    # Phase 5: CSP supply chain risks
    _emit("🔍 Phase 5: Analyzing CSP for supply chain risks...")
    csp_findings = _analyze_csp_for_supply_chain(base)
    all_findings.extend(csp_findings)
    for cf in csp_findings:
        _emit(f"  {'🔴' if cf['severity'] == 'HIGH' else '🟡'} {cf['desc']}")

    elapsed = time.time() - start

    # Format output
    lines = [
        f"SUPPLY CHAIN ANALYSIS for {base}",
        f"{'='*60}",
        f"Third-party resources: {total} from {len(all_domains)} domains",
        f"Findings: {len(all_findings)} | Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if all_domains:
        lines.append(f"🌐 THIRD-PARTY DOMAINS ({len(all_domains)})")
        lines.append("-" * 40)
        for d in sorted(all_domains):
            script_count = len([s for s in resources["scripts"] if s["domain"] == d])
            sri_count = len([s for s in resources["scripts"] if s["domain"] == d and s["sri"]])
            if script_count:
                sri_status = f"SRI: {sri_count}/{script_count}" if script_count else ""
                lines.append(f"  📦 {d} ({script_count} scripts, {sri_status})")
            else:
                lines.append(f"  📦 {d}")
        lines.append("")

    for sev in ["HIGH", "MEDIUM", "LOW"]:
        group = [f for f in all_findings if f["severity"] == sev]
        if group:
            icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}[sev]
            lines.append(f"{icon} {sev} ({len(group)})")
            lines.append("-" * 40)
            for f in group:
                lines.append(f"  [{f['type']}] {f['desc']}")
                if f.get("source") and f["source"] != "inline":
                    lines.append(f"    Source: {f['source']}")
                if f.get("preview"):
                    lines.append(f"    Preview: {f['preview'][:150]}...")
            lines.append("")

    if not all_findings:
        lines.append("No supply chain vulnerabilities found.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "supply_chain_scan",
        "description": "Analyze third-party supply chain risks. Extracts all third-party JS/CSS/fonts/iframes, checks Subresource Integrity (SRI), detects known vulnerable JS libraries (jQuery, Angular, Lodash, etc.), finds exposed package manifests (package.json, requirements.txt, etc.), and analyzes CSP for CDN-based script injection risks. Critical for sites loading resources from CDNs.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL for supply chain analysis"
                }
            },
            "required": ["target"]
        }
    }
}
