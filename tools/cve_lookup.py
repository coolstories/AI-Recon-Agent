import requests
import re
import time


def lookup_cve(software: str, version: str) -> str:
    """Search for CVEs affecting a specific software version using NVD + web search."""
    output = []
    output.append(f"=== CVE Lookup: {software} {version} ===\n")

    # 1. Web search for version-specific CVEs (most reliable for targeted results)
    web_cves = _web_search_cves(software, version)
    if web_cves:
        output.append("--- Web Search Results (version-specific) ---")
        output.append(web_cves)
        output.append("")

    # 2. NVD API search for structured CVE data
    nvd_results = _nvd_search(software, version)
    if nvd_results:
        output.append("--- NVD Database Results ---")
        output.append(nvd_results)

    if len(output) <= 2:
        output.append(f"No CVEs found for {software} {version}.")
        output.append(f"Check manually: https://nvd.nist.gov/vuln/search/results?query={software}+{version}")

    return "\n".join(output)


def _web_search_cves(software, version):
    """Search the web for CVEs targeting a specific software version."""
    try:
        from ddgs import DDGS
        ddgs = DDGS()

        queries = [
            f"{software} {version} CVE vulnerability",
            f"{software} {version} security advisory",
            f'"{software}" "{version}" CVE exploit',
        ]

        all_results = []
        seen_urls = set()
        for q in queries:
            try:
                results = list(ddgs.text(q, max_results=8))
                for r in results:
                    url = r.get("href", "")
                    if url not in seen_urls:
                        seen_urls.add(url)
                        all_results.append(r)
            except Exception:
                continue

        if not all_results:
            return ""

        lines = []
        for i, r in enumerate(all_results[:10], 1):
            title = r.get("title", "N/A")
            url = r.get("href", "N/A")
            body = r.get("body", "")[:250]

            # Extract any CVE IDs mentioned
            cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', title + " " + body)
            cve_tag = f" [{', '.join(set(cve_ids))}]" if cve_ids else ""

            lines.append(f"{i}.{cve_tag} {title}")
            lines.append(f"   {url}")
            lines.append(f"   {body}")
            lines.append("")

        return "\n".join(lines)
    except Exception:
        return ""


def _nvd_search(software, version):
    """Query NVD API and return version-relevant CVEs."""
    search_terms = [software, software.lower()]
    vulns = []
    total = 0
    used_keyword = ""

    for keyword in search_terms:
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 25},
                headers={"User-Agent": "AIReconAgent/1.0"},
                timeout=30,
            )
            if resp.status_code == 403:
                time.sleep(6)
                continue
            if resp.status_code != 200:
                continue
            data = resp.json()
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            if vulns:
                used_keyword = keyword
                break
        except Exception:
            continue

    if not vulns:
        return ""

    # Parse and score CVEs
    parsed = []
    for v in vulns:
        cve_data = v.get("cve", {})
        cve_id = cve_data.get("id", "N/A")
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        severity = "N/A"
        for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            ml = metrics.get(mk, [])
            if ml:
                cd = ml[0].get("cvssData", {})
                cvss_score = cd.get("baseScore", 0.0)
                severity = cd.get("baseSeverity", ml[0].get("baseSeverity", "N/A"))
                break

        configs = cve_data.get("configurations", [])
        affected = _extract_affected_versions(configs)
        is_affected = _is_version_affected(version, affected) if affected else False

        published = cve_data.get("published", "")
        year = int(published[:4]) if published and len(published) >= 4 else 0

        score = 0
        if is_affected:
            score += 1000
        if year >= 2020:
            score += 100
        elif year >= 2015:
            score += 50
        score += int(cvss_score * 10)

        parsed.append({
            "cve_id": cve_id, "desc": desc, "cvss": cvss_score,
            "severity": severity, "affected": affected,
            "is_affected": is_affected,
            "published": published[:10] if published else "N/A",
            "score": score,
        })

    parsed.sort(key=lambda x: x["score"], reverse=True)

    # Only show top 10 most relevant
    lines = []
    lines.append(f"Total in NVD for '{used_keyword}': {total} CVE(s)")
    aff = sum(1 for p in parsed if p["is_affected"])
    if aff:
        lines.append(f"⚠️ {aff} CVE(s) CONFIRMED to affect version {version}")
    lines.append("")

    for i, p in enumerate(parsed[:10], 1):
        lines.append(f"  {p['cve_id']} | CVSS {p['cvss']} ({p['severity']}) | {p['published']}")
        lines.append(f"    {p['desc'][:200]}")
        if p["affected"]:
            status = "⚠️ AFFECTED" if p["is_affected"] else "ℹ️ likely not affected"
            lines.append(f"    Versions: {p['affected'][:150]} — {status}")
        lines.append(f"    https://nvd.nist.gov/vuln/detail/{p['cve_id']}")
        lines.append("")

    return "\n".join(lines)


def _fallback_cve_search(software, version):
    """Fallback: search via cvedetails or web search."""
    try:
        from ddgs import DDGS
        ddgs = DDGS()
        results = list(ddgs.text(f"{software} {version} CVE vulnerability", max_results=10))

        if not results:
            return f"No CVE information found for {software} {version}."

        output = [f"CVE search results for '{software} {version}':\n"]
        for i, r in enumerate(results[:8], 1):
            output.append(f"{i}. {r.get('title', 'N/A')}")
            output.append(f"   {r.get('href', 'N/A')}")
            output.append(f"   {r.get('body', '')[:200]}")
            output.append("")

        return "\n".join(output)
    except Exception as e:
        return f"CVE LOOKUP ERROR: {str(e)}"


def _extract_affected_versions(configs):
    """Extract affected version ranges from NVD configuration data."""
    versions = []
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    start = match.get("versionStartIncluding", "")
                    end = match.get("versionEndExcluding", match.get("versionEndIncluding", ""))
                    cpe = match.get("criteria", "")
                    if start or end:
                        versions.append(f"{start or '0'} to {end}")
                    elif cpe:
                        # Extract version from CPE string
                        parts = cpe.split(":")
                        if len(parts) >= 6 and parts[5] != "*":
                            versions.append(parts[5])
    return ", ".join(versions) if versions else ""


def _is_version_affected(version, affected_str):
    """Simple heuristic to check if a version string appears in the affected range."""
    version_clean = re.sub(r'[^0-9.]', '', version.split("p")[0].split("-")[0])
    return version_clean in affected_str or version in affected_str


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "lookup_cve",
        "description": "Search the National Vulnerability Database (NVD) for known CVEs affecting a specific software and version. Returns CVE IDs, CVSS scores, severity ratings, descriptions, affected version ranges, and verification links. Use this AFTER identifying software versions from nmap/banner grabbing to confirm if they are actually vulnerable.",
        "parameters": {
            "type": "object",
            "properties": {
                "software": {
                    "type": "string",
                    "description": "Software name, e.g. 'OpenSSH', 'Apache', 'nginx', 'WordPress', 'PHP', 'MySQL'"
                },
                "version": {
                    "type": "string",
                    "description": "Version string, e.g. '9.2p1', '2.4.49', '1.18.0', '6.9.1', '8.0.35'"
                }
            },
            "required": ["software", "version"]
        }
    }
}
