from __future__ import annotations

from typing import List

from tools.passive_recon_backend import (
    PassiveReconError,
    STATUS_ERROR,
    STATUS_FALLBACK,
    append_status,
    build_unavailable_message,
    extract_netlas_ports,
    is_ip_address,
    netlas_host_lookup,
    netlas_search_domains,
    netlas_search_responses,
    normalize_target,
    resolve_to_ip,
    shodan_dns_json,
    shodan_host_json,
    shodan_search_json,
)


def _format_host_base(lines: List[str], data: dict):
    host_type = str(data.get("type", "") or "").strip()
    ip = str(data.get("ip", "") or "").strip()
    domain = str(data.get("domain", "") or "").strip()
    source = str(data.get("source", "") or "").strip()

    if ip:
        lines.append(f"IP: {ip}")
    if domain:
        lines.append(f"Domain: {domain}")
    if host_type:
        lines.append(f"Type: {host_type}")
    if source:
        lines.append(f"Source: {source}")

    organization = data.get("organization")
    if isinstance(organization, dict):
        org_name = str(organization.get("name", "") or "").strip()
    else:
        org_name = str(organization or "").strip()
    if org_name:
        lines.append(f"Organization: {org_name}")

    geo = data.get("geo", {}) if isinstance(data.get("geo"), dict) else {}
    country = str(geo.get("country", "") or "").strip()
    city = str(geo.get("city", "") or "").strip()
    if city or country:
        lines.append(f"Location: {city or 'N/A'}, {country or 'N/A'}")


def _format_netlas_host_result(target: str, data: dict) -> str:
    lines = [
        f"=== Passive Recon Host Report: {target} ===",
        "Backend: Netlas (primary)",
        "",
    ]
    _format_host_base(lines, data)

    ports = extract_netlas_ports(data)
    lines.append(f"Open Ports: {ports}")

    software = data.get("software", [])
    if isinstance(software, list) and software:
        lines.append("")
        lines.append("Software/Service Signals:")
        for item in software[:12]:
            if not isinstance(item, dict):
                continue
            uri = str(item.get("uri", "") or "").strip()
            tags = item.get("tag", [])
            names = []
            if isinstance(tags, list):
                for t in tags:
                    if isinstance(t, dict):
                        name = str(t.get("name", "") or "").strip()
                        if name:
                            names.append(name)
            tag_text = ", ".join(sorted(set(names))) if names else "unknown"
            line = f"- {tag_text}"
            if uri:
                line += f" ({uri})"
            lines.append(line)

    ioc = data.get("ioc")
    if ioc:
        lines.append("")
        lines.append(f"IOC signals: {ioc}")

    related_domains = data.get("domains") or data.get("related_domains")
    if isinstance(related_domains, list) and related_domains:
        lines.append("")
        lines.append("Related domains:")
        for d in related_domains[:12]:
            lines.append(f"- {d}")

    return append_status(lines, "OK")


def _format_netlas_ports_result(target: str, data: dict) -> str:
    ports = extract_netlas_ports(data)
    lines = [
        f"=== Passive Recon Ports: {target} ===",
        "Backend: Netlas (primary)",
        f"Open ports: {', '.join(str(p) for p in ports) if ports else 'None observed'}",
    ]
    return append_status(lines, "OK")


def _format_netlas_search_result(query: str, normalized_query: str, items: list[dict], max_results: int) -> str:
    lines = [
        f"=== Passive Recon Search ===",
        "Backend: Netlas (primary)",
        f"Original query: {query}",
        f"Netlas query: {normalized_query}",
        f"Results shown: {min(len(items), max_results)}",
        "",
    ]

    stream_urls = []
    for idx, item in enumerate(items[:max_results], start=1):
        data = item.get("data", {}) if isinstance(item, dict) else {}
        ip = str(data.get("ip", "") or "").strip()
        host = str(data.get("host", "") or "").strip()
        port = data.get("port", "")
        protocol = str(data.get("protocol", "") or "").strip()
        geo = data.get("geo", {}) if isinstance(data.get("geo"), dict) else {}
        city = str(geo.get("city", "") or "").strip()
        country = str(geo.get("country", "") or "").strip()
        http = data.get("http", {}) if isinstance(data.get("http"), dict) else {}
        title = str(http.get("title", "") or "").strip()
        status_code = http.get("status_code", "")

        lines.append(f"--- Result #{idx} ---")
        lines.append(f"IP: {ip or 'N/A'}")
        lines.append(f"Host: {host or 'N/A'}")
        lines.append(f"Port: {port or 'N/A'}")
        lines.append(f"Protocol: {protocol or 'N/A'}")
        if title:
            lines.append(f"Title: {title}")
        if status_code != "":
            lines.append(f"HTTP status: {status_code}")
        if city or country:
            lines.append(f"Location: {city or 'N/A'}, {country or 'N/A'}")
        lines.append("")

        try:
            port_num = int(port)
        except Exception:
            port_num = 0
        if port_num == 554 and ip:
            stream_urls.append(f"rtsp://{ip}:554")
        elif port_num in {80, 443, 8080, 8081} and ip:
            scheme = "https" if port_num == 443 else "http"
            stream_urls.append(f"{scheme}://{ip}:{port_num}")

    if stream_urls:
        lines.append("--- Potential Viewable Streams ---")
        for s in stream_urls[:20]:
            lines.append(f"  {s}")

    return append_status(lines, "OK")


def _format_netlas_dns_result(target: str, resolved_ip: str, domain_items: list[dict]) -> str:
    lines = [
        "=== Passive Recon DNS Resolution ===",
        "Backend: Netlas (primary)",
        f"Target: {target}",
        f"Local DNS resolve: {resolved_ip or 'unresolved'}",
    ]
    if domain_items:
        lines.append("")
        lines.append("Domain enrichment (Netlas domains index):")
        for item in domain_items[:30]:
            data = item.get("data", {}) if isinstance(item, dict) else {}
            dom = str(data.get("domain", "") or "").strip()
            zone = str(data.get("zone", "") or "").strip()
            ts = str(data.get("@timestamp", "") or "").strip()
            if dom:
                extra = []
                if zone:
                    extra.append(f"zone={zone}")
                if ts:
                    extra.append(f"seen={ts}")
                suffix = f" ({', '.join(extra)})" if extra else ""
                lines.append(f"- {dom}{suffix}")
    return append_status(lines, "OK")


def _format_shodan_host_result(target: str, data: dict) -> str:
    ip = str(data.get("ip_str", "") or resolve_to_ip(target) or "").strip()
    lines = [
        f"=== Passive Recon Host Report: {target} ===",
        "Backend: Netlas (primary)",
        "Backend fallback: Shodan",
        "",
        f"IP: {ip or 'N/A'}",
        f"Organization: {data.get('org', 'N/A')}",
        f"ISP: {data.get('isp', 'N/A')}",
        f"OS: {data.get('os', 'N/A')}",
        f"Location: {data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}",
    ]
    ports = data.get("ports", []) if isinstance(data.get("ports"), list) else []
    lines.append(f"Open Ports: {sorted(set(int(p) for p in ports if str(p).isdigit())) if ports else []}")
    hostnames = data.get("hostnames", [])
    if isinstance(hostnames, list) and hostnames:
        lines.append("Hostnames: " + ", ".join(str(h) for h in hostnames[:12]))
    return append_status(lines, STATUS_FALLBACK, code=STATUS_FALLBACK)


def _format_shodan_search_result(query: str, data: dict, max_results: int) -> str:
    matches = data.get("matches", []) if isinstance(data.get("matches"), list) else []
    total = data.get("total", 0)
    lines = [
        "=== Passive Recon Search ===",
        "Backend: Netlas (primary)",
        "Backend fallback: Shodan",
        f"Original query: {query}",
        f"Total results: {total}",
        f"Results shown: {min(len(matches), max_results)}",
        "",
    ]
    for idx, item in enumerate(matches[:max_results], start=1):
        ip = item.get("ip_str", "N/A")
        port = item.get("port", "N/A")
        product = item.get("product", "N/A")
        location = item.get("location", {}) if isinstance(item.get("location"), dict) else {}
        city = location.get("city", "N/A")
        country = location.get("country_name", "N/A")
        lines.append(f"--- Result #{idx} ---")
        lines.append(f"IP: {ip}")
        lines.append(f"Port: {port}")
        lines.append(f"Product: {product}")
        lines.append(f"Location: {city}, {country}")
        lines.append("")
    return append_status(lines, STATUS_FALLBACK, code=STATUS_FALLBACK)


def _format_shodan_dns_result(target: str, data: dict) -> str:
    lines = [
        "=== Passive Recon DNS Resolution ===",
        "Backend: Netlas (primary)",
        "Backend fallback: Shodan",
        f"Target: {target}",
    ]
    for host, ip in (data or {}).items():
        lines.append(f"{host} -> {ip}")
    return append_status(lines, STATUS_FALLBACK, code=STATUS_FALLBACK)


def _error_with_status(message: str, code: str = "NETLAS_REQUEST_FAILED") -> str:
    return append_status([f"ERROR: {message}"], STATUS_ERROR, code=code)


def _try_netlas_host_lookup(target: str) -> dict:
    normalized = normalize_target(target)
    if not normalized:
        raise PassiveReconError("NETLAS_REQUEST_FAILED", "Target normalization failed.", False)
    try:
        return netlas_host_lookup(normalized)
    except PassiveReconError as first_exc:
        if first_exc.fallback_allowed:
            raise
        if not is_ip_address(normalized):
            ip = resolve_to_ip(normalized)
            if ip and ip != normalized:
                return netlas_host_lookup(ip)
        raise


def _fallback_or_unavailable(
    netlas_error: PassiveReconError,
    target: str,
    query_type: str,
    max_results: int,
) -> str:
    unavailable_code = (
        netlas_error.code
        if netlas_error.code in {"NETLAS_AUTH_OR_PLAN_DENIED", "NETLAS_RATE_LIMITED"}
        else "PASSIVE_RECON_UNAVAILABLE"
    )
    if not netlas_error.fallback_allowed:
        if netlas_error.code in {"NETLAS_KEY_MISSING", "NETLAS_AUTH_OR_PLAN_DENIED", "NETLAS_RATE_LIMITED"}:
            return build_unavailable_message(
                code=netlas_error.code,
                reason=netlas_error.message,
                immediate_action="Set NETLAS_API_KEY with a plan/key that allows passive recon queries.",
            )
        return _error_with_status(netlas_error.message, code=netlas_error.code)

    try:
        if query_type == "host":
            data = shodan_host_json(target)
            return _format_shodan_host_result(target, data)
        if query_type == "ports":
            data = shodan_host_json(target)
            return _format_shodan_host_result(target, data)
        if query_type == "search":
            data = shodan_search_json(target)
            return _format_shodan_search_result(target, data, max_results=max_results)
        if query_type == "dns":
            normalized = normalize_target(target)
            data = shodan_dns_json(normalized)
            return _format_shodan_dns_result(target, data)
    except PassiveReconError as shodan_err:
        return build_unavailable_message(
            code=unavailable_code,
            reason=(
                f"Netlas failure ({netlas_error.code}: {netlas_error.message}); "
                f"Shodan fallback failed ({shodan_err.code}: {shodan_err.message})."
            ),
            immediate_action="Provide a valid NETLAS_API_KEY or SHODAN_API_KEY with sufficient access.",
        )
    except Exception as shodan_exc:
        return build_unavailable_message(
            code=unavailable_code,
            reason=(
                f"Netlas failure ({netlas_error.code}: {netlas_error.message}); "
                f"Shodan fallback request failed ({shodan_exc})."
            ),
            immediate_action="Retry after verifying API credentials and network access.",
        )
    return build_unavailable_message(
        code=unavailable_code,
        reason=f"Netlas failure ({netlas_error.code}: {netlas_error.message}).",
        immediate_action="Retry with valid passive recon credentials.",
    )


def shodan_lookup(target: str, query_type: str = "host", max_results: int = 20) -> str:
    qtype = str(query_type or "host").strip().lower()
    result_cap = max(1, min(int(max_results or 20), 100))

    if qtype not in {"host", "search", "dns", "ports"}:
        return _error_with_status(
            f"Unknown query_type '{query_type}'. Use: host, search, dns, ports",
            code="INVALID_QUERY_TYPE",
        )

    if qtype in {"host", "ports"}:
        try:
            data = _try_netlas_host_lookup(target)
            if qtype == "ports":
                return _format_netlas_ports_result(target, data)
            return _format_netlas_host_result(target, data)
        except PassiveReconError as netlas_err:
            return _fallback_or_unavailable(netlas_err, target, qtype, result_cap)
        except Exception as exc:
            return _error_with_status(f"Netlas host lookup failed: {exc}", code="NETLAS_REQUEST_FAILED")

    if qtype == "dns":
        normalized = normalize_target(target)
        if not normalized:
            return _error_with_status("Target is required for dns query type.", code="NETLAS_REQUEST_FAILED")
        resolved_ip = resolve_to_ip(normalized)
        domain_query = f"domain:*.{normalized}" if not is_ip_address(normalized) else ""
        try:
            domain_items = netlas_search_domains(domain_query, max_results=30) if domain_query else []
            return _format_netlas_dns_result(normalized, resolved_ip, domain_items)
        except PassiveReconError as netlas_err:
            return _fallback_or_unavailable(netlas_err, normalized, "dns", result_cap)
        except Exception as exc:
            return _error_with_status(f"Netlas DNS enrichment failed: {exc}", code="NETLAS_REQUEST_FAILED")

    try:
        items, normalized_query = netlas_search_responses(target, max_results=result_cap)
        return _format_netlas_search_result(target, normalized_query, items, result_cap)
    except PassiveReconError as netlas_err:
        return _fallback_or_unavailable(netlas_err, target, "search", result_cap)
    except Exception as exc:
        return _error_with_status(f"Netlas search failed: {exc}", code="NETLAS_REQUEST_FAILED")


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "shodan_lookup",
        "description": (
            "Passive reconnaissance lookup (Netlas-first) for ports, services, software, and DNS/search enrichment. "
            "Preserves legacy shodan_lookup contract but uses NETLAS_API_KEY as primary backend. "
            "Shodan is used automatically only when Netlas returns auth/quota/plan-limit failures."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, domain name, or passive-recon search query",
                },
                "query_type": {
                    "type": "string",
                    "enum": ["host", "search", "dns", "ports"],
                    "description": "Lookup mode: host, search, dns, or ports",
                    "default": "host",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results for search mode. Default: 20",
                    "default": 20,
                },
            },
            "required": ["target"],
        },
    },
}
