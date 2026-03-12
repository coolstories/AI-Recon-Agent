"""
Shared web target reachability resolver with safe URL fallbacks.
"""

from __future__ import annotations

import copy
import ipaddress
import socket
import time
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}
DEFAULT_TIMEOUT: Tuple[int, int] = (3, 6)  # (connect, read)
DEFAULT_CACHE_TTL_SECONDS = 300

_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCK = Lock()


def _is_domain_host(host: str) -> bool:
    if not host:
        return False
    host = host.strip().strip(".").lower()
    if not host or host == "localhost":
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    if "." not in host:
        return False
    labels = host.split(".")
    for label in labels:
        if not label:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def _format_host_for_netloc(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return "[%s]" % host
    return host


def _build_url(
    scheme: str,
    host: str,
    port: Optional[int],
    path: str,
    query: str,
    username: str = "",
    password: str = "",
) -> str:
    auth = ""
    if username:
        auth = username
        if password:
            auth += ":" + password
        auth += "@"
    host_for_netloc = _format_host_for_netloc(host)
    netloc = auth + host_for_netloc + ((":%d" % port) if port else "")
    return urlunparse((scheme, netloc, path or "", "", query or "", ""))


def _normalize_target_url(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return "https://"

    parsed = urlparse(raw)
    if not parsed.scheme:
        parsed = urlparse("https://" + raw)

    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        scheme = "https"

    host = (parsed.hostname or "").strip().strip(".").lower()
    if not host:
        return raw

    port = parsed.port
    if port == 80 and scheme == "http":
        port = None
    elif port == 443 and scheme == "https":
        port = None

    username = parsed.username or ""
    password = parsed.password or ""
    path = parsed.path or ""
    query = parsed.query or ""
    return _build_url(scheme, host, port, path, query, username=username, password=password)


def _generate_candidate_urls(normalized_url: str) -> List[str]:
    parsed = urlparse(normalized_url)
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    host = (parsed.hostname or "").lower().strip(".")
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query or ""
    username = parsed.username or ""
    password = parsed.password or ""

    if not host:
        return [normalized_url]

    candidates: List[str] = []

    def _add(url: str) -> None:
        if url not in candidates:
            candidates.append(url)

    original = _build_url(scheme, host, port, path, query, username=username, password=password)
    _add(original)

    has_non_default_port = False
    if port is not None:
        if scheme == "https":
            has_non_default_port = port != 443
        elif scheme == "http":
            has_non_default_port = port != 80
        else:
            has_non_default_port = True

    can_try_www = _is_domain_host(host) and not host.startswith("www.") and not has_non_default_port
    www_host = "www.%s" % host if can_try_www else ""

    if can_try_www:
        _add(_build_url(scheme, www_host, port, path, query, username=username, password=password))

    swap_scheme = "http" if scheme == "https" else "https"
    _add(_build_url(swap_scheme, host, port, path, query, username=username, password=password))

    if can_try_www:
        _add(_build_url(swap_scheme, www_host, port, path, query, username=username, password=password))

    return candidates


def _short_error(exc: Exception) -> str:
    msg = str(exc).strip().replace("\n", " ")
    if len(msg) > 140:
        msg = msg[:137] + "..."
    return "%s: %s" % (exc.__class__.__name__, msg)


def _probe_candidate(url: str, headers: Dict[str, str]) -> Tuple[bool, Dict[str, str], Optional[str]]:
    details = {"url": url, "head": "not_attempted", "get": "not_attempted"}

    for method in ("HEAD", "GET"):
        key = method.lower()
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            details[key] = str(response.status_code)
            return True, details, response.url
        except Exception as exc:
            details[key] = _short_error(exc)

    return False, details, None


def _resolve_dns(host: str) -> Dict[str, Any]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({entry[4][0] for entry in infos if entry and entry[4]})
        if ips:
            return {"status": "ok", "values": ips[:8]}
        return {"status": "empty", "values": []}
    except Exception as exc:
        return {"status": "error", "error": _short_error(exc)}


def _tcp_check(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except socket.timeout:
        return "timeout"
    except Exception as exc:
        msg = str(exc).strip()
        if "refused" in msg.lower():
            return "refused"
        if "unreachable" in msg.lower():
            return "unreachable"
        return exc.__class__.__name__


def _build_recommendation(dns_results: Dict[str, Dict[str, Any]], tcp_results: Dict[str, Dict[str, str]]) -> str:
    if dns_results and all(v.get("status") != "ok" for v in dns_results.values()):
        return "DNS did not resolve from this runtime. Verify the hostname and DNS propagation."

    http_only_hosts = [
        host
        for host, ports in tcp_results.items()
        if ports.get("80") == "open" and ports.get("443") != "open"
    ]
    if http_only_hosts:
        return "HTTPS may be unavailable while HTTP is reachable. Retry with http:// and verify port 443 listener."

    fully_blocked_hosts = [
        host
        for host, ports in tcp_results.items()
        if ports.get("80") != "open" and ports.get("443") != "open"
    ]
    if tcp_results and len(fully_blocked_hosts) == len(tcp_results):
        return (
            "Both 80/443 appear blocked or unreachable from this runtime. "
            "Verify firewall allowlists, WAF/CDN rules, or scan vantage point."
        )

    return "Target remained unreachable across https/http + optional www variants. Retry after network validation."


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if not cached:
            return None
        if now - cached.get("cached_at", 0) > DEFAULT_CACHE_TTL_SECONDS:
            _CACHE.pop(key, None)
            return None
        result = copy.deepcopy(cached["result"])
        result["from_cache"] = True
        return result


def _cache_put(key: str, result: Dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _CACHE[key] = {"cached_at": time.time(), "result": copy.deepcopy(result)}


def resolve_web_target(target: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Resolve and probe safe URL variants for a web target.
    Returns a dict with:
      ok, normalized_url, selected_url, used_fallback, attempts, dns, tcp, recommendation, from_cache
    """
    normalized_url = _normalize_target_url(target)
    cached = _cache_get(normalized_url)
    if cached is not None:
        return cached

    probe_headers = headers or DEFAULT_HEADERS
    candidates = _generate_candidate_urls(normalized_url)
    attempts: List[Dict[str, str]] = []

    for idx, candidate in enumerate(candidates):
        reachable, attempt_details, resolved_url = _probe_candidate(candidate, probe_headers)
        attempts.append(attempt_details)
        if reachable:
            selected = _normalize_target_url(resolved_url or candidate)
            result = {
                "ok": True,
                "original_target": (target or "").strip(),
                "normalized_url": normalized_url,
                "selected_url": selected.rstrip("/"),
                "used_fallback": idx > 0,
                "attempts": attempts,
                "attempted_urls": candidates,
                "dns": {},
                "tcp": {},
                "recommendation": "",
                "from_cache": False,
            }
            _cache_put(normalized_url, result)
            return copy.deepcopy(result)

    hosts: List[str] = []
    for url in candidates:
        host = (urlparse(url).hostname or "").strip().strip(".").lower()
        if host and host not in hosts:
            hosts.append(host)

    dns_results: Dict[str, Dict[str, Any]] = {}
    tcp_results: Dict[str, Dict[str, str]] = {}
    for host in hosts:
        dns_results[host] = _resolve_dns(host)
        tcp_results[host] = {"80": _tcp_check(host, 80), "443": _tcp_check(host, 443)}

    recommendation = _build_recommendation(dns_results, tcp_results)
    result = {
        "ok": False,
        "original_target": (target or "").strip(),
        "normalized_url": normalized_url,
        "selected_url": None,
        "used_fallback": False,
        "attempts": attempts,
        "attempted_urls": candidates,
        "dns": dns_results,
        "tcp": tcp_results,
        "recommendation": recommendation,
        "from_cache": False,
    }
    _cache_put(normalized_url, result)
    return copy.deepcopy(result)


def format_fallback_notice(resolution: Dict[str, Any]) -> str:
    if not resolution or not resolution.get("used_fallback"):
        return ""
    original = resolution.get("normalized_url", "")
    selected = resolution.get("selected_url", "")
    if not original or not selected or original == selected:
        return ""
    return "Target fallback applied: %s -> %s" % (original, selected)


def format_unreachable_error(original_target: str, resolution: Dict[str, Any]) -> str:
    target_label = (original_target or "").strip() or resolution.get("normalized_url", "<target>")
    lines = ["ERROR: Cannot reach %s" % target_label, "Tried:"]

    for attempt in resolution.get("attempts", []):
        lines.append(
            " - %s (HEAD: %s; GET: %s)"
            % (
                attempt.get("url", "unknown"),
                attempt.get("head", "n/a"),
                attempt.get("get", "n/a"),
            )
        )
    if not resolution.get("attempts"):
        lines.append(" - No URL candidates were generated")

    lines.append("DNS:")
    dns = resolution.get("dns", {})
    if dns:
        for host, dns_data in dns.items():
            status = dns_data.get("status")
            if status == "ok":
                lines.append(" - %s: %s" % (host, ", ".join(dns_data.get("values", []) or ["resolved"])))
            elif status == "empty":
                lines.append(" - %s: resolved but no addresses returned" % host)
            else:
                lines.append(" - %s: %s" % (host, dns_data.get("error", "resolution failed")))
    else:
        lines.append(" - No DNS diagnostics")

    lines.append("TCP 80/443:")
    tcp = resolution.get("tcp", {})
    if tcp:
        for host, ports in tcp.items():
            lines.append(
                " - %s: 80=%s, 443=%s"
                % (host, ports.get("80", "unknown"), ports.get("443", "unknown"))
            )
    else:
        lines.append(" - No TCP diagnostics")

    lines.append("Recommendation: %s" % resolution.get("recommendation", "Verify target availability and retry."))
    return "\n".join(lines)
