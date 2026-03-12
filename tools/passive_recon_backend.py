from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import quote

import requests


NETLAS_BASE = "https://app.netlas.io/api"
SHODAN_BASE = "https://api.shodan.io"
DEFAULT_TIMEOUT = 20
NETLAS_PAGE_SIZE = 20

STATUS_OK = "OK"
STATUS_FALLBACK = "NETLAS_FALLBACK_TO_SHODAN"
STATUS_UNAVAILABLE = "PASSIVE_RECON_UNAVAILABLE"
STATUS_ERROR = "ERROR"


@dataclass
class PassiveReconError(Exception):
    code: str
    message: str
    fallback_allowed: bool = False

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def get_netlas_key() -> str:
    return (os.getenv("NETLAS_API_KEY", "") or "").strip()


def get_shodan_key() -> str:
    return (os.getenv("SHODAN_API_KEY", "") or "").strip()


def normalize_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0].split(":")[0]
    return raw.strip().lower()


def is_ip_address(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    try:
        socket.inet_aton(raw)
        return True
    except Exception:
        return False


def resolve_to_ip(target: str) -> str:
    host = normalize_target(target)
    if not host:
        return ""
    if is_ip_address(host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def append_status(lines: List[str], status: str, code: str = "") -> str:
    if code:
        lines.append(f"PASSIVE_RECON_CODE: {code}")
    lines.append(f"PASSIVE_RECON_STATUS: {status}")
    return "\n".join(lines)


def build_unavailable_message(code: str, reason: str, immediate_action: str) -> str:
    lines = [
        f"COVERAGE DOWNGRADE: passive recon unavailable ({code}).",
        f"Reason: {reason}",
        f"Immediate next action: {immediate_action}",
    ]
    return append_status(lines, STATUS_UNAVAILABLE, code=code)


def classify_passive_recon_result(result_text: str) -> dict:
    text = str(result_text or "")
    status_match = re.search(r"PASSIVE_RECON_STATUS:\s*([A-Z0-9_]+)", text)
    code_match = re.search(r"PASSIVE_RECON_CODE:\s*([A-Z0-9_]+)", text)
    status = status_match.group(1) if status_match else ""
    code = code_match.group(1) if code_match else ""

    if not status and "COVERAGE DOWNGRADE:" in text:
        status = STATUS_UNAVAILABLE
    if not status:
        status = STATUS_OK

    first_line = ""
    for line in text.splitlines():
        if line.strip():
            first_line = line.strip()
            break

    fallback_used = status == STATUS_FALLBACK or code == STATUS_FALLBACK
    degraded = status in {STATUS_UNAVAILABLE} or fallback_used
    if code in {"NETLAS_KEY_MISSING", "NETLAS_AUTH_OR_PLAN_DENIED", "NETLAS_RATE_LIMITED", "PASSIVE_RECON_UNAVAILABLE"}:
        degraded = True

    return {
        "status": status,
        "code": code,
        "fallback_used": fallback_used,
        "degraded": degraded,
        "message": first_line or "Passive recon status updated.",
    }


def _netlas_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {get_netlas_key()}",
        "Accept": "application/json",
        "User-Agent": "AIReconAgent-PassiveRecon/1.0",
    }


def _classify_netlas_failure(status_code: int, body_text: str) -> Tuple[str, str, bool]:
    text = (body_text or "").lower()
    if status_code == 429 or ("rate" in text and "limit" in text):
        return ("NETLAS_RATE_LIMITED", "Netlas API rate limit reached.", True)
    if status_code in {401, 403}:
        return ("NETLAS_AUTH_OR_PLAN_DENIED", "Netlas denied access (auth/plan limitation).", True)
    if any(k in text for k in ("access denied", "not available for this plan", "quota", "plan")):
        return ("NETLAS_AUTH_OR_PLAN_DENIED", "Netlas denied access (auth/plan limitation).", True)
    if status_code == 404:
        return ("NETLAS_NOT_FOUND", "Requested Netlas resource was not found.", False)
    return ("NETLAS_REQUEST_FAILED", f"Netlas request failed with HTTP {status_code}.", False)


def netlas_get_json(path: str, params: dict | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    key = get_netlas_key()
    if not key:
        raise PassiveReconError(
            code="NETLAS_KEY_MISSING",
            message="NETLAS_API_KEY is not configured.",
            fallback_allowed=False,
        )

    url = f"{NETLAS_BASE}{path}"
    resp = requests.get(url, headers=_netlas_headers(), params=params or {}, timeout=timeout)
    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception as exc:
            raise PassiveReconError(
                code="NETLAS_REQUEST_FAILED",
                message=f"Netlas returned non-JSON response: {exc}",
                fallback_allowed=False,
            ) from exc

    code, reason, fallback_allowed = _classify_netlas_failure(resp.status_code, resp.text[:500])
    raise PassiveReconError(code=code, message=reason, fallback_allowed=fallback_allowed)


def netlas_host_lookup(target: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    normalized = normalize_target(target)
    if not normalized:
        raise PassiveReconError(
            code="NETLAS_REQUEST_FAILED",
            message="Target host/IP normalization failed.",
            fallback_allowed=False,
        )
    return netlas_get_json(f"/host/{quote(normalized, safe='')}/", timeout=timeout)


def adapt_shodan_query_to_netlas(query: str) -> str:
    q = str(query or "").strip()
    if not q:
        return q

    transformed = q
    transformed = re.sub(r"\bcity:([^\s]+)", r"geo.city:\1", transformed, flags=re.IGNORECASE)
    transformed = re.sub(r"\bcountry:([^\s]+)", r"geo.country:\1", transformed, flags=re.IGNORECASE)
    transformed = re.sub(r"\borg:([^\s]+)", r"organization:\1", transformed, flags=re.IGNORECASE)

    lower = transformed.lower()
    has_camera_term = ("webcam" in lower) or ("camera" in lower)
    has_title_filter = ("http.title:" in lower) or ("title:" in lower)
    if has_camera_term and not has_title_filter:
        transformed = f"({transformed}) AND (http.title:*camera* OR http.title:*webcam*)"
    return transformed


def netlas_search_responses(query: str, max_results: int = 20, timeout: int = DEFAULT_TIMEOUT) -> Tuple[List[dict], str]:
    normalized_query = adapt_shodan_query_to_netlas(query)
    limit = max(1, min(int(max_results or 20), 100))
    items: List[dict] = []
    start = 0

    while len(items) < limit:
        data = netlas_get_json("/responses/", params={"q": normalized_query, "start": start}, timeout=timeout)
        batch = data.get("items", []) if isinstance(data, dict) else []
        if not isinstance(batch, list) or not batch:
            break
        items.extend(batch)
        if len(batch) < NETLAS_PAGE_SIZE:
            break
        start += NETLAS_PAGE_SIZE

    return items[:limit], normalized_query


def netlas_search_domains(query: str, max_results: int = 20, timeout: int = DEFAULT_TIMEOUT) -> List[dict]:
    limit = max(1, min(int(max_results or 20), 100))
    items: List[dict] = []
    start = 0

    while len(items) < limit:
        data = netlas_get_json("/domains/", params={"q": query, "start": start}, timeout=timeout)
        batch = data.get("items", []) if isinstance(data, dict) else []
        if not isinstance(batch, list) or not batch:
            break
        items.extend(batch)
        if len(batch) < NETLAS_PAGE_SIZE:
            break
        start += NETLAS_PAGE_SIZE

    return items[:limit]


def extract_netlas_ports(host_data: dict) -> List[int]:
    ports = []
    raw_ports = (host_data or {}).get("ports", [])
    if isinstance(raw_ports, list):
        for item in raw_ports:
            if isinstance(item, dict):
                port = item.get("port")
            else:
                port = item
            try:
                port_num = int(port)
            except Exception:
                continue
            if 0 < port_num <= 65535:
                ports.append(port_num)
    return sorted(set(ports))


def shodan_host_json(target: str, timeout: int = 20) -> dict:
    key = get_shodan_key()
    if not key:
        raise PassiveReconError("SHODAN_KEY_MISSING", "SHODAN_API_KEY is not configured.", False)
    ip = resolve_to_ip(target)
    if not ip:
        raise PassiveReconError("SHODAN_RESOLVE_FAILED", f"Could not resolve {target} to an IP.", False)

    resp = requests.get(f"{SHODAN_BASE}/shodan/host/{ip}", params={"key": key}, timeout=timeout)
    if resp.status_code == 404:
        return {"ip_str": ip, "ports": [], "hostnames": [], "not_found": True}
    if resp.status_code == 401:
        raise PassiveReconError("SHODAN_AUTH_FAILED", "Invalid Shodan API key.", False)
    if resp.status_code in {402, 403}:
        raise PassiveReconError("SHODAN_AUTH_OR_PLAN_DENIED", "Shodan denied access (plan limitation).", False)
    resp.raise_for_status()
    return resp.json()


def shodan_search_json(query: str, timeout: int = 20) -> dict:
    key = get_shodan_key()
    if not key:
        raise PassiveReconError("SHODAN_KEY_MISSING", "SHODAN_API_KEY is not configured.", False)
    resp = requests.get(
        f"{SHODAN_BASE}/shodan/host/search",
        params={"key": key, "query": query, "page": 1},
        timeout=timeout,
    )
    if resp.status_code in {401, 402, 403}:
        raise PassiveReconError("SHODAN_AUTH_OR_PLAN_DENIED", "Shodan denied search access (plan limitation).", False)
    resp.raise_for_status()
    return resp.json()


def shodan_dns_json(hostname: str, timeout: int = 20) -> dict:
    key = get_shodan_key()
    if not key:
        raise PassiveReconError("SHODAN_KEY_MISSING", "SHODAN_API_KEY is not configured.", False)
    resp = requests.get(
        f"{SHODAN_BASE}/dns/resolve",
        params={"key": key, "hostnames": hostname},
        timeout=timeout,
    )
    if resp.status_code in {401, 402, 403}:
        raise PassiveReconError("SHODAN_AUTH_OR_PLAN_DENIED", "Shodan denied DNS resolve access.", False)
    resp.raise_for_status()
    return resp.json()
