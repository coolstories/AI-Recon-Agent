import json
import sys
import os
import base64
import hmac
import threading
import uuid
import time
import re
import shutil
import ipaddress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional
import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure common local binary locations are available to subprocess-based tools.
for _bin_dir in (os.path.expanduser("~/.local/bin"), "/opt/homebrew/bin", "/usr/local/bin"):
    if os.path.isdir(_bin_dir) and _bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{_bin_dir}:{os.environ.get('PATH', '')}"

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from agent.llm import (
    chat_completion_stream,
    get_model,
    LLMStreamTimeoutError,
    LLMStreamRetriesExhaustedError,
)
from agent.prompts import SYSTEM_PROMPT
from agent.intent import build_intent_system_message, CAMERA_HINTS
from tools.terminal import run_terminal, TOOL_DEFINITION as TERMINAL_TOOL
from tools.web_request import (
    make_web_request, check_ssl_cert,
    TOOL_DEFINITION_WEB, TOOL_DEFINITION_SSL,
)
from tools.search import search_web, TOOL_DEFINITION as SEARCH_TOOL
from tools.geocode import geocode_location, TOOL_DEFINITION as GEOCODE_TOOL
from tools.overpass import query_overpass, TOOL_DEFINITION as OVERPASS_TOOL
from tools.file_io import read_file, write_file, TOOL_DEFINITION_READ, TOOL_DEFINITION_WRITE
from tools.shodan_search import (
    shodan_host_lookup, shodan_search,
    TOOL_DEFINITION_HOST as SHODAN_HOST_TOOL,
    TOOL_DEFINITION_SEARCH as SHODAN_SEARCH_TOOL,
)
from tools.public_cams import search_public_cams, TOOL_DEFINITION as PUBLIC_CAMS_TOOL
from tools.live_cams import search_live_webcams, TOOL_DEFINITION as LIVE_CAMS_TOOL
from tools.cve_lookup import lookup_cve, TOOL_DEFINITION as CVE_LOOKUP_TOOL
from tools.vuln_check import check_exposed_paths, TOOL_DEFINITION as VULN_CHECK_TOOL
from tools.ffuf_scan import run_ffuf, TOOL_DEFINITION as FFUF_TOOL
from tools.nuclei_scan import run_nuclei, TOOL_DEFINITION as NUCLEI_TOOL
from tools.shodan_recon import shodan_lookup, TOOL_DEFINITION as SHODAN_RECON_TOOL
from tools.passive_recon_backend import classify_passive_recon_result
from tools.exploit import exploit_target, TOOL_DEFINITION as EXPLOIT_TOOL
from tools.telegram import send_telegram, send_telegram_file, TOOL_DEFINITION_SEND as TELEGRAM_SEND_TOOL, TOOL_DEFINITION_FILE as TELEGRAM_FILE_TOOL
from tools.port_scanner import port_scan, TOOL_DEFINITION as PORT_SCAN_TOOL
from tools.subdomain_enum import subdomain_enumerate, TOOL_DEFINITION as SUBDOMAIN_TOOL
from tools.param_miner import param_mine, TOOL_DEFINITION as PARAM_MINE_TOOL
from tools.cors_scanner import cors_scan, TOOL_DEFINITION as CORS_TOOL
from tools.header_audit import header_audit, TOOL_DEFINITION as HEADER_AUDIT_TOOL
from tools.js_analyzer import js_analyze, TOOL_DEFINITION as JS_ANALYZER_TOOL
from tools.cms_scanner import cms_scan, TOOL_DEFINITION as CMS_SCAN_TOOL
from tools.dns_recon import dns_recon, TOOL_DEFINITION as DNS_RECON_TOOL
from tools.waf_fingerprint import waf_fingerprint, TOOL_DEFINITION as WAF_TOOL
from tools.graphql_exploit import graphql_exploit, TOOL_DEFINITION as GRAPHQL_TOOL
from tools.cloud_recon import cloud_recon, TOOL_DEFINITION as CLOUD_RECON_TOOL
from tools.api_fuzzer import api_fuzz, TOOL_DEFINITION as API_FUZZ_TOOL
from tools.cache_poisoner import cache_poison, TOOL_DEFINITION as CACHE_POISON_TOOL
from tools.http_smuggler import http_smuggle, TOOL_DEFINITION as HTTP_SMUGGLE_TOOL
from tools.oauth_tester import oauth_test, TOOL_DEFINITION as OAUTH_TOOL
from tools.race_tester import race_test, TOOL_DEFINITION as RACE_TOOL
from tools.supply_chain import supply_chain_scan, TOOL_DEFINITION as SUPPLY_CHAIN_TOOL
from tools.trufflehog_scan import run_trufflehog, TOOL_DEFINITION as TRUFFLEHOG_TOOL
from tools.gitleaks_scan import run_gitleaks, TOOL_DEFINITION as GITLEAKS_TOOL
from tools.aquatone_scan import run_aquatone, TOOL_DEFINITION as AQUATONE_TOOL
from tools.testssl_scan import run_testssl, TOOL_DEFINITION as TESTSSL_TOOL
from tools.naabu_scan import run_naabu, TOOL_DEFINITION as NAABU_TOOL
from tools.waybackurls_scan import run_waybackurls, TOOL_DEFINITION as WAYBACKURLS_TOOL
from tools.arjun_scan import run_arjun, TOOL_DEFINITION as ARJUN_TOOL
from tools.wfuzz_scan import run_wfuzz, TOOL_DEFINITION as WFUZZ_TOOL
from tools.semgrep_scan import run_semgrep, TOOL_DEFINITION as SEMGREP_TOOL
from tools.wpscan_scan import run_wpscan, TOOL_DEFINITION as WPSCAN_TOOL
from tools.final_truth import verify_bug_bounty_truth
from tools.target_reachability import resolve_web_target

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def _extract_basic_auth_password(auth_header: str) -> str:
    raw = str(auth_header or "").strip()
    if not raw or not raw.lower().startswith("basic "):
        return ""
    token = raw.split(" ", 1)[1].strip()
    if not token:
        return ""
    try:
        decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
    except Exception:
        return ""
    if ":" not in decoded:
        return ""
    _, password = decoded.split(":", 1)
    return password


def _basic_auth_unauthorized() -> Response:
    return Response(
        status_code=401,
        content="Unauthorized",
        media_type="text/plain",
        headers={"WWW-Authenticate": f'Basic realm="{ACCESS_AUTH_REALM}"'},
    )


@app.middleware("http")
async def _access_password_guard(request: Request, call_next):
    if not ACCESS_AUTH_ENABLED or not ACCESS_AUTH_PASSWORD:
        return await call_next(request)

    path = request.url.path or "/"
    if path in ACCESS_AUTH_EXEMPT_PATHS:
        return await call_next(request)

    provided_password = _extract_basic_auth_password(request.headers.get("Authorization", ""))
    if not provided_password or not hmac.compare_digest(str(provided_password), str(ACCESS_AUTH_PASSWORD)):
        return _basic_auth_unauthorized()
    return await call_next(request)


ALL_TOOLS = [
    TERMINAL_TOOL, TOOL_DEFINITION_WEB, TOOL_DEFINITION_SSL, SEARCH_TOOL,
    GEOCODE_TOOL, OVERPASS_TOOL, TOOL_DEFINITION_READ, TOOL_DEFINITION_WRITE,
    SHODAN_HOST_TOOL, SHODAN_SEARCH_TOOL, PUBLIC_CAMS_TOOL, LIVE_CAMS_TOOL,
    CVE_LOOKUP_TOOL, VULN_CHECK_TOOL,
    FFUF_TOOL, NUCLEI_TOOL, SHODAN_RECON_TOOL, EXPLOIT_TOOL,
    TELEGRAM_SEND_TOOL, TELEGRAM_FILE_TOOL,
    PORT_SCAN_TOOL, SUBDOMAIN_TOOL, PARAM_MINE_TOOL, CORS_TOOL,
    HEADER_AUDIT_TOOL, JS_ANALYZER_TOOL, CMS_SCAN_TOOL, DNS_RECON_TOOL, WAF_TOOL,
    GRAPHQL_TOOL, CLOUD_RECON_TOOL, API_FUZZ_TOOL, CACHE_POISON_TOOL,
    HTTP_SMUGGLE_TOOL, OAUTH_TOOL, RACE_TOOL, SUPPLY_CHAIN_TOOL,
    TRUFFLEHOG_TOOL, GITLEAKS_TOOL, AQUATONE_TOOL, TESTSSL_TOOL, NAABU_TOOL,
    WAYBACKURLS_TOOL, ARJUN_TOOL, WFUZZ_TOOL, SEMGREP_TOOL, WPSCAN_TOOL,
]

TOOL_HANDLERS = {
    "run_terminal": lambda args: run_terminal(args["command"], args.get("timeout", 180), require_confirm=False),
    "web_request": lambda args: make_web_request(args["url"], args.get("method", "GET")),
    "check_ssl": lambda args: check_ssl_cert(args["hostname"]),
    "search_web": lambda args: search_web(args["query"], args.get("max_results", 10)),
    "geocode": lambda args: geocode_location(args["location"]),
    "overpass_query": lambda args: query_overpass(args["lat"], args["lon"], args.get("radius", 500)),
    "read_file": lambda args: read_file(args["filepath"]),
    "write_file": lambda args: write_file(args["filepath"], args["content"]),
    "shodan_host": lambda args: shodan_host_lookup(args["ip"]),
    "shodan_search": lambda args: shodan_search(args["query"], args.get("max_results", 20)),
    "search_public_cams": lambda args: search_public_cams(args["lat"], args["lon"], args.get("radius_km", 10)),
    "search_live_webcams": lambda args: search_live_webcams(args["location"], args.get("max_results", 15)),
    "lookup_cve": lambda args: lookup_cve(args["software"], args["version"]),
    "check_exposed_paths": lambda args: check_exposed_paths(args["base_url"], args.get("scan_profile", "standard")),
    "run_ffuf": lambda args: run_ffuf(args["target_url"], args.get("mode", "dir"), args.get("wordlist", "common"), args.get("extensions", ""), args.get("threads", 50), args.get("timeout", 120)),
    "run_nuclei": lambda args: run_nuclei(args["target"], args.get("templates", "auto"), args.get("severity", "critical,high,medium"), args.get("timeout", 300), args.get("rate_limit", 150)),
    "shodan_lookup": lambda args: shodan_lookup(args["target"], args.get("query_type", "host")),
    "exploit_target": lambda args: exploit_target(args["target"], args.get("exploit_type", "auto"), args.get("options", {})),
    "send_telegram": lambda args: send_telegram(args["message"], args.get("chat_id", ""), args.get("parse_mode", "Markdown")),
    "send_telegram_file": lambda args: send_telegram_file(args["file_path"], args.get("caption", "")),
    "port_scan": lambda args: port_scan(args["target"], args.get("scan_type", "top100"), args.get("custom_ports", "")),
    "subdomain_enum": lambda args: subdomain_enumerate(args["target"], args.get("mode", "passive")),
    "param_mine": lambda args: param_mine(args["target"], args.get("method", "GET")),
    "cors_scan": lambda args: cors_scan(args["target"]),
    "header_audit": lambda args: header_audit(args["target"]),
    "js_analyze": lambda args: js_analyze(args["target"]),
    "cms_scan": lambda args: cms_scan(args["target"]),
    "dns_recon": lambda args: dns_recon(args["target"]),
    "waf_fingerprint": lambda args: waf_fingerprint(args["target"]),
    "graphql_exploit": lambda args: graphql_exploit(args["target"]),
    "cloud_recon": lambda args: cloud_recon(args["target"]),
    "api_fuzz": lambda args: api_fuzz(args["target"], args.get("mode", "full")),
    "cache_poison": lambda args: cache_poison(args["target"]),
    "http_smuggle": lambda args: http_smuggle(args["target"]),
    "oauth_test": lambda args: oauth_test(args["target"]),
    "race_test": lambda args: race_test(args["target"], args.get("endpoint", ""), args.get("method", "POST"), args.get("payload"), args.get("parallel", 15)),
    "supply_chain_scan": lambda args: supply_chain_scan(args["target"]),
    "run_trufflehog": lambda args: run_trufflehog(args["path"], args.get("scan_mode", "filesystem"), args.get("timeout", 300)),
    "run_gitleaks": lambda args: run_gitleaks(args["path"], args.get("timeout", 300)),
    "run_aquatone": lambda args: run_aquatone(args["targets"], args.get("timeout", 300)),
    "run_testssl": lambda args: run_testssl(args["target"], args.get("mode", "fast"), args.get("timeout", 420)),
    "run_naabu": lambda args: run_naabu(args["target"], args.get("scan_type", "top100"), args.get("rate", 1000), args.get("timeout", 180)),
    "run_waybackurls": lambda args: run_waybackurls(args["target"], args.get("timeout", 120)),
    "run_arjun": lambda args: run_arjun(args["target_url"], args.get("method", "GET"), args.get("timeout", 240)),
    "run_wfuzz": lambda args: run_wfuzz(args["target_url"], args.get("wordlist", "common"), args.get("hide_codes", "404"), args.get("threads", 20), args.get("timeout", 180)),
    "run_semgrep": lambda args: run_semgrep(args["path"], args.get("config", "auto"), args.get("timeout", 600)),
    "run_wpscan": lambda args: run_wpscan(args["target"], args.get("scan_profile", "aggressive_enum"), args.get("timeout", 420)),
}


def _build_required_tool_args() -> dict[str, list[str]]:
    out = {}
    for tool_def in ALL_TOOLS:
        fn = (tool_def or {}).get("function", {})
        name = fn.get("name")
        if not name:
            continue
        params = fn.get("parameters", {}) or {}
        required = params.get("required", []) or []
        if isinstance(required, list):
            out[name] = [str(x) for x in required]
    return out


REQUIRED_TOOL_ARGS = _build_required_tool_args()

MAX_ITERATIONS = 50
ASK_MAX_ITERATIONS = 8
STATUS_CHECK_TIMEOUT_PAUSE_THRESHOLD = 3
WORKER_STALL_THRESHOLD_SEC = int(os.getenv("WORKER_STALL_THRESHOLD_SEC", "220") or "220")
WORKER_RECOVERY_LIMIT = int(os.getenv("WORKER_RECOVERY_LIMIT", "1") or "1")
SESSION_FLUSH_INTERVAL_SEC = float(os.getenv("SESSION_FLUSH_INTERVAL_SEC", "2") or "2")
WORKER_MONITOR_POLL_SEC = 2.0
RECOVERY_MIN_GAP_SEC = 12.0
MAX_SCOPE_PIVOT_HOSTS = 8
SEVERE_PATH_TIMEOUT_SEC = 8
PASSIVE_RECON_TOOL_NAMES = {"shodan_lookup", "shodan_host", "shodan_search"}
BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = BASE_DIR / "data"
LEGACY_DATA_DIRS = [
    DATA_DIR / "sessions",
]
DATA_DIR.mkdir(exist_ok=True)

DEEP_SCAN_ENFORCER = (
    "DEEP SCAN EXECUTION REQUIREMENT: Use broad tool coverage and do not stop at shallow findings. "
    "When target is web/internet-facing, run reconnaissance, discovery, vulnerability scanning, and exploitation verification phases. "
    "Include advanced tools where applicable: run_naabu, run_waybackurls, run_arjun, run_wfuzz, run_testssl, run_aquatone. "
    "If WordPress is detected, run run_wpscan with aggressive_enum profile to deepen plugin/theme/user and vuln intelligence coverage. "
    "For local code paths/repos, include run_trufflehog, run_gitleaks, and run_semgrep. "
    "If credentials/secrets/tokens, XSS, SQLi, SSRF, auth bypass, or other critical issues are found, report concrete evidence only from tool output "
    "(endpoint, parameter/payload, and observed response indicator/value). "
    "Safety policy: only authorized assets and non-destructive validation are allowed. "
    "Never attempt write/modify/delete actions, account takeover, defacement, persistence, or command execution aimed at changing target state. "
    "If a user asks for takeover or code-changing outcomes, refuse and reframe to read-only validation and remediation guidance. "
    "If any tool is unavailable, record its exact error and continue the deep workflow."
)

LIGHT_SCAN_ENFORCER = (
    "LIGHT SCAN EXECUTION REQUIREMENT: keep scanning quick and targeted. "
    "Favor lightweight checks and avoid long-running or aggressive brute-force phases by default. "
    "Use high-signal tools first and report only evidence-backed findings."
)

EXTRA_VERIFICATION_PROMPT = (
    "DEEP SCAN EXTRA VERIFICATION PASS (bounded): The deterministic truth verifier found zero exploit-proven "
    "high/critical findings so far. Run ONE additional targeted verification pass now with a small number of "
    "high-signal checks aimed at proving or disproving high-impact issues. Prefer reproducibility over breadth. "
    "Only execute read-only checks, and do not perform state-changing actions (write/modify/delete/takeover attempts). "
    "After that pass, produce a concise final report that separates exploit-proven findings from unverified leads."
)

# Heuristic scan-intent markers for web security scanning (used only for mode coercion).
WEB_SCAN_HINTS = (
    "scan", "security scan", "vulnerability", "audit", "pentest", "penetration test",
    "recon", "enumerate", "find vulnerabilities", "exploit", "fuzz", "nuclei", "ffuf",
    "xss", "sqli", "ssrf", "idor", "cors", "header", "subdomain", "port scan", "naabu",
    "wpscan", "wordpress",
    "deep scan", "full scan",
)

DOMAIN_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)

RISKY_HOST_KEYWORDS = ("vault", "admin", "api", "staging", "auth")

AUTHORIZED_SCOPE_NOTE = "Authorized assets only; non-destructive validation only."
VALID_VERIFICATION_POLICIES = {"strict", "balanced", "aggressive"}
DEFAULT_VERIFICATION_POLICY = str(
    os.getenv("TRUTH_VERIFICATION_POLICY", "balanced") or "balanced"
).strip().lower()
if DEFAULT_VERIFICATION_POLICY not in VALID_VERIFICATION_POLICIES:
    DEFAULT_VERIFICATION_POLICY = "balanced"

ACCESS_AUTH_PASSWORD = str(os.getenv("ACCESS_PASSWORD", "Recon103!") or "Recon103!")
ACCESS_AUTH_ENABLED = str(os.getenv("ACCESS_AUTH_ENABLED", "1") or "1").strip().lower() not in {"0", "false", "no", "off"}
ACCESS_AUTH_REALM = str(os.getenv("ACCESS_AUTH_REALM", "AI Recon Agent") or "AI Recon Agent")
ACCESS_AUTH_EXEMPT_PATHS = {"/api/health"}

DEFENSIVE_QUERY_HINTS = (
    "prevent", "mitigate", "defend", "fix", "patch", "harden", "secure",
    "remediate", "protect", "detection", "monitoring", "best practice",
)

OFFENSIVE_INTENT_HINTS = (
    "hack", "break into", "bypass", "gain access", "get access", "take over",
    "deface", "backdoor", "persist", "persistence",
    "do whatever", "whatever it takes", "change code", "modify code",
    "alter website", "website control", "admin access",
)

DESTRUCTIVE_INTENT_PATTERNS = [
    ("website/code modification objective", re.compile(
        r"\b(change|modify|edit|overwrite|inject|tamper|deface)\b.{0,40}\b(code|website|site|web\s*app|frontend|backend|production)\b",
        re.IGNORECASE,
    )),
    ("unauthorized access objective", re.compile(
        r"\b(gain|get|obtain|force|bypass)\b.{0,30}\b(admin|root|shell|write|command|account)\b.{0,30}\b(access|control)\b",
        re.IGNORECASE,
    )),
    ("unauthorized website access objective", re.compile(
        r"\b(gain|get|obtain|bypass|force)\b.{0,20}\baccess\b.{0,30}\b(website|site|app|application|server|account)\b",
        re.IGNORECASE,
    )),
    ("remote command execution objective", re.compile(
        r"\b(run|execute)\b.{0,20}\b(command|cmd|shell)\b.{0,30}\b(target|server|website|site|app)\b",
        re.IGNORECASE,
    )),
    ("takeover objective", re.compile(
        r"\b(account\s*takeover|site\s*takeover|domain\s*takeover|full\s*control|persistent\s*access)\b",
        re.IGNORECASE,
    )),
    ("destructive impact objective", re.compile(
        r"\b(delete|drop|destroy|wipe|deface|ransom)\b.{0,40}\b(database|db|files|site|application|app)\b",
        re.IGNORECASE,
    )),
]

# ---------- Session management ----------

sessions = {}  # session_id -> { status, query, events[], created_at, ... }
sessions_lock = threading.Lock()
worker_threads = {}  # session_id -> thread
worker_monitor_thread = None


def _now_iso() -> str:
    return datetime.now().isoformat()


def _parse_iso(value: str, fallback_ts: Optional[float] = None) -> float:
    if value:
        try:
            return datetime.fromisoformat(value).timestamp()
        except Exception:
            pass
    return fallback_ts if fallback_ts is not None else time.time()


def _is_terminal_event(event_type: str) -> bool:
    return event_type in {"error", "done"}


def _default_runtime_state() -> dict:
    return {
        "messages": [],
        "iteration": 0,
        "extra_verification_used": False,
        "auto_wpscan_hosts": [],
        "known_hosts": [],
        "severe_path_executed": False,
        "netlas_disabled": False,
        "passive_recon_degraded": "",
        "last_progress_at": "",
        "recovery_attempts": 0,
    }


def _normalize_auth_context(raw) -> dict:
    ctx = raw if isinstance(raw, dict) else {}
    enabled = bool(ctx.get("enabled", False))
    scope = str(ctx.get("scope", "all") or "all").strip().lower()
    if scope not in {"all", "allowlist"}:
        scope = "all"
    profile = str(ctx.get("profile", "default") or "default").strip().lower()
    profile = re.sub(r"[^a-z0-9_-]", "", profile) or "default"

    allowed_hosts = []
    seen = set()
    raw_hosts = ctx.get("allowed_hosts") or []
    if isinstance(raw_hosts, list):
        for item in raw_hosts[:80]:
            host = _normalize_web_target(str(item))
            if not host or host in seen:
                continue
            seen.add(host)
            allowed_hosts.append(host)

    return {
        "enabled": enabled,
        "scope": scope,
        "allowed_hosts": allowed_hosts,
        "profile": profile,
    }


def _normalize_verification_policy(raw) -> str:
    policy = str(raw or "").strip().lower()
    if policy in VALID_VERIFICATION_POLICIES:
        return policy
    return DEFAULT_VERIFICATION_POLICY


def _with_session_defaults(data: dict) -> dict:
    out = dict(data or {})
    out.setdefault("requested_mode", out.get("mode", "auto"))
    out.setdefault("stop_requested", False)
    out.setdefault("status_check_timeout_streak", 0)
    out.setdefault("status_check_paused", False)
    out.setdefault("worker_recovery_attempts", int(out.get("worker_recovery_attempts", 0) or 0))
    out.setdefault("worker_recovery_limit", int(out.get("worker_recovery_limit", WORKER_RECOVERY_LIMIT) or WORKER_RECOVERY_LIMIT))
    out.setdefault("recovery_state", out.get("recovery_state", "none"))
    out.setdefault("worker_token", int(out.get("worker_token", 0) or 0))
    out.setdefault("last_progress_at", out.get("created_at", _now_iso()))
    out.setdefault("last_recovery_at", "")
    out.setdefault("resolved_scope_hosts", list(out.get("resolved_scope_hosts", []) or []))
    out.setdefault("coverage_degraded", list(out.get("coverage_degraded", []) or []))
    out.setdefault("severe_path_status", out.get("severe_path_status", "none"))
    out.setdefault("verification_policy", _normalize_verification_policy(out.get("verification_policy")))
    out["auth_context"] = _normalize_auth_context(out.get("auth_context", {}))
    runtime = out.get("runtime", {}) or {}
    merged_runtime = _default_runtime_state()
    merged_runtime.update(runtime)
    if not merged_runtime.get("last_progress_at"):
        merged_runtime["last_progress_at"] = out.get("last_progress_at", "")
    out["runtime"] = merged_runtime
    out.setdefault("events", [])
    return out


def _session_snapshot(s: dict) -> dict:
    return {
        "id": s["id"],
        "query": s["query"],
        "mode": s.get("mode", "auto"),
        "requested_mode": s.get("requested_mode", s.get("mode", "auto")),
        "status": s["status"],
        "stop_requested": bool(s.get("stop_requested", False)),
        "created_at": s["created_at"],
        "finished_at": s.get("finished_at", ""),
        "events": list(s.get("events", [])),
        "status_check_timeout_streak": int(s.get("status_check_timeout_streak", 0) or 0),
        "status_check_paused": bool(s.get("status_check_paused", False)),
        "worker_recovery_attempts": int(s.get("worker_recovery_attempts", 0) or 0),
        "worker_recovery_limit": int(s.get("worker_recovery_limit", WORKER_RECOVERY_LIMIT) or WORKER_RECOVERY_LIMIT),
        "recovery_state": s.get("recovery_state", "none"),
        "last_progress_at": s.get("last_progress_at", ""),
        "last_recovery_at": s.get("last_recovery_at", ""),
        "resolved_scope_hosts": list(s.get("resolved_scope_hosts", []) or []),
        "coverage_degraded": list(s.get("coverage_degraded", []) or []),
        "severe_path_status": s.get("severe_path_status", "none"),
        "verification_policy": _normalize_verification_policy(s.get("verification_policy")),
        "auth_context": _normalize_auth_context(s.get("auth_context", {})),
        "worker_token": int(s.get("worker_token", 0) or 0),
        "runtime": dict(s.get("runtime", _default_runtime_state()) or _default_runtime_state()),
    }


def _looks_like_camera_query(text: str) -> bool:
    q = (text or "").strip().lower()
    if not q:
        return False
    if any(h in q for h in CAMERA_HINTS):
        return True
    camera_extras = (
        "traffic cam", "live feed", "stream near", "webcam near", "cctv near",
        "surveillance near", "overpass",
    )
    return any(h in q for h in camera_extras)


def _looks_like_web_scan_query(text: str) -> bool:
    q = (text or "").strip().lower()
    if not q:
        return False
    has_url = bool(re.search(r"https?://|(?:\b[a-z0-9-]+\.)+[a-z]{2,}\b", q))
    asks_scan = any(h in q for h in WEB_SCAN_HINTS)
    return has_url or asks_scan


def _coerce_execution_mode(query: str, requested_mode: str) -> str:
    req = (requested_mode or "auto").strip().lower()
    if req == "ask":
        return "ask"
    if _looks_like_camera_query(query):
        return "auto"
    if _looks_like_web_scan_query(query):
        return "deep"
    return "auto"


def _classify_query_safety(query: str) -> dict:
    text = (query or "").strip()
    q = text.lower()
    if not q:
        return {"blocked": False, "reason": "", "matches": []}

    defensive = any(h in q for h in DEFENSIVE_QUERY_HINTS)
    offensive = any(h in q for h in OFFENSIVE_INTENT_HINTS)

    matches = []
    for label, pattern in DESTRUCTIVE_INTENT_PATTERNS:
        if pattern.search(text):
            matches.append(label)

    # Defensive intent without offensive phrasing should not be blocked.
    if matches and defensive and not offensive:
        return {"blocked": False, "reason": "", "matches": []}

    if matches:
        return {
            "blocked": True,
            "reason": (
                "Request asked for takeover or state-changing compromise outcomes "
                "(code/website/account modification), which are out of scope."
            ),
            "matches": matches,
        }
    return {"blocked": False, "reason": "", "matches": []}


def _build_policy_block_report(query: str, safety: dict, mode: str = "auto") -> str:
    target = _extract_primary_target(query)
    lines = [
        "## Security Policy Enforcement Report",
        "",
        f"> {AUTHORIZED_SCOPE_NOTE}",
        "",
        "### Decision",
        "- Result: **Blocked**",
        "- Reason: "
        + str(safety.get("reason") or "Destructive or takeover-oriented objective is not allowed."),
        f"- Mode requested: **{mode}**",
        f"- Primary target parsed: **{target or 'Not detected'}**",
    ]
    indicators = safety.get("matches") or []
    if indicators:
        lines.append("- Matched safety indicators:")
        for item in indicators[:5]:
            lines.append(f"  - `{item}`")

    lines.extend([
        "",
        "### Allowed Path (Authorized, Read-Only)",
        "1. Confirm asset ownership or explicit written authorization.",
        "2. Run non-destructive verification only (read/list/enumerate proof).",
        "3. Produce evidence-backed findings with remediation and retest guidance.",
        "",
        "### Non-Destructive Scope",
        "- Allowed: header validation, endpoint reachability, auth surface checks, deterministic misconfiguration proof.",
        "- Not allowed: write/modify/delete actions, defacement, takeover attempts, persistence actions.",
        "",
        "### Original Query",
        f"- `{_clip_text(query or '', 600)}`",
    ])
    return "\n".join(lines)


def _friendly_runtime_error_message(exc: Exception) -> str:
    raw = str(exc or "")
    low = raw.lower()
    if "401" in low and "user not found" in low:
        return (
            "LLM provider authentication failed (401: User not found). "
            "Set a valid `OPENROUTER_API_KEY` in Railway environment variables and redeploy. "
            "This app is configured for OpenRouter (`https://openrouter.ai/api/v1`), so an OpenAI key will not work."
        )
    if "openrouter_api_key not set" in low:
        return (
            "Missing required environment variable `OPENROUTER_API_KEY`. "
            "Set it in Railway variables and redeploy."
        )
    return (
        "Uncaught worker exception; forcing session shutdown. "
        f"Details: {raw}"
    )


def _normalize_web_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    host = (parsed.netloc or parsed.path or "").strip().lower()
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def _registrable_domain(host: str) -> str:
    h = (host or "").strip().lower().strip(".")
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h
    except Exception:
        pass
    labels = [p for p in h.split(".") if p]
    if len(labels) <= 2:
        return h
    common_second_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(labels[-1]) == 2 and labels[-2] in common_second_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_first_party_host(host: str, root_domain: str) -> bool:
    h = (host or "").strip().lower().strip(".")
    rd = (root_domain or "").strip().lower().strip(".")
    if not h or not rd:
        return False
    return h == rd or h.endswith("." + rd)


def _extract_hosts_from_text(text: str) -> list[str]:
    out = []
    seen = set()
    for match in DOMAIN_HOST_RE.finditer(text or ""):
        host = _normalize_web_target(match.group(0))
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(host)
    return out


def _risk_rank_host(host: str) -> tuple[int, int]:
    h = (host or "").lower()
    score = 0
    for idx, kw in enumerate(RISKY_HOST_KEYWORDS):
        if kw in h:
            score += (len(RISKY_HOST_KEYWORDS) - idx)
    if h.startswith("vault.") or ".vault." in h:
        score += 8
    if h.startswith("api.") or ".api." in h:
        score += 4
    if h.startswith("www."):
        score -= 1
    return (score, -len(h))


def _env_json_headers(var_name: str) -> dict:
    raw = (os.getenv(var_name, "") or "").strip()
    if not raw:
        return {}
    try:
        val = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(val, dict):
        return {}
    out = {}
    for k, v in val.items():
        ks = str(k).strip()
        vs = str(v).strip()
        if ks and vs:
            out[ks] = vs
    return out


def _load_auth_profile_headers(profile_name: str) -> dict:
    profile = (profile_name or "default").strip().lower() or "default"
    env_prefix = f"AUTH_PROFILE_{profile.upper()}"
    headers = {}
    headers.update(_env_json_headers(f"{env_prefix}_HEADERS_JSON"))
    if not headers and profile != "default":
        headers.update(_env_json_headers("AUTH_PROFILE_DEFAULT_HEADERS_JSON"))
    if not headers:
        headers.update(_env_json_headers("AUTH_PROFILE_HEADERS_JSON"))

    bearer = (os.getenv(f"{env_prefix}_BEARER_TOKEN", "") or "").strip()
    cookie = (os.getenv(f"{env_prefix}_COOKIE", "") or "").strip()
    api_key = (os.getenv(f"{env_prefix}_X_API_KEY", "") or "").strip()

    if not bearer and profile != "default":
        bearer = (os.getenv("AUTH_PROFILE_DEFAULT_BEARER_TOKEN", "") or "").strip()
    if not cookie and profile != "default":
        cookie = (os.getenv("AUTH_PROFILE_DEFAULT_COOKIE", "") or "").strip()
    if not api_key and profile != "default":
        api_key = (os.getenv("AUTH_PROFILE_DEFAULT_X_API_KEY", "") or "").strip()

    if bearer and "Authorization" not in headers:
        headers["Authorization"] = "Bearer " + bearer
    if cookie and "Cookie" not in headers:
        headers["Cookie"] = cookie
    if api_key and "X-API-Key" not in headers:
        headers["X-API-Key"] = api_key
    return headers


def _host_allowed_by_auth_context(host: str, auth_context: dict, root_domain: str) -> bool:
    if not _is_first_party_host(host, root_domain):
        return False
    if not bool((auth_context or {}).get("enabled", False)):
        return False
    scope = str((auth_context or {}).get("scope", "all") or "all").lower()
    if scope == "all":
        return True

    allowed = (auth_context or {}).get("allowed_hosts") or []
    for allowed_host in allowed:
        ah = _normalize_web_target(str(allowed_host))
        if not ah:
            continue
        if host == ah or host.endswith("." + ah):
            return True
    return False


def _is_vault_version_in_known_vuln_range(version: str) -> bool:
    ver = (version or "").strip()
    if not ver:
        return False
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", ver)
    if not m:
        return False
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    # CVE-2025-12044 affected <= 1.20.4 in supported branches.
    return (major, minor, patch) <= (1, 20, 4)


def _is_private_or_internal_addr(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    host = raw
    if "://" in raw:
        try:
            host = (urlparse(raw).hostname or raw).strip()
        except Exception:
            host = raw
    host = host.strip("[]").strip().lower()
    if not host:
        return False
    if host.endswith(".internal") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False


def _run_waybackurls_fallback(target: str, timeout: int = 120, stream_callback=None) -> str:
    target_host = _normalize_web_target(target)
    if not target_host:
        return "ERROR: wayback fallback could not normalize target host."

    def _stream(msg):
        if stream_callback:
            stream_callback("tool_info", {"message": msg})

    _stream("waybackurls unavailable; using robots/sitemap/archive fallback discovery.")
    lines = [
        "WAYBACK FALLBACK DISCOVERY",
        "Target: %s" % target_host,
        "",
    ]
    discovered = []
    fetch_targets = [
        "https://%s/robots.txt" % target_host,
        "https://%s/sitemap.xml" % target_host,
    ]
    for url in fetch_targets:
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": "AIReconAgent/1.0"},
                timeout=min(10, max(3, int(timeout // 12) or 6)),
                verify=False,
                allow_redirects=True,
            )
            lines.append("[%s] %s" % (resp.status_code, url))
            body = (resp.text or "")[:24000]
            for found in re.findall(r"https?://[^\s<>'\"`]+", body, flags=re.IGNORECASE):
                clean = found.rstrip(".,;:)]}>\"'")
                if target_host in clean and clean not in discovered:
                    discovered.append(clean)
        except Exception as exc:
            lines.append("[ERR] %s -> %s" % (url, str(exc)[:120]))

    cdx_url = (
        "https://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&limit=80"
        % target_host
    )
    try:
        archive_resp = requests.get(
            cdx_url,
            headers={"User-Agent": "AIReconAgent/1.0"},
            timeout=min(12, max(4, int(timeout // 10) or 8)),
        )
        lines.append("[%s] %s" % (archive_resp.status_code, cdx_url))
        if archive_resp.status_code == 200:
            for row in archive_resp.text.splitlines()[:120]:
                row = row.strip()
                if row and row not in discovered:
                    discovered.append(row)
    except Exception as exc:
        lines.append("[ERR] %s -> %s" % (cdx_url, str(exc)[:120]))

    if discovered:
        lines.append("")
        lines.append("Discovered endpoints (fallback):")
        for item in discovered[:60]:
            lines.append("- %s" % item)
    else:
        lines.append("")
        lines.append("No additional archived endpoints found with fallback discovery.")

    return "\n".join(lines)


def _probe_management_plane_host(base_url: str, extra_headers: Optional[dict] = None) -> dict:
    headers = {"User-Agent": "AIReconAgent-SeverePath/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    endpoints = ["/v1/sys/health", "/v1/sys/seal-status", "/v1/sys/leader", "/v1/sys/init"]
    evidence = []
    reachable = 0
    unsealed = False
    version = ""
    topology_leak = False

    for path in endpoints:
        url = base_url.rstrip("/") + path
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=SEVERE_PATH_TIMEOUT_SEC,
                verify=False,
                allow_redirects=False,
            )
            status = int(r.status_code)
            if status < 500 and status not in {404, 405}:
                reachable += 1
            data = {}
            try:
                data = r.json() if r.text else {}
            except Exception:
                data = {}
            if isinstance(data, dict):
                sealed = data.get("sealed")
                if sealed is False:
                    unsealed = True
                if not version and isinstance(data.get("version"), str):
                    version = str(data.get("version"))
                if path == "/v1/sys/leader":
                    if _is_private_or_internal_addr(data.get("leader_address")):
                        topology_leak = True
                    if _is_private_or_internal_addr(data.get("leader_cluster_address")):
                        topology_leak = True
            evidence.append("%s -> HTTP %s" % (path, status))
        except Exception as exc:
            evidence.append("%s -> ERROR %s" % (path, str(exc)[:90]))

    vulnerable_version = _is_vault_version_in_known_vuln_range(version)
    high_impact = (
        reachable >= 2
        and unsealed
        and (vulnerable_version or topology_leak)
        and len(evidence) >= 3
    )
    return {
        "reachable": reachable,
        "unsealed": unsealed,
        "version": version,
        "vulnerable_version": vulnerable_version,
        "topology_leak": topology_leak,
        "high_impact": high_impact,
        "evidence": evidence,
    }


def _cms_result_indicates_wordpress(result_text: str) -> bool:
    text = (result_text or "").lower()
    if not text:
        return False
    return "wordpress" in text and "no known cms detected" not in text


def _session_storage_dirs():
    dirs = [DATA_DIR]
    for legacy_dir in LEGACY_DATA_DIRS:
        if legacy_dir.exists() and legacy_dir.is_dir():
            dirs.append(legacy_dir)
    return dirs


def _resolve_session_filepath(session_id: str, prefer_existing: bool = True) -> Path:
    """Return where a session file should be read/written.

    Prefer existing legacy paths for backward compatibility; default to primary data dir.
    """
    if prefer_existing:
        for d in _session_storage_dirs():
            fp = d / f"{session_id}.json"
            if fp.exists():
                return fp
    return DATA_DIR / f"{session_id}.json"


def _load_running_sessions_from_disk() -> list[str]:
    """Load persisted running sessions into memory for recovery."""
    loaded_ids = []
    for session_dir in _session_storage_dirs():
        for fp in session_dir.glob("*.json"):
            try:
                with open(fp) as f:
                    data = json.load(f)
                data = _with_session_defaults(data)
                if data.get("status") != "running":
                    continue
                sid = data.get("id")
                if not sid:
                    continue
                with sessions_lock:
                    if sid in sessions:
                        continue
                    sessions[sid] = data
                loaded_ids.append(sid)
            except Exception:
                continue
    return loaded_ids


def _is_stop_requested(session_id: str, worker_token: Optional[int] = None) -> bool:
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return True
        if worker_token is not None and int(s.get("worker_token", 0) or 0) != int(worker_token):
            return True
        return bool(s.get("stop_requested"))


def _mark_session_stopped(session_id: str, reason: str = "Stopped by user.") -> tuple[bool, str]:
    should_save = False
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return False, "not_found"
        if s.get("stop_requested"):
            return True, "already_stopping"
        if s.get("status") == "done":
            s["stop_requested"] = True
            return True, "already_done"

        s["stop_requested"] = True
        s["status"] = "done"
        s["finished_at"] = _now_iso()
        s["recovery_state"] = "failed"
        events = s.setdefault("events", [])
        events.append({"type": "error", "message": reason, "created_at": _now_iso()})
        events.append({"type": "done", "created_at": _now_iso()})
        worker_threads.pop(session_id, None)
        should_save = True

    if should_save:
        save_session(session_id)
    return True, "stopped"


def save_session(session_id):
    """Persist a session to disk as JSON."""
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return
        data = _session_snapshot(s)
    filepath = _resolve_session_filepath(session_id)
    with open(filepath, "w") as f:
        json.dump(data, f)


def load_session(session_id):
    """Load a session from disk."""
    filepath = _resolve_session_filepath(session_id)
    if not filepath.exists():
        return None
    with open(filepath) as f:
        data = json.load(f)
    return _with_session_defaults(data)


def load_all_sessions():
    """Load metadata for all saved sessions."""
    result_by_id = {}
    for session_dir in _session_storage_dirs():
        for fp in session_dir.glob("*.json"):
            try:
                with open(fp) as f:
                    data = _with_session_defaults(json.load(f))
                sid = data["id"]
                current = result_by_id.get(sid)
                mtime = fp.stat().st_mtime
                if (current is None) or (mtime >= current["_mtime"]):
                    result_by_id[sid] = {
                        "id": sid,
                        "query": data["query"],
                        "mode": data.get("mode", "auto"),
                        "requested_mode": data.get("requested_mode", data.get("mode", "auto")),
                        "status": data["status"],
                        "created_at": data["created_at"],
                        "finished_at": data.get("finished_at", ""),
                        "recovery_state": data.get("recovery_state", "none"),
                        "recovery_attempts": int(data.get("worker_recovery_attempts", 0) or 0),
                        "last_progress_at": data.get("last_progress_at", data.get("created_at", "")),
                        "severe_path_status": data.get("severe_path_status", "none"),
                        "resolved_scope_hosts": list(data.get("resolved_scope_hosts", []) or []),
                        "coverage_degraded_count": len(list(data.get("coverage_degraded", []) or [])),
                        "_mtime": mtime,
                    }
            except Exception:
                continue

    result = list(result_by_id.values())
    result.sort(key=lambda x: x["_mtime"], reverse=True)
    for r in result:
        r.pop("_mtime", None)
    return result


def _spawn_worker_for_session(session_id: str, recovering: bool = False, reason: str = "") -> bool:
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return False
        if s.get("status") != "running":
            return False
        if s.get("stop_requested"):
            return False

        token = int(s.get("worker_token", 0) or 0) + 1
        s["worker_token"] = token
        s["recovery_state"] = "recovering" if recovering else s.get("recovery_state", "none")
        if recovering:
            s["last_recovery_at"] = _now_iso()
        query = s.get("query", "")
        mode = s.get("mode", "auto")

    save_session(session_id)
    t = threading.Thread(
        target=run_agent_worker,
        args=(session_id, query, mode, token, recovering, reason),
        daemon=True,
    )
    with sessions_lock:
        worker_threads[session_id] = t
    t.start()
    return True


def _mark_session_failed_and_done(session_id: str, reason: str):
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return
        if s.get("status") == "done":
            return
        s["status"] = "done"
        s["finished_at"] = _now_iso()
        s["recovery_state"] = "failed"
        s["stop_requested"] = True
        events = s.setdefault("events", [])
        if not events or events[-1].get("type") != "error":
            events.append({"type": "error", "message": reason, "created_at": _now_iso()})
        if not events or events[-1].get("type") != "done":
            events.append({"type": "done", "created_at": _now_iso()})
        worker_threads.pop(session_id, None)
    save_session(session_id)


def _attempt_recovery_or_fail(session_id: str, trigger_reason: str):
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return
        if s.get("status") != "running" or s.get("stop_requested"):
            return
        attempts = int(s.get("worker_recovery_attempts", 0) or 0)
        limit = int(s.get("worker_recovery_limit", WORKER_RECOVERY_LIMIT) or WORKER_RECOVERY_LIMIT)
        last_recovery_ts = _parse_iso(s.get("last_recovery_at", ""), 0.0)
        if time.time() - last_recovery_ts < RECOVERY_MIN_GAP_SEC:
            return

        if attempts >= limit:
            fail_reason = (
                f"Worker recovery limit reached ({attempts}/{limit}). "
                f"Last trigger: {trigger_reason}"
            )
            # mark outside lock helper handles lock reentry
            pass_fail = fail_reason
            do_recover = False
        else:
            attempts += 1
            s["worker_recovery_attempts"] = attempts
            s["recovery_state"] = "recovering"
            s["last_recovery_at"] = _now_iso()
            runtime = dict(s.get("runtime", _default_runtime_state()) or _default_runtime_state())
            runtime["recovery_attempts"] = attempts
            s["runtime"] = runtime
            msg = (
                f"Auto-recovery attempt {attempts}/{limit}: {trigger_reason}. "
                "Recovered after interruption; continuing from persisted state."
            )
            s.setdefault("events", []).append({
                "type": "recovery",
                "message": msg,
                "attempt": attempts,
                "limit": limit,
                "created_at": _now_iso(),
                "state": "recovering",
                "reason": trigger_reason,
            })
            do_recover = True
            pass_fail = ""

    save_session(session_id)
    if not do_recover:
        _mark_session_failed_and_done(session_id, pass_fail)
        return
    _spawn_worker_for_session(session_id, recovering=True, reason=trigger_reason)


def _running_sessions_to_monitor() -> list[tuple[str, str]]:
    actions = []
    now_ts = time.time()
    with sessions_lock:
        for sid, s in sessions.items():
            if s.get("status") != "running":
                continue
            if s.get("stop_requested"):
                continue

            t = worker_threads.get(sid)
            alive = bool(t and t.is_alive())
            if not alive:
                actions.append((sid, "Worker thread exited unexpectedly while session remained running."))
                continue

            last_progress_ts = _parse_iso(
                s.get("last_progress_at", ""),
                _parse_iso(s.get("created_at", ""), now_ts),
            )
            stalled_for = now_ts - last_progress_ts
            if stalled_for > float(WORKER_STALL_THRESHOLD_SEC):
                actions.append((
                    sid,
                    f"No non-status progress for {int(stalled_for)}s (> {int(WORKER_STALL_THRESHOLD_SEC)}s threshold).",
                ))
    return actions


def _worker_monitor_loop():
    while True:
        try:
            for sid, reason in _running_sessions_to_monitor():
                _attempt_recovery_or_fail(sid, reason)
        except Exception:
            # Keep watchdog alive even if one check fails.
            pass
        time.sleep(WORKER_MONITOR_POLL_SEC)


def _ensure_worker_monitor():
    global worker_monitor_thread
    if worker_monitor_thread and worker_monitor_thread.is_alive():
        return
    worker_monitor_thread = threading.Thread(target=_worker_monitor_loop, daemon=True)
    worker_monitor_thread.start()


def _bootstrap_running_sessions():
    loaded = _load_running_sessions_from_disk()
    for sid in loaded:
        save_needed = False
        with sessions_lock:
            s = sessions.get(sid)
            if not s:
                continue
            if s.get("stop_requested"):
                s["status"] = "done"
                s["finished_at"] = _now_iso()
                s["recovery_state"] = "failed"
                s.setdefault("events", []).append({
                    "type": "error",
                    "message": "Session was marked stopped before recovery.",
                    "created_at": _now_iso(),
                })
                s.setdefault("events", []).append({"type": "done", "created_at": _now_iso()})
                save_needed = True
            else:
                s.setdefault("runtime", _default_runtime_state())
                s["recovery_state"] = "recovering"
                save_needed = True
        if save_needed:
            save_session(sid)
        with sessions_lock:
            s = sessions.get(sid)
            if not s or s.get("status") != "running" or s.get("stop_requested"):
                continue
        _spawn_worker_for_session(sid, recovering=True, reason="Recovered after server restart.")


def sse_event(event_type, data):
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def _clip_text(text, limit=4000):
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n... ({len(text) - limit} more chars)"


def _build_followup_context(session_data):
    events = session_data.get("events", [])
    final_report = ""
    final_truth = ""
    tool_summaries = []
    recent_qa = []

    for ev in events:
        etype = ev.get("type")
        if etype == "final_report" and ev.get("text"):
            final_report = ev.get("text", "")
        elif etype == "final_truth_report" and ev.get("markdown"):
            final_truth = ev.get("markdown", "")
        elif etype == "tool_result" and ev.get("result"):
            name = ev.get("name", "tool")
            tool_summaries.append(f"[{name}]\n{_clip_text(ev.get('result', ''), 900)}")
        elif etype in {"ask_question", "ask_answer"} and ev.get("text"):
            recent_qa.append((etype, ev.get("text", "")))

    context_parts = []
    context_parts.append(f"Primary task: {session_data.get('query', '')}")

    if final_report:
        context_parts.append("Latest final report:\n" + _clip_text(final_report, 9000))
    if final_truth:
        context_parts.append("Latest final truth verification:\n" + _clip_text(final_truth, 6000))
    if tool_summaries:
        latest_tools = list(reversed(tool_summaries[-6:]))
        context_parts.append("Recent tool evidence (newest first):\n" + "\n\n".join(latest_tools))
    if recent_qa:
        qa_lines = []
        for etype, txt in reversed(recent_qa[-6:]):
            role = "User question" if etype == "ask_question" else "Assistant answer"
            qa_lines.append(f"{role}: {_clip_text(txt, 700)}")
        context_parts.append("Recent follow-up Q&A (newest first):\n" + "\n\n".join(qa_lines))

    return "\n\n".join(context_parts)


def _extract_verification_inputs(events):
    """Extract report and evidence from both current and legacy event formats."""
    report_text = ""
    fallback_report = ""
    tool_outputs = []

    # Keep noisy stream deltas out of evidence aggregation.
    skip_types = {
        "step", "thinking", "tool_start", "tool_args", "tool_call", "done",
        "final_truth_report",
    }
    legacy_evidence_types = {
        "terminal_output", "ffuf_output", "nuclei_output", "exploit_progress",
        "tool_info", "jsanalyzer_progress", "dnsrecon_progress", "subdomain_progress",
        "portscan_progress", "waf_progress", "cms_progress", "cloud_progress",
    }

    for ev in events:
        etype = ev.get("type", "")
        if etype == "final_report" and ev.get("text"):
            report_text = ev.get("text", "")
            continue
        if etype == "thinking_done" and ev.get("text"):
            txt = ev.get("text", "")
            if len(txt) > len(fallback_report):
                fallback_report = txt
            continue
        if etype == "tool_result" and ev.get("result"):
            tool_outputs.append({
                "name": str(ev.get("name", "unknown") or "unknown"),
                "text": str(ev.get("result", "")),
            })
            continue
        if etype == "severe_path":
            msg = ev.get("message") or ev.get("summary") or ""
            if msg:
                tool_outputs.append({
                    "name": "severe_path",
                    "text": "[severe_path] " + str(msg)[:1200],
                })
            continue
        if etype == "coverage_degraded":
            msg = ev.get("message") or ""
            if msg:
                tool_outputs.append({
                    "name": "coverage_degraded",
                    "text": "[coverage_degraded] " + str(msg)[:1200],
                })
            continue

        if etype in skip_types:
            continue
        if etype in legacy_evidence_types:
            txt = ev.get("text") or ev.get("message") or ev.get("output") or ev.get("result")
            if txt:
                tool_outputs.append({
                    "name": str(etype or "legacy"),
                    "text": f"[{etype}] {str(txt)[:1200]}",
                })

    if not report_text and fallback_report:
        report_text = fallback_report

    if not tool_outputs:
        # Last-resort extraction for unknown legacy formats.
        for ev in events:
            etype = ev.get("type", "")
            if etype in skip_types:
                continue
            for field in ("result", "message", "output", "text"):
                val = ev.get(field)
                if val and isinstance(val, str) and len(val.strip()) > 12:
                    tool_outputs.append({
                        "name": str(etype or "unknown"),
                        "text": f"[{etype}] {val[:1000]}",
                    })
                    break
            if len(tool_outputs) >= 120:
                break

    return report_text, tool_outputs


def _extract_primary_target(query: str) -> str:
    if not query:
        return ""
    m = re.search(r"https?://[^\s]+|(?:\b[a-z0-9-]+\.)+[a-z]{2,}\b", query, flags=re.IGNORECASE)
    if not m:
        return ""
    return m.group(0).rstrip(".,;:)]}>\"'")


def _profile_min_confidence(summary: dict) -> int:
    return int((summary or {}).get("min_confidence", 75) or 75)


def _severity_sort_key(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(str(sev or "").lower(), 9)


def _tool_result_has_failure_signal(result: str) -> bool:
    txt = str(result or "")
    failure_pattern = re.compile(
        r"(?im)(^|\n)\s*(ERROR:|ERROR running |COVERAGE DOWNGRADE:|PASSIVE_RECON_STATUS:\s*PASSIVE_RECON_UNAVAILABLE|Traceback \(most recent call last\):|FATAL:|TIMEOUT\b|timed out\b|BIN_MISSING|command not found)",
    )
    return bool(failure_pattern.search(txt))


def _summarize_tool_coverage(events: list[dict]) -> dict:
    events = events or []
    tool_calls = [ev for ev in events if ev.get("type") == "tool_call"]
    tool_results = [ev for ev in events if ev.get("type") == "tool_result"]
    error_events = [ev for ev in events if ev.get("type") == "error"]
    timeout_events = [ev for ev in events if str(ev.get("type", "")).endswith("_timeout")]
    degraded_events = [ev for ev in events if ev.get("type") == "coverage_degraded"]

    failed_tool_names = []
    successful_results = 0
    for ev in tool_results:
        result = str(ev.get("result", ""))
        name = str(ev.get("name", "tool"))
        if _tool_result_has_failure_signal(result):
            failed_tool_names.append(name)
        else:
            successful_results += 1

    _, tool_outputs = _extract_verification_inputs(events)
    unique_tools = sorted({str(ev.get("name", "tool")) for ev in tool_calls})
    unique_failed_tools = sorted(set(failed_tool_names))

    return {
        "tool_call_count": len(tool_calls),
        "tool_result_count": len(tool_results),
        "unique_tool_count": len(unique_tools),
        "unique_tools": unique_tools,
        "successful_result_count": successful_results,
        "failed_result_count": len(failed_tool_names),
        "failed_tools": unique_failed_tools,
        "error_event_count": len(error_events),
        "timeout_event_count": len(timeout_events),
        "evidence_artifact_count": len(tool_outputs),
        "coverage_degraded_count": len(degraded_events),
        "coverage_degraded": [
            {
                "tool": str(ev.get("tool", "")),
                "message": str(ev.get("message", "")),
                "fallback": str(ev.get("fallback", "")),
                "code": str(ev.get("code", "")),
            }
            for ev in degraded_events[-12:]
        ],
    }


def _build_severity_status_matrix(findings: list[dict]) -> list[tuple[str, dict]]:
    status_order = ("confirmed", "partial", "needs_manual", "not_confirmed")
    severities = ("critical", "high", "medium", "low", "info")
    matrix = {sev: {status: 0 for status in status_order} for sev in severities}

    for finding in findings or []:
        sev = str(finding.get("severity", "info")).lower()
        if sev not in matrix:
            matrix[sev] = {status: 0 for status in status_order}
        status = str(finding.get("status", "not_confirmed")).lower()
        if status not in matrix[sev]:
            status = "not_confirmed"
        matrix[sev][status] += 1

    rows = []
    for sev in severities:
        row = matrix.get(sev, {})
        if sum(row.values()) > 0:
            rows.append((sev, row))
    # Include any unknown severity buckets if present.
    for sev, row in matrix.items():
        if sev in severities:
            continue
        if sum(row.values()) > 0:
            rows.append((sev, row))
    return rows


def _ensure_scope_note(text: str) -> str:
    body = text or ""
    note_line = f"> {AUTHORIZED_SCOPE_NOTE}"
    head = body[:240].lower()
    if AUTHORIZED_SCOPE_NOTE.lower() in head:
        return body
    if not body.strip():
        return note_line
    return f"{note_line}\n\n{body}"


def run_followup_ask(session_data, question):
    """Answer a follow-up question using this chat's existing context."""
    context_block = _build_followup_context(session_data)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": build_intent_system_message(question, mode_override="ask")},
        {
            "role": "system",
            "content": (
                "You are answering an in-thread follow-up question. "
                "Answer from this thread's evidence first; if unknown, say unknown. "
                "Use tools only when needed to verify uncertain facts.\n\n"
                f"{context_block}"
            ),
        },
        {"role": "user", "content": question},
    ]

    for _ in range(ASK_MAX_ITERATIONS):
        final_message = None
        try:
            for event in chat_completion_stream(messages, tools=ALL_TOOLS):
                if event["type"] == "done":
                    final_message = event
        except (LLMStreamTimeoutError, LLMStreamRetriesExhaustedError):
            return (
                "Follow-up request timed out before the AI returned a full answer. "
                "Immediate next action: retry with a shorter question or reduced scope."
            )
        except Exception as exc:
            return f"Follow-up request failed: {str(exc)}"

        if final_message is None:
            return "I couldn't complete the follow-up answer because the model stream ended unexpectedly."

        full_content = final_message.get("content", "") or ""
        tool_calls = final_message.get("tool_calls", []) or []

        if tool_calls:
            messages.append({"role": "assistant", "content": full_content, "tool_calls": tool_calls})
            for tc in tool_calls:
                func_name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    args = {}
                handler = TOOL_HANDLERS.get(func_name)
                if not handler:
                    result = f"Unknown tool: {func_name}"
                else:
                    try:
                        result = handler(args)
                    except Exception as e:
                        result = f"ERROR running {func_name}: {str(e)}"
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
        else:
            return full_content or "(No answer generated)"

    return "I reached the follow-up reasoning limit while trying to answer this question."


def _run_status_check_ask_internal(session_data, question):
    """Provide a concise status check without launching extra tools."""
    context_block = _build_followup_context(session_data)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": build_intent_system_message(question, mode_override="ask")},
        {
            "role": "system",
            "content": (
                "Automatic watchdog follow-up: there have been no visible progress updates for a while. "
                "Summarize likely current state from existing thread evidence, identify probable blocker, "
                "and give immediate next action. Keep it concise. Do not run tools."
                f"\n\n{context_block}"
            ),
        },
        {"role": "user", "content": question},
    ]

    final_message = None
    try:
        for event in chat_completion_stream(messages, tools=[]):
            if event["type"] == "done":
                final_message = event
    except (LLMStreamTimeoutError, LLMStreamRetriesExhaustedError) as exc:
        return {
            "ok": False,
            "text": "",
            "reason": "llm_timeout",
            "error": str(exc),
            "source": "fallback",
        }
    except Exception as exc:
        return {
            "ok": False,
            "text": "",
            "reason": "llm_error",
            "error": str(exc),
            "source": "fallback",
        }

    if final_message is None:
        return {
            "ok": False,
            "text": "",
            "reason": "llm_stream_ended",
            "error": "model stream ended unexpectedly",
            "source": "fallback",
        }

    text = (final_message.get("content", "") or "").strip() or "(No status update generated)"
    return {
        "ok": True,
        "text": text,
        "reason": "ok",
        "error": "",
        "source": "llm",
    }


def _build_deterministic_status_update(session_data, reason="llm_timeout", error_text=""):
    """Build a local status update when the LLM status check is unavailable."""
    events = list(session_data.get("events", []) or [])
    non_status_events = [
        ev for ev in events
        if ev.get("type") not in {"status_check", "status_check_result"}
    ]

    if not non_status_events:
        return (
            "Status check used fallback mode because the AI response was unavailable. "
            "Likely blocker: no prior progress evidence found in this session. "
            "Immediate next action: wait for a tool/progress event; if none appears, stop and retry."
        )

    last = non_status_events[-1]
    etype = str(last.get("type", "unknown"))
    tool_name = str(last.get("name", "") or "")
    event_time = str(last.get("created_at", "") or "")
    elapsed = ""
    if event_time:
        try:
            ago = int((datetime.now() - datetime.fromisoformat(event_time)).total_seconds())
            if ago >= 0:
                elapsed = f"{ago}s ago"
        except Exception:
            elapsed = ""

    blocker = "the main model step appears stalled after the latest event."
    action = "Use Stop, then rerun with a narrower target or fewer aggressive tools."

    if etype == "tool_call":
        blocker = f"waiting on tool execution result for `{tool_name or 'unknown_tool'}`."
        action = "Use Stop, then retry and run this tool separately with a smaller timeout/scope."
    elif etype.endswith("_start") or etype == "tool_start":
        blocker = f"tool phase appears stuck right after start (`{tool_name or etype}`)."
        action = "Use Stop, then rerun and verify tool availability/timeouts."
    elif etype == "tool_result":
        blocker = "tool output finished, but the next model reasoning step did not progress."
        action = "Use Stop and retry the scan; if repeated, switch model or reduce prompt/tool load."
    elif etype == "step":
        blocker = "the model likely stalled right after entering a new reasoning step."
        action = "Use Stop and retry; if repeated, run a shorter light scan first."
    elif etype in {"thinking", "thinking_done"}:
        blocker = "model response generation appears stalled mid-thought."
        action = "Use Stop and retry with smaller scope."

    reason_hint = "AI status check timed out."
    if reason == "llm_error":
        reason_hint = "AI status check failed due to model/API error."
    elif reason == "llm_stream_ended":
        reason_hint = "AI status check stream ended unexpectedly."

    err_detail = ""
    if error_text:
        clipped = _clip_text(error_text, 180).replace("\n", " ").strip()
        if clipped:
            err_detail = f" Diagnostic: {clipped}"

    time_hint = f" Last non-status event type: `{etype}`" + (f" ({elapsed})." if elapsed else ".")
    return (
        f"{reason_hint} Fallback analysis: likely blocker is {blocker} "
        f"Immediate next action: {action}{time_hint}{err_detail}"
    )


def run_status_check_ask(session_data, question):
    """Run status check with bounded model stream and deterministic fallback."""
    result = _run_status_check_ask_internal(session_data, question)
    if result.get("ok"):
        return {
            "text": result.get("text", "(No status update generated)"),
            "source": "llm",
            "reason": "ok",
            "timed_out": False,
        }

    reason = str(result.get("reason", "llm_error") or "llm_error")
    err = str(result.get("error", "") or "")
    fallback_text = _build_deterministic_status_update(
        session_data,
        reason=reason,
        error_text=err,
    )
    return {
        "text": fallback_text,
        "source": "fallback",
        "reason": reason,
        "timed_out": reason == "llm_timeout",
    }


def _session_events_snapshot(session_id: str):
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return []
        return list(s.get("events", []))


def _run_truth_verification_for_report(
    session_id: str,
    chat_query: str,
    report_text: str,
    verification_policy: str = DEFAULT_VERIFICATION_POLICY,
    primary_target: str = "",
):
    events = _session_events_snapshot(session_id)
    _, tool_outputs = _extract_verification_inputs(events)
    return verify_bug_bounty_truth(
        chat_query=chat_query or "",
        report_text=report_text or "",
        tool_outputs=tool_outputs,
        verification_policy=_normalize_verification_policy(verification_policy),
        primary_target=primary_target or _extract_primary_target(chat_query or ""),
    )


def _is_exploit_proven_high_critical(finding: dict, min_confidence: int) -> bool:
    if (finding or {}).get("status") != "confirmed":
        return False
    if (finding or {}).get("severity") not in {"high", "critical"}:
        return False
    if int((finding or {}).get("confidence", 0) or 0) < int(min_confidence):
        return False
    evidence_count = finding.get("evidence_count")
    if evidence_count is None:
        evidence_count = len((finding or {}).get("evidence") or [])
    if int(evidence_count) < 1:
        return False
    return bool(finding.get("direct_impact") or finding.get("bounty_ready"))


def _build_gated_final_report(
    truth_result: dict,
    query: str = "",
    mode: str = "auto",
    events=None,
    extra_pass_used: bool = False,
    session_meta: Optional[dict] = None,
) -> str:
    summary = (truth_result or {}).get("summary", {}) or {}
    findings = (truth_result or {}).get("findings", []) or []
    events = events or []
    session_meta = session_meta or {}
    min_confidence = _profile_min_confidence(summary)
    target = _extract_primary_target(query)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    coverage = _summarize_tool_coverage(events)
    matrix_rows = _build_severity_status_matrix(findings)

    verified = [f for f in findings if _is_exploit_proven_high_critical(f, min_confidence)]
    verified.sort(key=lambda f: (_severity_sort_key(f.get("severity")), -int(f.get("confidence", 0) or 0)))
    unverified = [f for f in findings if f not in verified]
    unverified.sort(key=lambda f: (_severity_sort_key(f.get("severity")), -int(f.get("confidence", 0) or 0)))
    actionable = [
        f for f in findings
        if f not in verified
        and str(f.get("status", "")).lower() in {"confirmed", "partial"}
        and int(f.get("evidence_count", len(f.get("evidence") or [])) or 0) >= 1
    ]
    actionable.sort(key=lambda f: (_severity_sort_key(f.get("severity")), -int(f.get("confidence", 0) or 0)))
    high_confirmed_non_proven = [
        f for f in findings
        if f not in verified
        and str(f.get("status", "")).lower() == "confirmed"
        and str(f.get("severity", "")).lower() in {"high", "critical"}
        and int(f.get("evidence_count", len(f.get("evidence") or [])) or 0) < 1
    ]
    manual_or_inconclusive = [
        f for f in findings
        if f not in verified and f not in high_confirmed_non_proven and f not in actionable
    ]

    resolved_scope_hosts = list(session_meta.get("resolved_scope_hosts", []) or [])
    severe_path_status = str(session_meta.get("severe_path_status", "none") or "none")
    coverage_degraded = list(session_meta.get("coverage_degraded", []) or [])
    auth_context = _normalize_auth_context(session_meta.get("auth_context", {}))

    lines = [
        "## Deep Scan Forensic Verification Report",
        "",
        f"> {AUTHORIZED_SCOPE_NOTE}",
        "",
        "### Engagement Metadata",
        f"- Generated: **{generated_at}**",
        f"- Mode: **{mode}**",
        f"- Query target: **{target or 'Not detected'}**",
        f"- Verification policy: **{summary.get('verification_policy', DEFAULT_VERIFICATION_POLICY)}**",
        f"- Verification profile: **{summary.get('profile', 'Unknown')}**",
        f"- Strictness: **{summary.get('strictness', 'unknown')}**",
        f"- Severity gate confidence threshold: **{min_confidence}%**",
        f"- Bounty-ready now: **{summary.get('ready_count', 0)}/{summary.get('total_findings', len(findings))}**",
        f"- Actionable evidence-backed findings: **{summary.get('actionable_count', len(actionable))}**",
        f"- Exploit-proven HIGH/CRITICAL after gating: **{len(verified)}**",
        f"- Severe-path workflow status: **{severe_path_status}**",
        f"- Resolved in-scope hosts: **{len(resolved_scope_hosts)}**",
        f"- Coverage degradation signals: **{len(coverage_degraded)}**",
        "",
    ]
    if extra_pass_used:
        lines.append("- Extra verification pass: **Executed (bounded)**")
    if auth_context.get("enabled"):
        lines.append(
            f"- Authorized auth context: **Enabled** (profile `{auth_context.get('profile', 'default')}`, scope `{auth_context.get('scope', 'all')}`)"
        )
    else:
        lines.append("- Authorized auth context: **Disabled**")
    lines.append("")

    lines.append("### Severity/Status Matrix")
    if matrix_rows:
        lines.extend([
            "| Severity | Confirmed | Partial | Needs Manual | Not Confirmed |",
            "|---|---:|---:|---:|---:|",
        ])
        for sev, row in matrix_rows:
            lines.append(
                f"| {str(sev).upper()} | {row.get('confirmed', 0)} | {row.get('partial', 0)} | "
                f"{row.get('needs_manual', 0)} | {row.get('not_confirmed', 0)} |"
            )
    else:
        lines.append("- No findings were available for matrix generation.")
    lines.append("")

    lines.append("### Exploit-Proven HIGH/CRITICAL (Evidence-Backed)")
    if verified:
        for f in verified:
            sev = str(f.get("severity", "")).upper()
            lines.append(f"#### [{sev}] {f.get('name', 'Finding')}")
            lines.append(f"- Confidence: **{f.get('confidence', 0)}%** (gate >= {min_confidence}%)")
            lines.append(
                "- Direct-impact quality: **"
                + ("Yes" if bool(f.get("direct_impact") or f.get("bounty_ready")) else "No")
                + "**"
            )
            lines.append(f"- Impact scope: {f.get('impact_scope', 'Not specified.')}")
            lines.append(f"- Preconditions: {f.get('preconditions', 'Not specified.')}")
            lines.append(f"- Verification method: {f.get('verification_method', 'Not specified.')}")
            lines.append(f"- Reproducibility notes: {f.get('reproducibility', 'Not specified.')}")
            lines.append(f"- Attacker impact summary: {f.get('attacker_action', 'Not provided')}")
            lines.append(f"- Evidence count: **{f.get('evidence_count', len(f.get('evidence') or []))}**")
            lines.append(f"- Remediation hint: {f.get('remediation_hint', 'Not specified.')}")
            ev = (f.get("evidence") or [])[:6]
            if ev:
                lines.append("- Evidence:")
                for item in ev:
                    lines.append(f"  - `{item}`")
            lines.append("")
    else:
        lines.append("- No exploit-proven HIGH/CRITICAL findings after deterministic gating.")
    lines.append("")

    lines.append("### High-Impact Proven Paths")
    if verified:
        for f in verified:
            sev = str(f.get("severity", "high")).upper()
            lines.append(f"- [{sev}] {f.get('name', 'Finding')}: {f.get('verification_method', 'Deterministic verification')} (evidence {f.get('evidence_count', len(f.get('evidence') or []))})")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("### Actionable Evidence-Backed Findings")
    if actionable:
        for f in actionable:
            sev = str(f.get("severity", "unknown")).upper()
            status = str(f.get("status", "unknown")).replace("_", " ").title()
            lines.append(f"#### [{sev}] {f.get('name', 'Finding')} — {status}")
            lines.append(f"- Confidence: **{f.get('confidence', 0)}%**")
            lines.append(f"- Reason: {f.get('reason', 'No reason provided')}")
            lines.append(f"- Verification method: {f.get('verification_method', 'Not specified.')}")
            lines.append(f"- Impact scope: {f.get('impact_scope', 'Not specified.')}")
            lines.append(f"- Next deterministic step: {f.get('next_validation_step', 'Not specified.')}")
            lines.append(f"- Evidence count: **{f.get('evidence_count', len(f.get('evidence') or []))}**")
            ev = (f.get("evidence") or [])[:5]
            if ev:
                lines.append("- Evidence:")
                for item in ev:
                    lines.append(f"  - `{item}`")
            lines.append("")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("### High-Risk Confirmed But Not Exploit-Proven")
    if high_confirmed_non_proven:
        for f in high_confirmed_non_proven:
            sev = str(f.get("severity", "unknown")).upper()
            lines.append(f"#### [{sev}] {f.get('name', 'Finding')} — Confirmed")
            lines.append(f"- Confidence: **{f.get('confidence', 0)}%**")
            lines.append(f"- Reason not exploit-proven: {f.get('reason', 'Direct impact threshold not met.')}")
            lines.append(f"- Next deterministic step: {f.get('next_validation_step', 'Not specified.')}")
            lines.append(f"- Evidence count: **{f.get('evidence_count', len(f.get('evidence') or []))}**")
            lines.append("")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("### Manual / Inconclusive Findings")
    if manual_or_inconclusive:
        for f in manual_or_inconclusive:
            sev = str(f.get("severity", "unknown")).upper()
            status = str(f.get("status", "unknown")).replace("_", " ").title()
            lines.append(f"#### [{sev}] {f.get('name', 'Finding')} — {status}")
            lines.append(f"- Confidence: **{f.get('confidence', 0)}%**")
            lines.append(f"- Reason: {f.get('reason', 'No reason provided')}")
            lines.append(f"- Next deterministic step: {f.get('next_validation_step', 'Not specified.')}")
            lines.append(f"- Verification method: {f.get('verification_method', 'Not specified.')}")
            lines.append(f"- Impact scope: {f.get('impact_scope', 'Not specified.')}")
            lines.append(f"- Evidence count: **{f.get('evidence_count', len(f.get('evidence') or []))}**")
            lines.append("")
    else:
        lines.append("- None")
    lines.append("")

    lines.extend([
        "### Tool Coverage And Data Quality",
        f"- Tool calls executed: **{coverage['tool_call_count']}** ({coverage['unique_tool_count']} unique tools)",
        f"- Tool results captured: **{coverage['tool_result_count']}**",
        f"- Successful tool results: **{coverage['successful_result_count']}**",
        f"- Failure/timeout signals: **{coverage['failed_result_count'] + coverage['timeout_event_count']}**",
        f"- Session error events: **{coverage['error_event_count']}**",
        f"- Evidence artifacts ingested for verification: **{coverage['evidence_artifact_count']}**",
        f"- Coverage degradations recorded: **{coverage['coverage_degraded_count']}**",
    ])
    if coverage["failed_tools"]:
        lines.append("- Tools with failure indicators: `" + ", ".join(coverage["failed_tools"][:12]) + "`")
    else:
        lines.append("- Tools with failure indicators: None observed.")
    lines.append("- Evidence provenance: tool outputs and deterministic verifier checks only; no unbacked claims.")
    if coverage.get("coverage_degraded"):
        lines.append("- Coverage downgrade details:")
        for item in coverage.get("coverage_degraded", [])[:8]:
            tool = item.get("tool") or "tool"
            msg = item.get("message") or "coverage reduced"
            fb = item.get("fallback") or "none"
            lines.append(f"  - `{tool}`: {msg} (fallback: {fb})")
    lines.append("")

    if not verified:
        lines.append("### Why 0 Severe (Diagnostic)")
        if not auth_context.get("enabled"):
            lines.append("- Authorized auth context was disabled; some high-impact authz proof paths could not be tested.")
        if severe_path_status in {"blocked", "none"}:
            lines.append("- Severe-path deterministic verification was not fully executed or was blocked.")
        if coverage_degraded:
            lines.append(f"- Coverage degradation reduced high-signal paths ({len(coverage_degraded)} item(s)).")
        if coverage.get("failed_tools"):
            lines.append("- Failed high-signal tools: `" + ", ".join(coverage.get("failed_tools", [])[:8]) + "`")
        if resolved_scope_hosts:
            lines.append("- Resolved scope hosts considered: `" + ", ".join(resolved_scope_hosts[:8]) + "`")
        else:
            lines.append("- No reachable first-party pivot hosts were confirmed for severe-path checks.")
        lines.append("- Deterministic direct-impact criteria were not met for HIGH/CRITICAL promotion.")
        lines.append("")

    immediate = []
    for finding in verified:
        hint = str(finding.get("remediation_hint", "")).strip()
        if hint and hint not in immediate:
            immediate.append(hint)

    near_term = []
    for finding in unverified:
        step = str(finding.get("next_validation_step", "")).strip()
        if step and step not in near_term:
            near_term.append(step)

    lines.append("### Prioritized Remediation And Retest Checklist")
    lines.append("#### Immediate (24-48 hours)")
    if immediate:
        for idx, hint in enumerate(immediate[:4], start=1):
            lines.append(f"{idx}. {hint}")
    else:
        lines.append("1. Review confirmed findings and maintain current controls where no exploit-proven critical issues exist.")
    lines.append("")
    lines.append("#### Near-Term (1-2 weeks)")
    if near_term:
        for idx, step in enumerate(near_term[:4], start=1):
            lines.append(f"{idx}. {step}")
    else:
        lines.append("1. Re-run deterministic verification after any security-control or configuration changes.")
    lines.append("")
    lines.append("#### Long-Term (1 month)")
    lines.append("1. Add recurring deep-scan verification with evidence retention and trend tracking.")
    lines.append("2. Monitor for regression in critical security headers, auth controls, and exposed infrastructure.")
    lines.append("3. Validate remediation closure by repeating the exact deterministic checks from this report.")
    return _ensure_scope_note("\n".join(lines))


def run_agent_worker(
    session_id,
    user_input,
    mode="auto",
    worker_token: Optional[int] = None,
    recovering: bool = False,
    recovery_reason: str = "",
):
    """Run agent in a background thread, storing events in the session."""
    runtime_snapshot = {}
    session_snapshot = {}
    with sessions_lock:
        s = sessions.get(session_id)
        if s:
            session_snapshot = _session_snapshot(s)
            runtime_snapshot = dict(s.get("runtime", _default_runtime_state()) or _default_runtime_state())
            if worker_token is None:
                worker_token = int(s.get("worker_token", 0) or 0)

    if worker_token is None:
        worker_token = 0

    start_iteration = 0
    extra_verification_used = False
    auto_wpscan_hosts = set()
    known_hosts = set()
    severe_path_executed = False
    netlas_disabled = False
    passive_recon_degraded = ""
    stopped = False
    next_iteration_idx = 0
    last_checkpoint_ts = 0.0
    primary_target = _extract_primary_target(user_input)
    primary_host = _normalize_web_target(primary_target or user_input)
    root_domain = _registrable_domain(primary_host)
    auth_context = _normalize_auth_context(session_snapshot.get("auth_context", {}))
    verification_policy = _normalize_verification_policy(
        session_snapshot.get("verification_policy", DEFAULT_VERIFICATION_POLICY)
    )

    # Fresh conversation by default.
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": build_intent_system_message(user_input, mode_override=mode)},
        {"role": "user", "content": user_input},
    ]
    if mode == "deep":
        messages.insert(2, {"role": "system", "content": DEEP_SCAN_ENFORCER})
    elif mode == "light":
        messages.insert(2, {"role": "system", "content": LIGHT_SCAN_ENFORCER})

    for host in _extract_hosts_from_text(user_input):
        if _is_first_party_host(host, root_domain):
            known_hosts.add(host)
    if primary_host:
        known_hosts.add(primary_host)

    # Recovery path: restore checkpointed runtime when available.
    if recovering:
        checkpoint_messages = runtime_snapshot.get("messages") or []
        if isinstance(checkpoint_messages, list) and checkpoint_messages:
            messages = checkpoint_messages
            start_iteration = int(runtime_snapshot.get("iteration", 0) or 0)
            extra_verification_used = bool(runtime_snapshot.get("extra_verification_used", False))
            auto_wpscan_hosts = set(runtime_snapshot.get("auto_wpscan_hosts", []) or [])
            known_hosts = set(runtime_snapshot.get("known_hosts", []) or [])
            severe_path_executed = bool(runtime_snapshot.get("severe_path_executed", False))
            netlas_disabled = bool(runtime_snapshot.get("netlas_disabled", runtime_snapshot.get("shodan_disabled", False)))
            passive_recon_degraded = str(runtime_snapshot.get("passive_recon_degraded", "") or "")
        else:
            resume_context = _build_followup_context(session_snapshot or {
                "id": session_id,
                "query": user_input,
                "mode": mode,
                "events": [],
            })
            messages.append({
                "role": "system",
                "content": (
                    "Recovered interrupted run. Continue from this prior context and finish the scan "
                    "without repeating already-covered trivial checks.\n\n"
                    f"{resume_context}"
                ),
            })
            messages.append({
                "role": "user",
                "content": (
                    "Continue the interrupted scan from the prior context. "
                    "Prioritize progress and finish with a final evidence-backed report."
                ),
            })
            start_iteration = 0

    start_iteration = max(0, min(MAX_ITERATIONS - 1, start_iteration))
    next_iteration_idx = start_iteration

    critical_persist_events = {
        "step", "tool_call", "tool_result", "error", "done",
        "final_report", "final_truth_report", "recovery",
        "severe_path", "coverage_degraded",
    }

    def checkpoint_runtime(force: bool = False):
        nonlocal last_checkpoint_ts
        now_ts = time.time()
        if not force and (now_ts - last_checkpoint_ts) < SESSION_FLUSH_INTERVAL_SEC:
            return

        with sessions_lock:
            s = sessions.get(session_id)
            if not s:
                return
            if int(s.get("worker_token", 0) or 0) != int(worker_token):
                return
            runtime = dict(s.get("runtime", _default_runtime_state()) or _default_runtime_state())
            runtime["messages"] = list(messages)
            runtime["iteration"] = int(next_iteration_idx)
            runtime["extra_verification_used"] = bool(extra_verification_used)
            runtime["auto_wpscan_hosts"] = sorted(list(auto_wpscan_hosts))
            runtime["known_hosts"] = sorted(list(known_hosts))
            runtime["severe_path_executed"] = bool(severe_path_executed)
            runtime["netlas_disabled"] = bool(netlas_disabled)
            runtime["passive_recon_degraded"] = str(passive_recon_degraded or "")
            runtime["last_progress_at"] = s.get("last_progress_at", _now_iso())
            runtime["recovery_attempts"] = int(s.get("worker_recovery_attempts", 0) or 0)
            s["runtime"] = runtime
            if not s.get("last_progress_at"):
                s["last_progress_at"] = runtime["last_progress_at"]

        save_session(session_id)
        last_checkpoint_ts = now_ts

    def emit(event_type, data):
        event = {"type": event_type, **data}
        event.setdefault("created_at", _now_iso())
        should_checkpoint = False
        force_checkpoint = False

        with sessions_lock:
            s = sessions.get(session_id)
            if not s:
                return
            if int(s.get("worker_token", 0) or 0) != int(worker_token):
                return
            if s.get("stop_requested") and event_type not in {"error", "done"}:
                return
            if event_type == "done" and s["events"] and s["events"][-1].get("type") == "done":
                return

            s["events"].append(event)
            if event_type not in {"status_check", "status_check_result"}:
                s["status_check_timeout_streak"] = 0
                s["status_check_paused"] = False
                s["last_progress_at"] = event["created_at"]
                if s.get("recovery_state") == "recovering" and event_type != "recovery":
                    s["recovery_state"] = "resumed"

            should_checkpoint = True
            force_checkpoint = event_type in critical_persist_events

        if should_checkpoint:
            checkpoint_runtime(force=force_checkpoint)

    def _persist_session_metadata(updates: dict):
        with sessions_lock:
            s = sessions.get(session_id)
            if not s:
                return
            if int(s.get("worker_token", 0) or 0) != int(worker_token):
                return
            for key, value in updates.items():
                s[key] = value
        save_session(session_id)

    def _record_coverage_degraded(tool: str, message: str, fallback: str = "", code: str = ""):
        entry = {
            "tool": tool,
            "message": message,
            "fallback": fallback,
            "code": code,
            "created_at": _now_iso(),
        }
        with sessions_lock:
            s = sessions.get(session_id)
            if not s:
                return
            if int(s.get("worker_token", 0) or 0) != int(worker_token):
                return
            arr = list(s.get("coverage_degraded", []) or [])
            arr.append(entry)
            s["coverage_degraded"] = arr[-30:]
        emit("coverage_degraded", entry)

    def _register_known_hosts_from_text(text: str):
        for host in _extract_hosts_from_text(text):
            if _is_first_party_host(host, root_domain):
                known_hosts.add(host)

    def _run_severe_path_phase() -> dict:
        nonlocal severe_path_executed
        severe_path_executed = True
        if mode != "deep":
            return {"status": "skipped", "hosts": []}
        if not root_domain:
            emit("severe_path", {
                "state": "blocked",
                "message": "Severe-path verification blocked: could not determine first-party root domain.",
            })
            _persist_session_metadata({"severe_path_status": "blocked"})
            return {"status": "blocked", "hosts": []}

        candidate_hosts = set(h for h in known_hosts if _is_first_party_host(h, root_domain))
        for prefix in ("vault", "admin", "api", "staging", "auth", "alpha", "app", "www"):
            candidate_hosts.add(f"{prefix}.{root_domain}")
        if primary_host and _is_first_party_host(primary_host, root_domain):
            candidate_hosts.add(primary_host)

        reachability = {}
        apex_ok = False
        for host in sorted(candidate_hosts):
            if not _is_first_party_host(host, root_domain):
                continue
            resolution = resolve_web_target(host, headers={"User-Agent": "AIReconAgent/1.0"})
            reachability[host] = resolution
            if host == primary_host and resolution.get("ok"):
                apex_ok = True

        reachable_hosts = [h for h, r in reachability.items() if r.get("ok")]
        reachable_hosts.sort(key=lambda h: _risk_rank_host(h), reverse=True)
        selected_hosts = reachable_hosts[:MAX_SCOPE_PIVOT_HOSTS]
        if not selected_hosts:
            emit("severe_path", {
                "state": "blocked",
                "message": "Severe-path verification blocked: no reachable first-party hosts after pivot resolution.",
            })
            _persist_session_metadata({
                "severe_path_status": "blocked",
                "resolved_scope_hosts": [],
            })
            return {"status": "blocked", "hosts": []}

        pivot_applied = (not apex_ok) and any(h != primary_host for h in selected_hosts)
        attempted_msg = "Severe-path verification attempted on %d host(s)." % len(selected_hosts)
        if pivot_applied and primary_host:
            attempted_msg += f" Apex `{primary_host}` unreachable; pivoted to reachable first-party subdomains."
        emit("severe_path", {
            "state": "attempted",
            "message": attempted_msg,
            "hosts": selected_hosts,
            "pivot_applied": pivot_applied,
        })

        auth_headers = {}
        if auth_context.get("enabled"):
            auth_headers = _load_auth_profile_headers(auth_context.get("profile", "default"))
            if not auth_headers:
                _record_coverage_degraded(
                    "auth_context",
                    "Auth context enabled but no env-backed auth profile headers were available.",
                    fallback="unauthenticated severe-path validation",
                    code="AUTH_PROFILE_MISSING",
                )

        report_lines = [
            "SEVERE PATH VERIFICATION",
            f"Root domain: {root_domain}",
            f"Pivot applied: {pivot_applied}",
            f"Hosts tested: {', '.join(selected_hosts)}",
            "",
        ]
        confirmed_hosts = []

        for host in selected_hosts:
            res = reachability.get(host) or {}
            selected_url = str(res.get("selected_url") or f"https://{host}").rstrip("/")
            auth_for_host = {}
            if auth_headers and _host_allowed_by_auth_context(host, auth_context, root_domain):
                auth_for_host = dict(auth_headers)
            probe = _probe_management_plane_host(selected_url, extra_headers=auth_for_host)

            report_lines.append(f"Host: {host}")
            report_lines.append(f"- Reachable control endpoints: {probe.get('reachable', 0)}")
            report_lines.append(f"- Unsealed/operational signal: {probe.get('unsealed', False)}")
            report_lines.append(f"- Version: {probe.get('version') or 'unknown'}")
            report_lines.append(f"- Known vulnerable version range hit: {probe.get('vulnerable_version', False)}")
            report_lines.append(f"- Internal topology exposure: {probe.get('topology_leak', False)}")
            if auth_for_host:
                report_lines.append("- Auth context: applied")
            elif auth_context.get("enabled"):
                report_lines.append("- Auth context: enabled but not in-scope/no headers")
            else:
                report_lines.append("- Auth context: disabled")
            if probe.get("high_impact"):
                report_lines.append("- HIGH_IMPACT_CONFIRMED: true")
                confirmed_hosts.append(host)
            for ev_line in (probe.get("evidence") or [])[:8]:
                report_lines.append(f"  - {ev_line}")
            report_lines.append("")

        severe_state = "confirmed" if confirmed_hosts else "attempted"
        if confirmed_hosts:
            emit("severe_path", {
                "state": "confirmed",
                "message": "Severe-path high-impact evidence confirmed on: " + ", ".join(confirmed_hosts[:4]),
                "hosts": confirmed_hosts,
            })
        result_text = "\n".join(report_lines)
        emit("tool_result", {
            "name": "severe_path_verifier",
            "result": result_text,
            "id": "severe_path_verifier",
        })
        _persist_session_metadata({
            "severe_path_status": severe_state,
            "resolved_scope_hosts": selected_hosts,
        })
        return {"status": severe_state, "hosts": selected_hosts}

    def finalize_session():
        with sessions_lock:
            s = sessions.get(session_id)
            if not s:
                return
            if int(s.get("worker_token", 0) or 0) != int(worker_token):
                return
            s["status"] = "done"
            s["finished_at"] = _now_iso()
            if s.get("recovery_state") == "recovering":
                s["recovery_state"] = "resumed"
            worker_threads.pop(session_id, None)
        checkpoint_runtime(force=True)
        save_session(session_id)

    try:
        if recovering:
            emit("recovery", {
                "message": (
                    "Recovered after interruption; continuing from persisted state."
                    + (f" Trigger: {recovery_reason}" if recovery_reason else "")
                ),
                "state": "recovering",
                "attempt": int(runtime_snapshot.get("recovery_attempts", 0) or 0),
            })

        safety = _classify_query_safety(user_input)
        if safety.get("blocked"):
            emit("thinking_done", {
                "text": (
                    "Request blocked by safety policy. Only authorized, non-destructive "
                    "security validation is supported."
                )
            })
            emit("final_report", {
                "text": _build_policy_block_report(user_input, safety, mode=mode),
            })
            emit("done", {})
            return

        if mode == "deep":
            if not shutil.which("waybackurls"):
                _record_coverage_degraded(
                    "run_waybackurls",
                    "waybackurls binary not found on PATH.",
                    fallback="robots/sitemap/archive endpoint discovery fallback",
                    code="BIN_MISSING",
                )
            netlas_key = (os.getenv("NETLAS_API_KEY", "") or "").strip()
            if not netlas_key:
                netlas_disabled = True
                passive_recon_degraded = "NETLAS_KEY_MISSING"
                _record_coverage_degraded(
                    "shodan_lookup",
                    "NETLAS_API_KEY is not configured.",
                    fallback="set NETLAS_API_KEY to re-enable passive recon",
                    code="NETLAS_KEY_MISSING",
                )
            _persist_session_metadata({
                "severe_path_status": "pending",
                "auth_context": auth_context,
            })

        for iteration in range(start_iteration, MAX_ITERATIONS):
            next_iteration_idx = iteration
            if _is_stop_requested(session_id, worker_token):
                stopped = True
                break
            emit("step", {"iteration": iteration + 1, "max": MAX_ITERATIONS})
            next_iteration_idx = iteration + 1

            final_message = None
            try:
                for event in chat_completion_stream(messages, tools=ALL_TOOLS):
                    if _is_stop_requested(session_id, worker_token):
                        stopped = True
                        break
                    etype = event.get("type")
                    if etype == "content_delta":
                        emit("thinking", {"text": event.get("text", "")})
                    elif etype == "tool_call_start":
                        emit("tool_start", {"name": event.get("name", ""), "index": event.get("index", 0)})
                    elif etype == "tool_call_args_delta":
                        emit("tool_args", {"text": event.get("text", ""), "index": event.get("index", 0)})
                    elif etype == "done":
                        final_message = event
            except Exception as e:
                if isinstance(e, (LLMStreamTimeoutError, LLMStreamRetriesExhaustedError)):
                    emit("error", {
                        "message": (
                            "LLM stream timed out during main run. "
                            "Immediate next action: stop and retry this scan, or reduce scan scope/tool load."
                        )
                    })
                else:
                    emit("error", {"message": f"Worker exception in model loop: {str(e)}"})
                break
            if stopped:
                break

            if final_message is None:
                emit("error", {"message": "Stream ended unexpectedly"})
                break

            full_content = final_message.get("content", "") or ""
            tool_calls = final_message.get("tool_calls") or []

            if full_content:
                emit("thinking_done", {"text": full_content})
                _register_known_hosts_from_text(full_content)

            if tool_calls:
                messages.append({"role": "assistant", "content": full_content or "", "tool_calls": tool_calls})
                for tc in tool_calls:
                    if _is_stop_requested(session_id, worker_token):
                        stopped = True
                        break
                    func_name = tc.get("function", {}).get("name", "")
                    try:
                        args = json.loads(tc.get("function", {}).get("arguments", "") or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    if not isinstance(args, dict):
                        args = {}
                    emit("tool_call", {"name": func_name, "args": args, "id": tc.get("id", "")})
                    for k in ("target", "target_url", "url", "base_url", "hostname"):
                        if k in args:
                            host = _normalize_web_target(str(args.get(k, "")))
                            if _is_first_party_host(host, root_domain):
                                known_hosts.add(host)

                    def tool_stream_callback(event_type, data):
                        if _is_stop_requested(session_id, worker_token):
                            return
                        emit(event_type, {**data, "tool_id": tc.get("id", "")})

                    required_args = REQUIRED_TOOL_ARGS.get(func_name, [])
                    missing_required = [key for key in required_args if key not in args]
                    if missing_required:
                        result = (
                            f"ERROR: Missing required argument(s) {missing_required} for tool {func_name}. "
                            "Skipping execution."
                        )
                        emit("tool_result", {"name": func_name, "result": result, "id": tc.get("id", "")})
                        messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": result})
                        continue

                    try:
                        if func_name == "run_terminal":
                            result = run_terminal(
                                args["command"],
                                args.get("timeout", 180),
                                require_confirm=False,
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "check_exposed_paths":
                            result = check_exposed_paths(
                                args["base_url"],
                                args.get("scan_profile", "deep" if mode == "deep" else "standard"),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "run_ffuf":
                            result = run_ffuf(
                                args["target_url"],
                                args.get("mode", "dir"),
                                args.get("wordlist", "common"),
                                args.get("extensions", ""),
                                args.get("threads", 50),
                                args.get("timeout", 120),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "run_nuclei":
                            result = run_nuclei(
                                args["target"],
                                args.get("templates", "auto"),
                                args.get("severity", "critical,high,medium"),
                                args.get("timeout", 300),
                                args.get("rate_limit", 150),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "exploit_target":
                            result = exploit_target(
                                args["target"],
                                args.get("exploit_type", "auto"),
                                args.get("options", {}),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "port_scan":
                            result = port_scan(
                                args["target"], args.get("scan_type", "top100"),
                                args.get("custom_ports", ""),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "subdomain_enum":
                            result = subdomain_enumerate(
                                args["target"], args.get("mode", "passive"),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "param_mine":
                            result = param_mine(
                                args["target"], args.get("method", "GET"),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "cors_scan":
                            result = cors_scan(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "header_audit":
                            result = header_audit(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "js_analyze":
                            result = js_analyze(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "cms_scan":
                            result = cms_scan(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "dns_recon":
                            result = dns_recon(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "waf_fingerprint":
                            result = waf_fingerprint(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "graphql_exploit":
                            result = graphql_exploit(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "cloud_recon":
                            result = cloud_recon(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "api_fuzz":
                            result = api_fuzz(args["target"], args.get("mode", "full"), stream_callback=tool_stream_callback)
                        elif func_name == "cache_poison":
                            result = cache_poison(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "http_smuggle":
                            result = http_smuggle(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "oauth_test":
                            result = oauth_test(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "race_test":
                            result = race_test(
                                args["target"], args.get("endpoint", ""), args.get("method", "POST"),
                                args.get("payload"), args.get("parallel", 15),
                                stream_callback=tool_stream_callback
                            )
                        elif func_name == "supply_chain_scan":
                            result = supply_chain_scan(args["target"], stream_callback=tool_stream_callback)
                        elif func_name == "run_trufflehog":
                            result = run_trufflehog(
                                args["path"],
                                args.get("scan_mode", "filesystem"),
                                args.get("timeout", 300),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_gitleaks":
                            result = run_gitleaks(
                                args["path"],
                                args.get("timeout", 300),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_aquatone":
                            result = run_aquatone(
                                args["targets"],
                                args.get("timeout", 300),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_testssl":
                            result = run_testssl(
                                args["target"],
                                args.get("mode", "fast"),
                                args.get("timeout", 420),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_naabu":
                            result = run_naabu(
                                args["target"],
                                args.get("scan_type", "top100"),
                                args.get("rate", 1000),
                                args.get("timeout", 180),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_waybackurls":
                            if shutil.which("waybackurls"):
                                result = run_waybackurls(
                                    args["target"],
                                    args.get("timeout", 120),
                                    stream_callback=tool_stream_callback,
                                    artifact_session=session_id,
                                )
                            else:
                                _record_coverage_degraded(
                                    "run_waybackurls",
                                    "waybackurls binary unavailable during tool execution.",
                                    fallback="robots/sitemap/archive endpoint discovery fallback",
                                    code="BIN_MISSING",
                                )
                                result = _run_waybackurls_fallback(
                                    args["target"],
                                    args.get("timeout", 120),
                                    stream_callback=tool_stream_callback,
                                )
                        elif func_name == "run_arjun":
                            result = run_arjun(
                                args["target_url"],
                                args.get("method", "GET"),
                                args.get("timeout", 240),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_wfuzz":
                            result = run_wfuzz(
                                args["target_url"],
                                args.get("wordlist", "common"),
                                args.get("hide_codes", "404"),
                                args.get("threads", 20),
                                args.get("timeout", 180),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_semgrep":
                            result = run_semgrep(
                                args["path"],
                                args.get("config", "auto"),
                                args.get("timeout", 600),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        elif func_name == "run_wpscan":
                            result = run_wpscan(
                                args["target"],
                                args.get("scan_profile", "aggressive_enum"),
                                args.get("timeout", 420),
                                stream_callback=tool_stream_callback,
                                artifact_session=session_id,
                            )
                        else:
                            if func_name in PASSIVE_RECON_TOOL_NAMES and netlas_disabled:
                                result = (
                                    "COVERAGE DOWNGRADE: passive recon unavailable (PASSIVE_RECON_UNAVAILABLE).\n"
                                    "Immediate next action: configure NETLAS_API_KEY to re-enable Netlas-first passive recon.\n"
                                    "PASSIVE_RECON_CODE: PASSIVE_RECON_UNAVAILABLE\n"
                                    "PASSIVE_RECON_STATUS: PASSIVE_RECON_UNAVAILABLE"
                                )
                            else:
                                handler = TOOL_HANDLERS.get(func_name)
                                result = handler(args) if handler else f"Unknown tool: {func_name}"
                    except KeyError as missing_arg:
                        result = f"ERROR: Missing required argument '{missing_arg.args[0]}' for tool {func_name}"
                    except Exception as tool_exc:
                        result = f"ERROR running {func_name}: {str(tool_exc)}"

                    if _is_stop_requested(session_id, worker_token):
                        stopped = True
                        break
                    if func_name in PASSIVE_RECON_TOOL_NAMES:
                        passive_status = classify_passive_recon_result(str(result))
                        passive_code = str(passive_status.get("code", "") or "")
                        if passive_status.get("fallback_used"):
                            passive_code = "NETLAS_FALLBACK_TO_SHODAN"
                        if passive_status.get("degraded"):
                            fallback_note = (
                                "Shodan secondary backend"
                                if passive_status.get("fallback_used")
                                else "DNS/HTTP-only reconnaissance"
                            )
                            _record_coverage_degraded(
                                func_name,
                                str(passive_status.get("message", "Passive recon degraded.")),
                                fallback=fallback_note,
                                code=passive_code or "PASSIVE_RECON_UNAVAILABLE",
                            )
                            if passive_code in {
                                "NETLAS_KEY_MISSING",
                                "NETLAS_AUTH_OR_PLAN_DENIED",
                                "NETLAS_RATE_LIMITED",
                                "PASSIVE_RECON_UNAVAILABLE",
                            }:
                                netlas_disabled = True
                                passive_recon_degraded = passive_code
                    emit("tool_result", {"name": func_name, "result": result, "id": tc.get("id", "")})
                    messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": result})
                    _register_known_hosts_from_text(result)

                    if mode == "deep" and func_name == "cms_scan" and _cms_result_indicates_wordpress(result):
                        auto_target = args.get("target", "")
                        auto_host = _normalize_web_target(auto_target)
                        if auto_host and auto_host not in auto_wpscan_hosts:
                            auto_wpscan_hosts.add(auto_host)
                            auto_tool_id = f"{tc.get('id', '')}:auto_wpscan"
                            auto_args = {
                                "target": auto_target,
                                "scan_profile": "aggressive_enum",
                                "timeout": 420,
                                "auto_triggered": True,
                            }
                            emit("tool_call", {"name": "run_wpscan", "args": auto_args, "id": auto_tool_id})

                            def auto_wpscan_stream_callback(event_type, data):
                                emit(event_type, {**data, "tool_id": auto_tool_id})

                            try:
                                auto_result = run_wpscan(
                                    auto_target,
                                    "aggressive_enum",
                                    420,
                                    stream_callback=auto_wpscan_stream_callback,
                                    artifact_session=session_id,
                                )
                            except Exception as auto_exc:
                                auto_result = f"ERROR running run_wpscan: {str(auto_exc)}"

                            if _is_stop_requested(session_id, worker_token):
                                stopped = True
                                break
                            emit("tool_result", {"name": "run_wpscan", "result": auto_result, "id": auto_tool_id})
                            messages.append({
                                "role": "system",
                                "content": (
                                    "Automatic follow-up evidence: WordPress was detected by cms_scan, "
                                    "so run_wpscan was executed in aggressive_enum profile.\n\n"
                                    f"{_clip_text(auto_result, 12000)}"
                                ),
                            })
                if stopped:
                    break
            else:
                if _is_stop_requested(session_id, worker_token):
                    stopped = True
                    break
                if mode == "deep":
                    if not severe_path_executed:
                        _run_severe_path_phase()
                    truth_result = _run_truth_verification_for_report(
                        session_id,
                        user_input,
                        full_content or "",
                        verification_policy=verification_policy,
                        primary_target=primary_target or user_input,
                    )
                    ready_count = int((truth_result.get("summary") or {}).get("ready_count", 0) or 0)

                    if ready_count == 0 and not extra_verification_used:
                        extra_verification_used = True
                        emit("thinking_done", {
                            "text": (
                                "No exploit-proven HIGH/CRITICAL findings were verified yet. "
                                "Running one bounded extra verification pass now."
                            )
                        })
                        messages.append({"role": "assistant", "content": full_content or ""})
                        messages.append({"role": "system", "content": EXTRA_VERIFICATION_PROMPT})
                        messages.append({
                            "role": "user",
                            "content": (
                                "Run one bounded extra verification pass focused on reproducible high-impact findings. "
                                "Then provide a final report that clearly separates exploit-proven findings from "
                                "unverified leads."
                            ),
                        })
                        continue

                    with sessions_lock:
                        s_meta = sessions.get(session_id) or {}
                        report_meta = {
                            "resolved_scope_hosts": list(s_meta.get("resolved_scope_hosts", []) or []),
                            "coverage_degraded": list(s_meta.get("coverage_degraded", []) or []),
                            "severe_path_status": str(s_meta.get("severe_path_status", "none") or "none"),
                            "auth_context": _normalize_auth_context(s_meta.get("auth_context", {})),
                        }

                    gated_report = _build_gated_final_report(
                        truth_result,
                        query=user_input,
                        mode=mode,
                        events=_session_events_snapshot(session_id),
                        extra_pass_used=extra_verification_used,
                        session_meta=report_meta,
                    )
                    emit("final_report", {"text": gated_report})
                    emit("final_truth_report", {
                        "markdown": truth_result.get("markdown", ""),
                        "summary": truth_result.get("summary", {}),
                        "findings": truth_result.get("findings", []),
                    })
                else:
                    final_text = full_content or ""
                    if _looks_like_web_scan_query(user_input):
                        final_text = _ensure_scope_note(final_text)
                    emit("final_report", {"text": final_text})
                emit("done", {})
                break
        else:
            if not stopped:
                emit("error", {"message": "Reached max iterations"})

    except Exception as fatal_exc:
        emit("error", {
            "message": _friendly_runtime_error_message(fatal_exc)
        })
    finally:
        with sessions_lock:
            s = sessions.get(session_id)
            can_emit_done = bool(
                s
                and int(s.get("worker_token", 0) or 0) == int(worker_token)
                and (not s.get("events") or s["events"][-1].get("type") != "done")
            )
        if can_emit_done:
            emit("done", {})
        finalize_session()


# Start recovery bootstrap and watchdog monitor once worker/runtime code is loaded.
_bootstrap_running_sessions()
_ensure_worker_monitor()


# ---------- API routes ----------

@app.post("/api/chats")
async def create_chat(request: Request):
    """Create a new chat session and start the agent."""
    body = await request.json()
    query = body.get("query", "").strip()
    mode = (body.get("mode", "auto") or "auto").strip().lower()
    verification_policy = _normalize_verification_policy(body.get("verification_policy"))
    auth_context = _normalize_auth_context(body.get("auth_context", {}))
    if mode not in {"auto", "ask", "scan", "normal", "light", "deep"}:
        mode = "auto"
    effective_mode = _coerce_execution_mode(query, mode)
    if not query:
        return JSONResponse({"error": "query is required"}, status_code=400)

    session_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()

    with sessions_lock:
        sessions[session_id] = {
            "id": session_id,
            "query": query,
            "mode": effective_mode,
            "requested_mode": mode,
            "status": "running",
            "stop_requested": False,
            "status_check_timeout_streak": 0,
            "status_check_paused": False,
            "worker_recovery_attempts": 0,
            "worker_recovery_limit": WORKER_RECOVERY_LIMIT,
            "recovery_state": "none",
            "last_progress_at": now,
            "last_recovery_at": "",
            "worker_token": 0,
            "resolved_scope_hosts": [],
            "coverage_degraded": [],
            "severe_path_status": "none",
            "verification_policy": verification_policy,
            "auth_context": auth_context,
            "created_at": now,
            "finished_at": "",
            "events": [],
            "runtime": _default_runtime_state(),
        }

    # Save immediately so it appears in the list
    save_session(session_id)

    # Start agent in background thread
    _spawn_worker_for_session(session_id, recovering=False, reason="")

    return {
        "id": session_id,
        "query": query,
        "mode": effective_mode,
        "requested_mode": mode,
        "status": "running",
        "created_at": now,
        "recovery_state": "none",
        "recovery_attempts": 0,
        "last_progress_at": now,
        "resolved_scope_hosts": [],
        "coverage_degraded_count": 0,
        "severe_path_status": "none",
        "verification_policy": verification_policy,
        "auth_context": {
            "enabled": auth_context.get("enabled", False),
            "scope": auth_context.get("scope", "all"),
            "allowed_hosts": auth_context.get("allowed_hosts", []),
            "profile": auth_context.get("profile", "default"),
        },
    }


@app.post("/api/chats/{session_id}/ask")
async def ask_in_chat(session_id: str, request: Request):
    """Ask a follow-up question in the same chat context (no new thread)."""
    body = await request.json()
    question = (body.get("question", "") or "").strip()
    if not question:
        return JSONResponse({"error": "question is required"}, status_code=400)

    now = datetime.now().isoformat()
    ask_event = {"type": "ask_question", "text": question, "created_at": now}

    in_memory = False
    with sessions_lock:
        s = sessions.get(session_id)
        if s:
            s["status"] = "running"
            s["events"].append(ask_event)
            session_data = {
                "id": s["id"],
                "query": s["query"],
                "mode": s.get("mode", "auto"),
                "requested_mode": s.get("requested_mode", s.get("mode", "auto")),
                "status": s["status"],
                "created_at": s["created_at"],
                "finished_at": s.get("finished_at", ""),
                "events": list(s["events"]),
            }
            in_memory = True
        else:
            session_data = load_session(session_id)

    if not session_data:
        return JSONResponse({"error": "chat not found"}, status_code=404)

    if not in_memory:
        session_data["status"] = "running"
        session_data.setdefault("events", []).append(ask_event)
        filepath = _resolve_session_filepath(session_id)
        with open(filepath, "w") as f:
            json.dump(session_data, f)
    else:
        save_session(session_id)

    answer = run_followup_ask(session_data, question)

    answer_event = {"type": "ask_answer", "text": answer, "created_at": datetime.now().isoformat()}
    if in_memory:
        with sessions_lock:
            s = sessions.get(session_id)
            if s:
                s["events"].append(answer_event)
                s["status"] = "done"
                s["finished_at"] = datetime.now().isoformat()
        save_session(session_id)
    else:
        session_data.setdefault("events", []).append(answer_event)
        session_data["status"] = "done"
        session_data["finished_at"] = datetime.now().isoformat()
        filepath = _resolve_session_filepath(session_id)
        with open(filepath, "w") as f:
            json.dump(session_data, f)

    return {"answer": answer}


@app.get("/api/chats")
async def list_chats():
    """List all chat sessions (from disk + in-memory)."""
    disk_sessions = load_all_sessions()
    # Merge in-memory running sessions
    with sessions_lock:
        for sid, s in sessions.items():
            if not any(d["id"] == sid for d in disk_sessions):
                disk_sessions.append({
                    "id": s["id"],
                    "query": s["query"],
                    "mode": s.get("mode", "auto"),
                    "requested_mode": s.get("requested_mode", s.get("mode", "auto")),
                    "status": s["status"],
                    "created_at": s["created_at"],
                    "finished_at": s.get("finished_at", ""),
                    "recovery_state": s.get("recovery_state", "none"),
                    "recovery_attempts": int(s.get("worker_recovery_attempts", 0) or 0),
                    "last_progress_at": s.get("last_progress_at", s.get("created_at", "")),
                    "severe_path_status": s.get("severe_path_status", "none"),
                    "verification_policy": _normalize_verification_policy(s.get("verification_policy")),
                    "resolved_scope_hosts": list(s.get("resolved_scope_hosts", []) or []),
                    "coverage_degraded_count": len(list(s.get("coverage_degraded", []) or [])),
                })
            else:
                # Update status from memory (may be more current)
                for d in disk_sessions:
                    if d["id"] == sid:
                        d["status"] = s["status"]
                        d["mode"] = s.get("mode", d.get("mode", "auto"))
                        d["requested_mode"] = s.get("requested_mode", d.get("requested_mode", d.get("mode", "auto")))
                        d["recovery_state"] = s.get("recovery_state", d.get("recovery_state", "none"))
                        d["recovery_attempts"] = int(s.get("worker_recovery_attempts", d.get("recovery_attempts", 0)) or 0)
                        d["last_progress_at"] = s.get("last_progress_at", d.get("last_progress_at", s.get("created_at", "")))
                        d["severe_path_status"] = s.get("severe_path_status", d.get("severe_path_status", "none"))
                        d["verification_policy"] = _normalize_verification_policy(
                            s.get("verification_policy", d.get("verification_policy", DEFAULT_VERIFICATION_POLICY))
                        )
                        d["resolved_scope_hosts"] = list(s.get("resolved_scope_hosts", d.get("resolved_scope_hosts", [])) or [])
                        d["coverage_degraded_count"] = len(list(s.get("coverage_degraded", []) or []))
                        break
    # Sort by created_at desc
    for d in disk_sessions:
        d["verification_policy"] = _normalize_verification_policy(d.get("verification_policy"))
    disk_sessions.sort(key=lambda x: x["created_at"], reverse=True)
    return disk_sessions


@app.get("/api/chats/{session_id}")
async def get_chat(session_id: str):
    """Get full chat data including all events."""
    # Check in-memory first
    with sessions_lock:
        s = sessions.get(session_id)
        if s:
            return {
                "id": s["id"],
                "query": s["query"],
                "mode": s.get("mode", "auto"),
                "requested_mode": s.get("requested_mode", s.get("mode", "auto")),
                "status": s["status"],
                "created_at": s["created_at"],
                "finished_at": s.get("finished_at", ""),
                "recovery_state": s.get("recovery_state", "none"),
                "recovery_attempts": int(s.get("worker_recovery_attempts", 0) or 0),
                "last_progress_at": s.get("last_progress_at", s.get("created_at", "")),
                "severe_path_status": s.get("severe_path_status", "none"),
                "verification_policy": _normalize_verification_policy(s.get("verification_policy")),
                "resolved_scope_hosts": list(s.get("resolved_scope_hosts", []) or []),
                "coverage_degraded": list(s.get("coverage_degraded", []) or []),
                "auth_context": _normalize_auth_context(s.get("auth_context", {})),
                "events": list(s["events"]),
            }
    # Fall back to disk
    data = load_session(session_id)
    if data:
        data.setdefault("requested_mode", data.get("mode", "auto"))
        data["verification_policy"] = _normalize_verification_policy(data.get("verification_policy"))
        return data
    return JSONResponse({"error": "not found"}, status_code=404)


@app.delete("/api/chats/{session_id}")
async def delete_chat(session_id: str):
    """Delete a chat session."""
    with sessions_lock:
        sessions.pop(session_id, None)
    removed = set()
    for session_dir in _session_storage_dirs():
        filepath = session_dir / f"{session_id}.json"
        if filepath.exists():
            filepath.unlink()
            removed.add(str(filepath))
    return {"ok": True}


@app.post("/api/chats/{session_id}/stop")
async def stop_chat(session_id: str):
    """Stop an in-progress chat run."""
    ok, state = _mark_session_stopped(session_id, reason="Stopped by user.")
    if not ok:
        data = load_session(session_id)
        if not data:
            return JSONResponse({"error": "not found"}, status_code=404)
        return {"ok": True, "status": data.get("status", "done"), "state": "already_persisted"}

    with sessions_lock:
        s = sessions.get(session_id)
        status = s.get("status", "done") if s else "done"

    return {"ok": True, "status": status, "state": state}


@app.post("/api/chats/{session_id}/status_check")
async def status_check_chat(session_id: str, request: Request):
    """Run an automatic watchdog status check for stalled runs without ending the session."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    default_question = (
        "No progress events have appeared for over 200 seconds. "
        "Check what is likely happening right now, identify the likely blocker, "
        "and give the immediate next action."
    )
    question = (body.get("question", "") or "").strip() or default_question

    now = datetime.now().isoformat()
    check_event = {"type": "status_check", "text": question, "created_at": now}

    in_memory = False
    original_status = "done"
    timeout_streak = 0
    paused = False
    with sessions_lock:
        s = sessions.get(session_id)
        if s:
            in_memory = True
            original_status = s.get("status", "done")
            timeout_streak = int(s.get("status_check_timeout_streak", 0) or 0)
            paused = bool(s.get("status_check_paused", False))
            if original_status != "running":
                return {
                    "answer": f"Session is not running (status: {original_status}).",
                    "status": original_status,
                    "skipped": True,
                    "paused": paused,
                    "timeout_streak": timeout_streak,
                    "reason": "not_running",
                    "source": "fallback",
                }
            if paused:
                return {
                    "answer": (
                        "Auto status checks are paused after repeated timeouts. "
                        "Immediate next action: wait for real progress events, or stop and retry if still stalled."
                    ),
                    "status": original_status,
                    "skipped": True,
                    "paused": True,
                    "timeout_streak": timeout_streak,
                    "reason": "paused",
                    "source": "fallback",
                }
            s["events"].append(check_event)
            session_data = {
                "id": s["id"],
                "query": s["query"],
                "mode": s.get("mode", "auto"),
                "requested_mode": s.get("requested_mode", s.get("mode", "auto")),
                "status": s.get("status", "running"),
                "created_at": s["created_at"],
                "finished_at": s.get("finished_at", ""),
                "status_check_timeout_streak": timeout_streak,
                "status_check_paused": paused,
                "events": list(s["events"]),
            }
        else:
            session_data = load_session(session_id)

    if not session_data:
        return JSONResponse({"error": "chat not found"}, status_code=404)

    if not in_memory:
        original_status = session_data.get("status", "done")
        timeout_streak = int(session_data.get("status_check_timeout_streak", 0) or 0)
        paused = bool(session_data.get("status_check_paused", False))
        if original_status != "running":
            return {
                "answer": f"Session is not running (status: {original_status}).",
                "status": original_status,
                "skipped": True,
                "paused": paused,
                "timeout_streak": timeout_streak,
                "reason": "not_running",
                "source": "fallback",
            }
        if paused:
            return {
                "answer": (
                    "Auto status checks are paused after repeated timeouts. "
                    "Immediate next action: wait for real progress events, or stop and retry if still stalled."
                ),
                "status": original_status,
                "skipped": True,
                "paused": True,
                "timeout_streak": timeout_streak,
                "reason": "paused",
                "source": "fallback",
            }
        session_data.setdefault("events", []).append(check_event)
        filepath = _resolve_session_filepath(session_id)
        with open(filepath, "w") as f:
            json.dump(session_data, f)
    else:
        save_session(session_id)

    check = run_status_check_ask(session_data, question)
    answer = str(check.get("text", "") or "(No status update generated)")
    source = str(check.get("source", "fallback") or "fallback")
    reason = str(check.get("reason", "llm_error") or "llm_error")
    timed_out = bool(check.get("timed_out", False))

    if timed_out:
        timeout_streak += 1
    else:
        timeout_streak = 0

    paused = timeout_streak >= STATUS_CHECK_TIMEOUT_PAUSE_THRESHOLD
    if paused and timed_out:
        answer = (
            f"Auto status checks paused after {timeout_streak} consecutive timeouts. "
            "Run is still active. Immediate next action: wait for real progress events, "
            "or stop and retry if the run remains stalled."
        )
        reason = "paused_after_timeouts"
        source = "fallback"

    answer_event = {
        "type": "status_check_result",
        "text": answer,
        "created_at": datetime.now().isoformat(),
        "paused": paused,
        "timeout_streak": timeout_streak,
        "reason": reason,
        "source": source,
    }

    if in_memory:
        with sessions_lock:
            s = sessions.get(session_id)
            if s:
                s["status_check_timeout_streak"] = timeout_streak
                s["status_check_paused"] = paused
                s["events"].append(answer_event)
        save_session(session_id)
    else:
        session_data["status_check_timeout_streak"] = timeout_streak
        session_data["status_check_paused"] = paused
        session_data.setdefault("events", []).append(answer_event)
        filepath = _resolve_session_filepath(session_id)
        with open(filepath, "w") as f:
            json.dump(session_data, f)

    return {
        "answer": answer,
        "status": original_status,
        "paused": paused,
        "timeout_streak": timeout_streak,
        "reason": reason,
        "source": source,
    }


@app.get("/api/chats/{session_id}/stream")
async def stream_chat(session_id: str):
    """SSE stream for a running chat. Sends all past events then streams new ones."""
    def generate():
        cursor = 0
        while True:
            with sessions_lock:
                s = sessions.get(session_id)
                if not s:
                    # Session not in memory — may be finished on disk
                    break
                events = s["events"][cursor:]
                status = s["status"]

            for ev in events:
                yield sse_event(ev["type"], {k: v for k, v in ev.items() if k != "type"})
                cursor += 1

            if status == "done":
                break
            time.sleep(0.1)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "model": get_model()}


@app.post("/api/chats/{session_id}/verify_truth")
async def verify_truth(session_id: str):
    """Run deterministic verification on a finished report and return bounty-readiness verdict."""
    # Pull session from memory first (latest), then disk
    with sessions_lock:
        s = sessions.get(session_id)
        session_data = None
        if s:
            session_data = {
                "id": s["id"],
                "query": s["query"],
                "status": s["status"],
                "verification_policy": _normalize_verification_policy(s.get("verification_policy")),
                "created_at": s["created_at"],
                "finished_at": s.get("finished_at", ""),
                "events": list(s["events"]),
            }

    if not session_data:
        session_data = load_session(session_id)
    if not session_data:
        return JSONResponse({"error": "chat not found"}, status_code=404)

    events = session_data.get("events", [])
    report_text, tool_outputs = _extract_verification_inputs(events)

    if not report_text and not tool_outputs:
        return JSONResponse({"error": "No report data found for verification"}, status_code=400)

    result = verify_bug_bounty_truth(
        chat_query=session_data.get("query", ""),
        report_text=report_text,
        tool_outputs=tool_outputs,
        verification_policy=_normalize_verification_policy(session_data.get("verification_policy")),
        primary_target=_extract_primary_target(session_data.get("query", "")),
    )

    # Persist as an event so it survives refresh/reopen.
    truth_event = {
        "type": "final_truth_report",
        "markdown": result.get("markdown", ""),
        "summary": result.get("summary", {}),
        "findings": result.get("findings", []),
    }
    in_memory = False
    with sessions_lock:
        s = sessions.get(session_id)
        if s is not None:
            s["events"].append(truth_event)
            in_memory = True
    if in_memory:
        save_session(session_id)
    else:
        session_data.setdefault("events", []).append(truth_event)
        filepath = _resolve_session_filepath(session_id)
        with open(filepath, "w") as f:
            json.dump(session_data, f)

    return result


# ---------- Serve frontend ----------

@app.get("/")
async def root():
    return FileResponse(
        "web/index.html",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/{path:path}")
async def static_files(path: str):
    file_path = f"web/{path}"
    if os.path.exists(file_path):
        return FileResponse(
            file_path,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    return FileResponse(
        "web/index.html",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000") or "8000")
    uvicorn.run(app, host="0.0.0.0", port=port)
