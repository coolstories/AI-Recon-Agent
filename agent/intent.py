from __future__ import annotations

import re

SCAN_HINTS = (
    "scan", "security scan", "vulnerability scan", "audit", "pentest", "penetration test",
    "recon", "enumerate", "find vulnerabilities", "bug bounty", "exploit", "fuzz",
    "run nuclei", "run ffuf", "nmap", "attack chain", "normal scan",
)

DEEP_HINTS = (
    "deep scan", "full scan", "deep run", "all tools", "go all out", "comprehensive scan",
)

LIGHT_HINTS = (
    "light scan", "quick scan", "fast scan", "surface scan",
)

CAMERA_HINTS = (
    "camera", "cctv", "webcam", "live feed", "traffic cam", "surveillance",
)

QUESTION_PREFIXES = (
    "what", "why", "how", "when", "where", "who", "is", "are", "can", "could",
    "should", "does", "do",
)


def build_intent_system_message(user_input: str, mode_override: str | None = None) -> str:
    """Return a system instruction that forces question-vs-scan behavior."""
    if mode_override == "light":
        return (
            "INTENT MODE: LIGHT SCAN. The user explicitly selected light mode. "
            "Run a quick, low-noise security pass focused on high-signal checks only. "
            "Prefer lightweight recon and validation (e.g., DNS basics, SSL/cert check, header audit, "
            "quick exposed-path checks) and avoid heavy brute-force or long exploitation chains unless strong evidence appears. "
            "Report only findings directly backed by tool output."
        )
    if mode_override == "deep":
        return (
            "INTENT MODE: DEEP SCAN. The user explicitly selected deep mode. "
            "Run an aggressive, comprehensive scan workflow using broad tool coverage. "
            "Prefer full recon + discovery + exploitation verification chains over quick checks. "
            "Deep priority order for web targets: dns_recon, subdomain_enum(active), cloud_recon, "
            "port_scan(top1000), run_naabu(top1000), waf_fingerprint, cms_scan, run_wpscan(when WordPress is detected), js_analyze, "
            "supply_chain_scan, api_fuzz(full), graphql_exploit, param_mine, run_waybackurls, "
            "run_ffuf, run_arjun, run_wfuzz, run_nuclei, check_ssl, run_testssl, exploit_target(auto), "
            "oauth_test, cors_scan, header_audit, cache_poison, http_smuggle, race_test, lookup_cve, "
            "and run_aquatone on live hosts when possible. "
            "For local code/repo deep scans, include run_trufflehog, run_gitleaks, and run_semgrep. "
            "Evidence policy is strict: only report credentials, tokens, secrets, auth bypasses, XSS/SQLi/RCE, "
            "or other critical findings when directly supported by tool output. "
            "For high-impact findings, include concrete evidence snippets (affected URL/endpoint, parameter, payload, "
            "response indicator, and extracted credential/token values exactly as observed). "
            "If a tool is unavailable, report the exact tool error and continue with alternatives."
        )
    if mode_override in {"scan", "normal"}:
        return (
            "INTENT MODE: NORMAL SCAN. The user explicitly selected normal scan mode. "
            "Run tools as needed for verification and produce structured findings."
        )
    if mode_override == "ask":
        return (
            "INTENT MODE: QUESTION. The user explicitly selected ask mode. "
            "Answer directly first. Use tools only if strictly needed for accuracy. "
            "Do NOT launch multi-step recon chains or aggressive exploitation by default."
        )

    text = (user_input or "").strip().lower()
    asks_deep = any(h in text for h in DEEP_HINTS)
    asks_light = any(h in text for h in LIGHT_HINTS)
    asks_scan = any(h in text for h in SCAN_HINTS)
    asks_cameras = any(h in text for h in CAMERA_HINTS)
    looks_like_question = "?" in text or text.startswith(QUESTION_PREFIXES)
    has_url = bool(re.search(r"https?://|(?:\b[a-z0-9-]+\.)+[a-z]{2,}\b", text))

    if asks_deep:
        return build_intent_system_message(user_input, mode_override="deep")

    if asks_light:
        return build_intent_system_message(user_input, mode_override="light")

    if asks_scan or asks_cameras:
        return (
            "INTENT MODE: NORMAL SCAN. The user explicitly asked for scanning/recon/camera discovery. "
            "Run tools as needed for verification and produce structured findings."
        )

    if looks_like_question or has_url:
        return (
            "INTENT MODE: QUESTION. The user asked a normal question, NOT a scan request. "
            "Answer directly first. Use tools only if strictly needed for accuracy. "
            "Do NOT launch multi-step recon chains or aggressive exploitation by default."
        )

    return (
        "INTENT MODE: QUESTION by default. Unless the user explicitly asks for a scan/audit/pentest, "
        "respond as Q&A and avoid multi-tool scanning workflows."
    )
