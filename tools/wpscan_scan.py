from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from tools._cli_runner import (
    build_missing_binary_error,
    create_artifact_dir,
    emit,
    find_binary,
    run_command,
    write_text,
)


def _normalize_target(target: str):
    value = (target or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"https://{value}"


def _host_label(target: str):
    value = _normalize_target(target)
    if not value:
        return ""
    parsed = urlparse(value)
    host = (parsed.netloc or parsed.path or "").strip()
    return host or value


def _read_env_token_from_file():
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return ""
    try:
        for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key not in {"WPSCAN_API_TOKEN", "WPSCAN_API_KEY"}:
                continue
            token = value.strip().strip('"').strip("'")
            if token:
                return token
    except Exception:
        return ""
    return ""


def _get_wpscan_token():
    token = (os.environ.get("WPSCAN_API_TOKEN") or "").strip()
    if token:
        return token
    token = (os.environ.get("WPSCAN_API_KEY") or "").strip()
    if token:
        return token
    return _read_env_token_from_file()


def _count_vulns(item):
    if not isinstance(item, dict):
        return 0
    vulns = item.get("vulnerabilities")
    if isinstance(vulns, list):
        return len(vulns)
    return 0


def _summarize_report(report_path: Path):
    if not report_path.exists():
        return {
            "loaded": False,
            "is_wp": False,
            "core_version": "unknown",
            "core_status": "unknown",
            "core_vulns": 0,
            "plugin_count": 0,
            "plugin_vulns": 0,
            "theme_count": 0,
            "theme_vulns": 0,
            "user_count": 0,
            "interesting_count": 0,
            "vuln_api_plan": "unknown",
            "vuln_api_requests": 0,
        }

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {
            "loaded": False,
            "is_wp": False,
            "core_version": "unknown",
            "core_status": "unknown",
            "core_vulns": 0,
            "plugin_count": 0,
            "plugin_vulns": 0,
            "theme_count": 0,
            "theme_vulns": 0,
            "user_count": 0,
            "interesting_count": 0,
            "vuln_api_plan": "unknown",
            "vuln_api_requests": 0,
        }

    if not isinstance(payload, dict):
        return {
            "loaded": False,
            "is_wp": False,
            "core_version": "unknown",
            "core_status": "unknown",
            "core_vulns": 0,
            "plugin_count": 0,
            "plugin_vulns": 0,
            "theme_count": 0,
            "theme_vulns": 0,
            "user_count": 0,
            "interesting_count": 0,
            "vuln_api_plan": "unknown",
            "vuln_api_requests": 0,
        }

    version = payload.get("version") if isinstance(payload.get("version"), dict) else {}
    core_version = str(version.get("number", "unknown"))
    core_status = str(version.get("status", "unknown"))
    core_vulns = _count_vulns(version)

    plugins = payload.get("plugins") if isinstance(payload.get("plugins"), dict) else {}
    plugin_count = len(plugins)
    plugin_vulns = sum(_count_vulns(v) for v in plugins.values() if isinstance(v, dict))

    themes = payload.get("themes") if isinstance(payload.get("themes"), dict) else {}
    theme_count = len(themes)
    theme_vulns = sum(_count_vulns(v) for v in themes.values() if isinstance(v, dict))

    main_theme = payload.get("main_theme") if isinstance(payload.get("main_theme"), dict) else {}
    if main_theme and not themes:
        theme_count = 1
        theme_vulns = _count_vulns(main_theme)

    users = payload.get("users")
    if isinstance(users, dict):
        user_count = len(users)
    elif isinstance(users, list):
        user_count = len(users)
    else:
        user_count = 0

    interesting = payload.get("interesting_findings") if isinstance(payload.get("interesting_findings"), list) else []
    vuln_api = payload.get("vuln_api") if isinstance(payload.get("vuln_api"), dict) else {}

    is_wp = any([
        bool(version),
        bool(plugins),
        bool(themes),
        bool(main_theme),
        user_count > 0,
        len(interesting) > 0,
    ])

    return {
        "loaded": True,
        "is_wp": is_wp,
        "core_version": core_version,
        "core_status": core_status,
        "core_vulns": core_vulns,
        "plugin_count": plugin_count,
        "plugin_vulns": plugin_vulns,
        "theme_count": theme_count,
        "theme_vulns": theme_vulns,
        "user_count": user_count,
        "interesting_count": len(interesting),
        "vuln_api_plan": str(vuln_api.get("plan", "unknown")),
        "vuln_api_requests": int(vuln_api.get("requests_done_during_scan", 0) or 0),
    }


def _looks_like_non_wordpress(stdout_text: str, stderr_text: str):
    blob = f"{stdout_text}\n{stderr_text}".lower()
    checks = (
        "does not seem to be running wordpress",
        "target is not running wordpress",
        "not running wordpress",
        "scan aborted",
    )
    return any(marker in blob for marker in checks)


def run_wpscan(
    target: str,
    scan_profile: str = "aggressive_enum",
    timeout: int = 420,
    stream_callback=None,
    artifact_session: str | None = None,
):
    normalized = _normalize_target(target)
    if not normalized:
        return "ERROR: target is required"

    profile = (scan_profile or "aggressive_enum").strip().lower()
    if profile != "aggressive_enum":
        profile = "aggressive_enum"

    binary_name, _ = find_binary(["wpscan"])
    if not binary_name:
        return build_missing_binary_error(["wpscan"], "WPScan")

    token = _get_wpscan_token()
    env_patch = {}
    if token:
        env_patch["WPSCAN_API_TOKEN"] = token

    artifact_dir = create_artifact_dir("wpscan", artifact_session)
    report_file = artifact_dir / "report.json"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [
        binary_name,
        "--url",
        normalized,
        "--format",
        "json",
        "--output",
        str(report_file),
        "--random-user-agent",
        "--enumerate",
        "vp,vt,tt,cb,dbe,u,m",
        "--plugins-detection",
        "aggressive",
    ]

    token_mode = "env" if token else "none"
    emit(stream_callback, "tool_info", {
        "message": f"Running WPScan ({profile}) on {_host_label(normalized)} [token: {token_mode}]",
    })

    result = run_command(
        cmd,
        timeout=timeout,
        stream_callback=stream_callback,
        env=env_patch or None,
    )

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "wpscan",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target": normalized,
        "host": _host_label(normalized),
        "scan_profile": profile,
        "token_mode": token_mode,
    }, indent=2))

    summary = _summarize_report(report_file)
    non_wp = _looks_like_non_wordpress(result["stdout"], result["stderr"])

    if non_wp and not summary["is_wp"]:
        return (
            "=== WPScan WordPress Assessment ===\n"
            f"Target: {normalized}\n"
            f"Profile: {profile}\n"
            f"Status: completed in {result['elapsed']}s\n"
            "WordPress detected: no\n"
            "Result: Target does not appear to run WordPress (or scan aborted before WP fingerprint confirmation).\n"
            f"Artifacts: {artifact_dir}"
        )

    status = "timeout" if result["timed_out"] else "completed"
    lines = [
        "=== WPScan WordPress Assessment ===",
        f"Target: {normalized}",
        f"Profile: {profile}",
        f"Status: {status} in {result['elapsed']}s",
        f"WordPress detected: {'yes' if summary['is_wp'] else 'unknown'}",
        f"Core version: {summary['core_version']} ({summary['core_status']})",
        f"Core vulnerability entries: {summary['core_vulns']}",
        f"Plugins discovered: {summary['plugin_count']} (vuln entries: {summary['plugin_vulns']})",
        f"Themes discovered: {summary['theme_count']} (vuln entries: {summary['theme_vulns']})",
        f"Users enumerated: {summary['user_count']}",
        f"Interesting findings: {summary['interesting_count']}",
        f"Vuln API plan: {summary['vuln_api_plan']} (requests: {summary['vuln_api_requests']})",
    ]

    if token_mode == "none":
        lines.append("Note: WPSCAN_API_TOKEN/WPSCAN_API_KEY not found; vulnerability DB enrichment may be limited.")

    lines.append(f"Artifacts: {artifact_dir}")
    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_wpscan",
        "description": "Run WPScan against a WordPress target for aggressive enumeration and vulnerability intelligence without brute-force login attempts.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or host",
                },
                "scan_profile": {
                    "type": "string",
                    "enum": ["aggressive_enum"],
                    "description": "WPScan profile. Uses aggressive plugin detection and broad safe enumeration.",
                    "default": "aggressive_enum",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 420",
                    "default": 420,
                },
            },
            "required": ["target"],
        },
    },
}
