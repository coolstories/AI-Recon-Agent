from __future__ import annotations

import json
from urllib.parse import urlparse

from tools._cli_runner import (
    create_artifact_dir,
    emit,
    find_binary_or_auto_install,
    run_command,
    write_text,
)


def _normalize_target(target: str):
    value = (target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return value
    parsed = urlparse(value)
    return parsed.netloc or parsed.path


def _count_findings(report_path):
    if not report_path.exists():
        return 0
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0

    if not isinstance(payload, list):
        return 0

    count = 0
    for row in payload:
        if not isinstance(row, dict):
            continue
        severity = str(row.get("severity", "")).lower()
        finding = str(row.get("finding", "")).strip()
        if finding and severity not in {"ok", "info"}:
            count += 1
    return count


def _python_tls_fallback(target: str):
    try:
        from tools.web_request import check_ssl_cert
        return check_ssl_cert(target)
    except Exception as exc:
        return f"SSL CHECK ERROR: Python TLS fallback failed: {str(exc)}"


def run_testssl(
    target: str,
    mode: str = "fast",
    timeout: int = 420,
    stream_callback=None,
    artifact_session: str | None = None,
):
    norm_target = _normalize_target(target)
    if not norm_target:
        return "ERROR: target is required"

    binary_name, _, missing_error = find_binary_or_auto_install(
        ["testssl.sh", "testssl"],
        tool_name="testssl.sh",
        stream_callback=stream_callback,
        install_timeout=max(180, int(timeout)),
    )
    if not binary_name:
        emit(stream_callback, "coverage_degraded", {
            "tool": "run_testssl",
            "code": "BIN_MISSING",
            "message": "testssl.sh unavailable after auto-install attempt.",
            "fallback": "python-ssl-cert-probe",
        })
        fallback = _python_tls_fallback(norm_target)
        return (
            "COVERAGE DOWNGRADE: testssl.sh unavailable; executed Python TLS certificate fallback.\n"
            f"{missing_error}\n\n"
            f"{fallback}"
        )

    profile = (mode or "fast").strip().lower()
    if profile not in {"fast", "full"}:
        profile = "fast"

    artifact_dir = create_artifact_dir("testssl", artifact_session)
    report_file = artifact_dir / "testssl_report.json"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [binary_name]
    if profile == "fast":
        cmd.append("--fast")
    cmd.extend([
        "--warnings",
        "off",
        "--jsonfile",
        str(report_file),
        norm_target,
    ])

    emit(stream_callback, "tool_info", {
        "message": f"Running testssl.sh ({profile}) against {norm_target}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "testssl",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target": norm_target,
        "mode": profile,
    }, indent=2))

    findings = _count_findings(report_file)
    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== testssl.sh TLS/SSL Scan ===\n"
        f"Target: {norm_target}\n"
        f"Mode: {profile}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Potential TLS issues: {findings}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_testssl",
        "description": "Run testssl.sh against a host to analyze TLS/SSL protocol and cipher configuration.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or URL",
                },
                "mode": {
                    "type": "string",
                    "enum": ["fast", "full"],
                    "description": "Scan depth profile",
                    "default": "fast",
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
