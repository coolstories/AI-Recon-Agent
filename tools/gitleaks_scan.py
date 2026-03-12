from __future__ import annotations

import json
from pathlib import Path

from tools._cli_runner import (
    create_artifact_dir,
    emit,
    find_binary_or_auto_install,
    run_command,
    write_text,
)


def run_gitleaks(
    path: str,
    timeout: int = 300,
    stream_callback=None,
    artifact_session: str | None = None,
):
    target_path = Path(path).expanduser()
    if not target_path.exists():
        return f"ERROR: path not found: {target_path}"

    binary_name, _, missing_error = find_binary_or_auto_install(
        ["gitleaks"],
        tool_name="GitLeaks",
        stream_callback=stream_callback,
        install_timeout=max(120, int(timeout)),
    )
    if not binary_name:
        return missing_error

    artifact_dir = create_artifact_dir("gitleaks", artifact_session)
    report_file = artifact_dir / "gitleaks_report.json"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [
        binary_name,
        "detect",
        "--source",
        str(target_path),
        "--report-format",
        "json",
        "--report-path",
        str(report_file),
        "--no-banner",
        "--redact",
    ]
    emit(stream_callback, "tool_info", {
        "message": f"Running GitLeaks on {target_path}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "gitleaks",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target": str(target_path),
    }, indent=2))

    findings = 0
    if report_file.exists():
        try:
            payload = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(payload, list):
                findings = len(payload)
        except json.JSONDecodeError:
            findings = 0

    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== GitLeaks Credential Leak Scan ===\n"
        f"Target: {target_path}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Findings: {findings}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_gitleaks",
        "description": "Run GitLeaks on a local path to detect leaked credentials/secrets in source code.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Local filesystem path to scan",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 300",
                    "default": 300,
                },
            },
            "required": ["path"],
        },
    },
}
