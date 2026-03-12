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


def run_semgrep(
    path: str,
    config: str = "auto",
    timeout: int = 600,
    stream_callback=None,
    artifact_session: str | None = None,
):
    target_path = Path(path).expanduser()
    if not target_path.exists():
        return f"ERROR: path not found: {target_path}"

    binary_name, _, missing_error = find_binary_or_auto_install(
        ["semgrep"],
        tool_name="Semgrep",
        stream_callback=stream_callback,
        install_timeout=max(180, int(timeout)),
    )
    if not binary_name:
        return missing_error

    artifact_dir = create_artifact_dir("semgrep", artifact_session)
    report_file = artifact_dir / "semgrep_report.json"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    config_value = (config or "auto").strip() or "auto"
    cmd = [
        binary_name,
        "scan",
        "--config",
        config_value,
        "--json",
        "--output",
        str(report_file),
        str(target_path),
    ]
    emit(stream_callback, "tool_info", {
        "message": f"Running Semgrep ({config_value}) on {target_path}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "semgrep",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target": str(target_path),
        "config": config_value,
    }, indent=2))

    findings = 0
    if report_file.exists():
        try:
            payload = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
            results = payload.get("results", []) if isinstance(payload, dict) else []
            findings = len(results)
        except json.JSONDecodeError:
            findings = 0

    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== Semgrep Static Security Scan ===\n"
        f"Target: {target_path}\n"
        f"Config: {config_value}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Findings: {findings}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_semgrep",
        "description": "Run Semgrep static code security analysis on a local path. Good for code-level vulnerability detection.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Local filesystem path to scan",
                },
                "config": {
                    "type": "string",
                    "description": "Semgrep rule config. Default: auto",
                    "default": "auto",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 600",
                    "default": 600,
                },
            },
            "required": ["path"],
        },
    },
}
