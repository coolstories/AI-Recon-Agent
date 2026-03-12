from __future__ import annotations

import json
from pathlib import Path

from tools._cli_runner import (
    build_missing_binary_error,
    create_artifact_dir,
    emit,
    find_binary,
    run_command,
    write_text,
)


def _count_json_lines(text: str):
    count = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("DetectorName"):
            count += 1
    return count


def run_trufflehog(
    path: str,
    scan_mode: str = "filesystem",
    timeout: int = 300,
    stream_callback=None,
    artifact_session: str | None = None,
):
    target_path = Path(path).expanduser()
    if not target_path.exists():
        return f"ERROR: path not found: {target_path}"

    mode = (scan_mode or "filesystem").strip().lower()
    if mode not in {"filesystem", "git"}:
        mode = "filesystem"

    binary_name, _ = find_binary(["trufflehog"])
    if not binary_name:
        return build_missing_binary_error(["trufflehog"], "TruffleHog")

    artifact_dir = create_artifact_dir("trufflehog", artifact_session)
    stdout_file = artifact_dir / "stdout.jsonl"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [binary_name, mode, str(target_path), "--json"]
    emit(stream_callback, "tool_info", {
        "message": f"Running TruffleHog ({mode}) on {target_path}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "trufflehog",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "scan_mode": mode,
        "target": str(target_path),
    }, indent=2))

    findings = _count_json_lines(result["stdout"])
    status = "timeout" if result["timed_out"] else "completed"

    return (
        f"=== TruffleHog Secret Scan ===\n"
        f"Target: {target_path}\n"
        f"Mode: {mode}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Potential secrets found: {findings}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_trufflehog",
        "description": "Run TruffleHog for local secret detection on files or local git repos. On-demand only for credential/secret leak checks.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Local filesystem path to scan",
                },
                "scan_mode": {
                    "type": "string",
                    "enum": ["filesystem", "git"],
                    "description": "Scan mode. Use filesystem for code dirs, git for local git repos.",
                    "default": "filesystem",
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
