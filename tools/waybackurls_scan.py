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
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return raw.split("/")[0]
    parsed = urlparse(raw)
    return parsed.netloc or parsed.path


def run_waybackurls(
    target: str,
    timeout: int = 120,
    stream_callback=None,
    artifact_session: str | None = None,
):
    norm_target = _normalize_target(target)
    if not norm_target:
        return "ERROR: target is required"

    binary_name, _, missing_error = find_binary_or_auto_install(
        ["waybackurls"],
        tool_name="Waybackurls",
        stream_callback=stream_callback,
        install_timeout=max(90, int(timeout)),
    )
    if not binary_name:
        return missing_error

    artifact_dir = create_artifact_dir("waybackurls", artifact_session)
    endpoints_file = artifact_dir / "endpoints.txt"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [binary_name, norm_target]
    emit(stream_callback, "tool_info", {
        "message": f"Running Waybackurls for {norm_target}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "waybackurls",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target": norm_target,
    }, indent=2))

    urls = sorted(set(line.strip() for line in result["stdout"].splitlines() if line.strip()))
    write_text(endpoints_file, "\n".join(urls))

    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== Waybackurls Historical Endpoint Discovery ===\n"
        f"Target: {norm_target}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Unique historical URLs: {len(urls)}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_waybackurls",
        "description": "Run waybackurls to discover historical endpoints for a target domain from web archives.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain/host/url",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 120",
                    "default": 120,
                },
            },
            "required": ["target"],
        },
    },
}
