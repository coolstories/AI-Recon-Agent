from __future__ import annotations

import json
from urllib.parse import urlparse

from tools._cli_runner import (
    build_missing_binary_error,
    create_artifact_dir,
    emit,
    find_binary,
    run_command,
    write_text,
)


def _normalize_host(target: str):
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return raw.split("/")[0]
    parsed = urlparse(raw)
    return (parsed.netloc or parsed.path).split("/")[0]


def run_naabu(
    target: str,
    scan_type: str = "top100",
    rate: int = 1000,
    timeout: int = 180,
    stream_callback=None,
    artifact_session: str | None = None,
):
    host = _normalize_host(target)
    if not host:
        return "ERROR: target is required"

    binary_name, _ = find_binary(["naabu"])
    if not binary_name:
        return build_missing_binary_error(["naabu"], "Naabu")

    profile = (scan_type or "top100").strip().lower()
    if profile not in {"top100", "top1000", "full"}:
        profile = "top100"

    artifact_dir = create_artifact_dir("naabu", artifact_session)
    ports_file = artifact_dir / "open_ports.txt"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [binary_name, "-host", host, "-rate", str(max(10, int(rate))), "-silent"]
    if profile == "top100":
        cmd.extend(["-top-ports", "100"])
    elif profile == "top1000":
        cmd.extend(["-top-ports", "1000"])
    else:
        cmd.extend(["-p", "-"])

    emit(stream_callback, "tool_info", {
        "message": f"Running Naabu ({profile}) against {host}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "naabu",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target": host,
        "scan_type": profile,
        "rate": rate,
    }, indent=2))

    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    unique_ports = sorted(set(lines))
    write_text(ports_file, "\n".join(unique_ports))

    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== Naabu Port Scan ===\n"
        f"Target: {host}\n"
        f"Profile: {profile}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Open ports discovered: {len(unique_ports)}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_naabu",
        "description": "Run Naabu fast port scanning against a host/domain. Useful for quick network attack surface discovery.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host/domain/IP",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["top100", "top1000", "full"],
                    "description": "Port coverage profile",
                    "default": "top100",
                },
                "rate": {
                    "type": "integer",
                    "description": "Packets/requests rate. Default: 1000",
                    "default": 1000,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 180",
                    "default": 180,
                },
            },
            "required": ["target"],
        },
    },
}
