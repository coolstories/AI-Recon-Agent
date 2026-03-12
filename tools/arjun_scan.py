from __future__ import annotations

import json

from tools._cli_runner import (
    create_artifact_dir,
    emit,
    find_binary_or_auto_install,
    run_command,
    write_text,
)


def _count_arjun_params(report_file):
    if not report_file.exists():
        return 0
    try:
        payload = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0

    if isinstance(payload, dict):
        total = 0
        for value in payload.values():
            if isinstance(value, list):
                total += len(value)
        return total
    if isinstance(payload, list):
        return len(payload)
    return 0


def run_arjun(
    target_url: str,
    method: str = "GET",
    timeout: int = 240,
    stream_callback=None,
    artifact_session: str | None = None,
):
    target = (target_url or "").strip()
    if not target:
        return "ERROR: target_url is required"
    if not target.startswith("http"):
        target = f"https://{target}"

    binary_name, _, missing_error = find_binary_or_auto_install(
        ["arjun"],
        tool_name="Arjun",
        stream_callback=stream_callback,
        install_timeout=max(120, int(timeout)),
    )
    if not binary_name:
        return missing_error

    verb = (method or "GET").strip().upper()
    if verb not in {"GET", "POST"}:
        verb = "GET"

    artifact_dir = create_artifact_dir("arjun", artifact_session)
    report_file = artifact_dir / "arjun_report.json"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    cmd = [
        binary_name,
        "-u",
        target,
        "-m",
        verb,
        "-oJ",
        str(report_file),
        "--passive",
        "--disable-update-check",
    ]
    emit(stream_callback, "tool_info", {
        "message": f"Running Arjun parameter discovery ({verb}) on {target}",
    })
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "arjun",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target_url": target,
        "method": verb,
    }, indent=2))

    findings = _count_arjun_params(report_file)
    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== Arjun Hidden Parameter Discovery ===\n"
        f"Target: {target}\n"
        f"Method: {verb}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Candidate parameters: {findings}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_arjun",
        "description": "Run Arjun hidden parameter discovery against a target URL.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target URL (http/https)",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method for parameter probing",
                    "default": "GET",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 240",
                    "default": 240,
                },
            },
            "required": ["target_url"],
        },
    },
}
