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


def _normalize_targets(targets):
    if isinstance(targets, list):
        raw_items = targets
    else:
        raw_items = str(targets or "").replace(",", "\n").splitlines()
    cleaned = []
    for item in raw_items:
        value = item.strip()
        if not value:
            continue
        cleaned.append(value)
    return sorted(set(cleaned))


def run_aquatone(
    targets,
    timeout: int = 300,
    stream_callback=None,
    artifact_session: str | None = None,
):
    target_list = _normalize_targets(targets)
    if not target_list:
        return "ERROR: targets are required"

    binary_name, _ = find_binary(["aquatone"])
    if not binary_name:
        return build_missing_binary_error(["aquatone"], "Aquatone")

    artifact_dir = create_artifact_dir("aquatone", artifact_session)
    input_file = artifact_dir / "targets.txt"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    write_text(input_file, "\n".join(target_list) + "\n")
    cmd = [binary_name, "-out", str(artifact_dir)]
    emit(stream_callback, "tool_info", {
        "message": f"Running Aquatone visual recon for {len(target_list)} targets",
    })
    result = run_command(
        cmd,
        timeout=timeout,
        stream_callback=stream_callback,
        stdin_text="\n".join(target_list) + "\n",
    )

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])

    screenshots_dir = artifact_dir / "screenshots"
    screenshot_count = 0
    if screenshots_dir.exists():
        screenshot_count = len(list(screenshots_dir.glob("*.png")))

    report_path = artifact_dir / "aquatone_report.html"
    if not report_path.exists():
        alternate = artifact_dir / "aquatone_report.json"
        if alternate.exists():
            report_path = alternate

    write_text(meta_file, json.dumps({
        "tool": "aquatone",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "targets": target_list,
        "screenshot_count": screenshot_count,
        "report_path": str(report_path) if report_path.exists() else "",
    }, indent=2))

    status = "timeout" if result["timed_out"] else "completed"
    report_label = str(report_path) if report_path.exists() else "not generated"
    return (
        f"=== Aquatone Visual Recon ===\n"
        f"Targets: {len(target_list)}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Screenshots captured: {screenshot_count}\n"
        f"Report: {report_label}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_aquatone",
        "description": "Run Aquatone visual recon to capture screenshots and visual fingerprints for a list of targets.",
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "string",
                    "description": "Targets separated by commas or newlines",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 300",
                    "default": 300,
                },
            },
            "required": ["targets"],
        },
    },
}
