from __future__ import annotations

import json
import os

from tools._cli_runner import (
    build_missing_binary_error,
    create_artifact_dir,
    emit,
    find_binary,
    run_command,
    write_text,
)


WORDLISTS = {
    "common": [
        "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "big": [
        "/opt/homebrew/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/wordlists/dirb/big.txt",
    ],
}

BUILTIN_WORDS = [
    "admin", "login", "api", "dashboard", "backup", ".git", ".env", "dev",
    "staging", "test", "internal", "debug", "graphql", "swagger", "docs",
    "uploads", "config", "wp-admin", "wp-login.php", "phpmyadmin", "console",
]


def _resolve_wordlist(wordlist: str, artifact_dir):
    if os.path.isfile(wordlist):
        return wordlist
    for candidate in WORDLISTS.get(wordlist, WORDLISTS["common"]):
        if os.path.isfile(candidate):
            return candidate
    fallback = artifact_dir / "wfuzz_builtin_wordlist.txt"
    write_text(fallback, "\n".join(BUILTIN_WORDS))
    return str(fallback)


def _count_results(report_file):
    if not report_file.exists():
        return 0
    try:
        payload = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0

    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            return len(payload["results"])
    return 0


def run_wfuzz(
    target_url: str,
    wordlist: str = "common",
    hide_codes: str = "404",
    threads: int = 20,
    timeout: int = 180,
    stream_callback=None,
    artifact_session: str | None = None,
):
    target = (target_url or "").strip()
    if not target:
        return "ERROR: target_url is required"
    if not target.startswith("http"):
        target = f"https://{target}"
    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"

    binary_name, _ = find_binary(["wfuzz"])
    if not binary_name:
        return build_missing_binary_error(["wfuzz"], "Wfuzz")

    artifact_dir = create_artifact_dir("wfuzz", artifact_session)
    report_file = artifact_dir / "wfuzz_report.json"
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    meta_file = artifact_dir / "meta.json"

    wl_path = _resolve_wordlist(wordlist, artifact_dir)
    emit(stream_callback, "tool_info", {
        "message": f"Running Wfuzz on {target} using {os.path.basename(wl_path)}",
    })

    cmd = [
        binary_name,
        "-w",
        wl_path,
        "-t",
        str(max(1, int(threads))),
        "--hc",
        hide_codes,
        "-f",
        f"{report_file},json",
        target,
    ]
    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)

    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "wfuzz",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target_url": target,
        "wordlist": wl_path,
        "hide_codes": hide_codes,
        "threads": threads,
    }, indent=2))

    hits = _count_results(report_file)
    status = "timeout" if result["timed_out"] else "completed"
    return (
        f"=== Wfuzz Web Fuzzing ===\n"
        f"Target: {target}\n"
        f"Hidden status codes: {hide_codes}\n"
        f"Status: {status} in {result['elapsed']}s\n"
        f"Responses matched: {hits}\n"
        f"Artifacts: {artifact_dir}"
    )


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_wfuzz",
        "description": "Run Wfuzz for web fuzzing against FUZZ-enabled target URLs.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target URL. If FUZZ is missing, /FUZZ is appended.",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist preset ('common', 'big') or absolute path",
                    "default": "common",
                },
                "hide_codes": {
                    "type": "string",
                    "description": "HTTP status codes to hide, comma-separated",
                    "default": "404",
                },
                "threads": {
                    "type": "integer",
                    "description": "Concurrent threads. Default: 20",
                    "default": 20,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max scan time in seconds. Default: 180",
                    "default": 180,
                },
            },
            "required": ["target_url"],
        },
    },
}
