from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable


INSTALL_HINTS = {
    "trufflehog": "Install: brew install trufflehog or go install github.com/trufflesecurity/trufflehog/v3@latest",
    "gitleaks": "Install: brew install gitleaks or go install github.com/gitleaks/gitleaks/v8@latest",
    "aquatone": "Install from release binary: https://github.com/michenriksen/aquatone/releases",
    "testssl.sh": "Install: brew install testssl or git clone https://github.com/testssl/testssl.sh",
    "testssl": "Install: brew install testssl or git clone https://github.com/testssl/testssl.sh",
    "naabu": "Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "waybackurls": "Install: go install github.com/tomnomnom/waybackurls@latest",
    "arjun": "Install: pip install arjun",
    "wfuzz": "Install: pip install wfuzz",
    "semgrep": "Install: pip install semgrep",
    "wpscan": "Install: brew install wpscanteam/tap/wpscan or gem install wpscan; Docker: docker run --rm wpscanteam/wpscan --help",
}


def emit(stream_callback, event_type: str, data: dict):
    if stream_callback:
        stream_callback(event_type, data)


def find_binary(candidates: Iterable[str]):
    for name in candidates:
        path = shutil.which(name)
        if path:
            return name, path
    return None, None


def build_missing_binary_error(candidates: Iterable[str], tool_name: str = ""):
    cands = list(candidates)
    preferred = cands[0] if cands else "unknown"
    hint = INSTALL_HINTS.get(preferred, "Install the required binary and ensure it is on PATH.")
    name_label = tool_name or preferred
    return (
        f"ERROR: {name_label} binary not found on PATH. Tried: {', '.join(cands)}.\n"
        f"{hint}\n"
        "You can also run: ./scripts/install_security_tools.sh"
    )


def sanitize_session_id(value: str | None):
    if not value:
        return "cli"
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip())
    return cleaned or "cli"


def create_artifact_dir(tool_name: str, artifact_session: str | None = None):
    project_root = Path(__file__).resolve().parents[1]
    session = sanitize_session_id(artifact_session)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    artifact_dir = project_root / "data" / "artifacts" / session / tool_name / ts
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def write_text(path: Path, content: str):
    path.write_text(content or "", encoding="utf-8", errors="replace")


def command_to_string(cmd: list[str]):
    return " ".join(shlex.quote(part) for part in cmd)


def run_command(
    cmd: list[str],
    timeout: int,
    stream_callback=None,
    cwd: str | None = None,
    env: dict | None = None,
    stdin_text: str | None = None,
):
    start = time.time()
    env_map = os.environ.copy()
    if env:
        env_map.update(env)

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env_map,
        stdin=subprocess.PIPE if stdin_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stdout_lines = []
    stderr_lines = []

    if stdin_text is not None and proc.stdin:
        proc.stdin.write(stdin_text)
        proc.stdin.close()

    def _reader(stream, collector, stream_name):
        for line in iter(stream.readline, ""):
            collector.append(line)
            if stream_callback and line.strip():
                prefix = "[stderr] " if stream_name == "stderr" else ""
                emit(stream_callback, "tool_output", {"text": f"{prefix}{line}"})
        stream.close()

    t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    last_progress = start

    while proc.poll() is None:
        now = time.time()
        elapsed = now - start
        if stream_callback and (now - last_progress) >= 3:
            emit(stream_callback, "tool_progress", {
                "elapsed": round(elapsed, 1),
                "timeout": timeout,
            })
            last_progress = now

        if elapsed > timeout:
            timed_out = True
            proc.kill()
            break
        time.sleep(0.2)

    t_out.join(timeout=5)
    t_err.join(timeout=5)

    elapsed = round(time.time() - start, 1)
    stdout = "".join(stdout_lines)
    stderr = "".join(stderr_lines)
    exit_code = proc.returncode if proc.returncode is not None else -1

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "elapsed": elapsed,
        "command": command_to_string(cmd),
    }
