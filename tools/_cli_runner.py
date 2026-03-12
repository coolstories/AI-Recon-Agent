from __future__ import annotations

import os
import re
import shlex
import shutil
import site
import subprocess
import sys
import sysconfig
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
    "ffuf": "Install: brew install ffuf or go install github.com/ffuf/ffuf/v2@latest",
    "nuclei": "Install: brew install nuclei or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "semgrep": "Install: pip install semgrep",
    "wpscan": "Install: brew install wpscanteam/tap/wpscan or gem install wpscan; Docker: docker run --rm wpscanteam/wpscan --help",
}

AUTO_INSTALL_LOCK = threading.Lock()
AUTO_INSTALL_LAST_ATTEMPT_TS = 0.0
AUTO_INSTALL_LAST_SUMMARY = "not_attempted"
AUTO_INSTALL_COOLDOWN_SEC = 300
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _python_user_bin_dirs():
    candidates = []
    try:
        user_base = site.getuserbase()
        if user_base:
            candidates.append(Path(user_base) / "bin")
    except Exception:
        pass

    try:
        scripts_dir = sysconfig.get_path("scripts")
        if scripts_dir:
            candidates.append(Path(scripts_dir))
    except Exception:
        pass

    # Common macOS user-site script path (python.org / system Python).
    candidates.append(Path.home() / "Library" / "Python" / f"{sys.version_info.major}.{sys.version_info.minor}" / "bin")

    out = []
    seen = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def _ruby_gem_user_bin_dirs():
    candidates = []

    ruby_path = shutil.which("ruby")
    if ruby_path:
        try:
            result = subprocess.run(
                [ruby_path, "-rrubygems", "-e", "puts Gem.user_dir + '/bin'"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            gem_bin = str(result.stdout or "").strip()
            if gem_bin:
                candidates.append(Path(gem_bin))
        except Exception:
            pass

    # Fallback for common gem user paths when ruby introspection is unavailable.
    try:
        for path in Path.home().glob(".local/share/gem/ruby/*/bin"):
            candidates.append(path)
    except Exception:
        pass

    out = []
    seen = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def _build_common_bin_dirs():
    defaults = [
        Path.home() / ".local" / "bin",
        Path.home() / "go" / "bin",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ]
    out = []
    seen = set()
    for candidate in [*defaults, *_python_user_bin_dirs(), *_ruby_gem_user_bin_dirs()]:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


COMMON_BIN_DIRS = _build_common_bin_dirs()


def emit(stream_callback, event_type: str, data: dict):
    if stream_callback:
        stream_callback(event_type, data)


def _ensure_path_dir(path: str):
    if not path:
        return
    current = os.environ.get("PATH", "")
    parts = current.split(":") if current else []
    if path not in parts:
        os.environ["PATH"] = f"{path}:{current}" if current else path


def _is_truthy_env(name: str, default: str = "1"):
    raw = str(os.getenv(name, default) or default).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def find_binary(candidates: Iterable[str]):
    for name in candidates:
        path = shutil.which(name)
        if path:
            return name, path
        for base in COMMON_BIN_DIRS:
            candidate = base / name
            if candidate.exists() and os.access(candidate, os.X_OK):
                _ensure_path_dir(str(base))
                return name, str(candidate)
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


def _tail_text(value: str, max_lines: int = 8, max_chars: int = 600):
    text = str(value or "").strip()
    if not text:
        return ""
    lines = text.splitlines()
    tail = "\n".join(lines[-max_lines:])
    if len(tail) > max_chars:
        tail = tail[-max_chars:]
    return tail


def _run_tool_installer(timeout: int = 900, stream_callback=None):
    script_path = PROJECT_ROOT / "scripts" / "install_security_tools.sh"
    if not script_path.exists():
        return {
            "ran": False,
            "timed_out": False,
            "elapsed": 0.0,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Installer script not found: {script_path}",
        }

    emit(stream_callback, "tool_info", {
        "message": "Missing scanner binary detected. Attempting auto-install via ./scripts/install_security_tools.sh",
    })
    result = run_command(["bash", str(script_path)], timeout=timeout, stream_callback=stream_callback, cwd=str(PROJECT_ROOT))
    for base in COMMON_BIN_DIRS:
        if base.exists():
            _ensure_path_dir(str(base))
    emit(stream_callback, "tool_info", {
        "message": (
            f"Auto-install finished: exit={result['exit_code']} timed_out={result['timed_out']} "
            f"elapsed={result['elapsed']}s"
        ),
    })
    return {"ran": True, **result}


def find_binary_or_auto_install(
    candidates: Iterable[str],
    tool_name: str = "",
    stream_callback=None,
    install_timeout: int = 900,
):
    global AUTO_INSTALL_LAST_ATTEMPT_TS
    global AUTO_INSTALL_LAST_SUMMARY

    cands = list(candidates)
    binary_name, binary_path = find_binary(cands)
    if binary_name:
        return binary_name, binary_path, ""

    if not _is_truthy_env("AUTO_INSTALL_MISSING_TOOLS", "1"):
        return None, None, build_missing_binary_error(cands, tool_name)

    now = time.time()
    install_result = None
    with AUTO_INSTALL_LOCK:
        binary_name, binary_path = find_binary(cands)
        if binary_name:
            return binary_name, binary_path, ""

        age_sec = now - float(AUTO_INSTALL_LAST_ATTEMPT_TS or 0.0)
        if AUTO_INSTALL_LAST_ATTEMPT_TS and age_sec < AUTO_INSTALL_COOLDOWN_SEC:
            emit(stream_callback, "tool_info", {
                "message": (
                    f"Auto-install recently attempted ({int(age_sec)}s ago). "
                    "Skipping reinstall cooldown and re-checking binary paths."
                ),
            })
        else:
            install_result = _run_tool_installer(timeout=max(60, int(install_timeout)), stream_callback=stream_callback)
            AUTO_INSTALL_LAST_ATTEMPT_TS = time.time()
            if install_result.get("ran"):
                AUTO_INSTALL_LAST_SUMMARY = (
                    f"exit={install_result.get('exit_code')} timed_out={install_result.get('timed_out')} "
                    f"elapsed={install_result.get('elapsed')}s"
                )
            else:
                AUTO_INSTALL_LAST_SUMMARY = str(install_result.get("stderr") or "installer_not_run")

    binary_name, binary_path = find_binary(cands)
    if binary_name:
        return binary_name, binary_path, ""

    base = build_missing_binary_error(cands, tool_name)
    if install_result:
        tail_out = _tail_text(install_result.get("stdout", ""))
        tail_err = _tail_text(install_result.get("stderr", ""))
        extra = [
            "AUTO_INSTALL: attempted ./scripts/install_security_tools.sh "
            f"(exit={install_result.get('exit_code')}, timed_out={install_result.get('timed_out')}, elapsed={install_result.get('elapsed')}s).",
        ]
        if tail_out:
            extra.append(f"AUTO_INSTALL_STDOUT_TAIL:\n{tail_out}")
        if tail_err:
            extra.append(f"AUTO_INSTALL_STDERR_TAIL:\n{tail_err}")
        return None, None, base + "\n" + "\n".join(extra)

    return None, None, base + f"\nAUTO_INSTALL_LAST: {AUTO_INSTALL_LAST_SUMMARY}"


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
