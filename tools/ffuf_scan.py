import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from tools._cli_runner import (
    create_artifact_dir,
    emit,
    find_binary_or_auto_install,
    run_command,
    write_text,
)


# Common wordlists (check which exist on the system)
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
    "raft-medium": [
        "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    ],
    "api": [
        "/opt/homebrew/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    ],
}

# Bundled mini wordlist as fallback (top 200 paths)
BUILTIN_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login.php", "administrator", "phpmyadmin",
    "dashboard", "config", "backup", "test", "api", "dev", "staging", "old",
    ".git", ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "wp-json", "wp-content", "wp-includes", "xmlrpc.php", "readme.html",
    "server-status", "server-info", "info.php", "phpinfo.php", "debug",
    "console", "shell", "cmd", "cgi-bin", "scripts", "includes", "assets",
    "uploads", "images", "img", "css", "js", "static", "media", "files",
    "docs", "doc", "documents", "download", "downloads", "data", "db",
    "database", "sql", "dump", "backup.sql", "backup.zip", "backup.tar.gz",
    "tmp", "temp", "cache", "log", "logs", "error.log", "access.log",
    "debug.log", "install", "setup", "update", "upgrade", "migrate",
    "panel", "portal", "manager", "manage", "user", "users", "account",
    "accounts", "profile", "register", "signup", "signin", "auth",
    "authenticate", "oauth", "token", "api/v1", "api/v2", "api/v3",
    "graphql", "rest", "swagger", "api-docs", "openapi", "health",
    "status", "ping", "version", "metrics", "monitor", "monitoring",
    ".well-known", "security.txt", ".well-known/security.txt",
    "wp-cron.php", "wp-config.php.bak", "wp-config.php~",
    "license.txt", "changelog.txt", "README.md", "CHANGELOG.md",
    "composer.json", "package.json", "Gemfile", "Makefile",
    ".gitignore", ".dockerignore", "Dockerfile", "docker-compose.yml",
    "node_modules", "vendor", "bower_components",
    "secret", "secrets", "private", "internal", "hidden",
    "proxy", "gateway", "redirect", "callback", "webhook", "hook",
    "cron", "jobs", "queue", "worker", "task", "tasks",
    "billing", "payment", "checkout", "cart", "order", "orders",
    "admin/config", "admin/users", "admin/logs", "admin/settings",
    "cpanel", "webmail", "mail", "email", "smtp",
    "ftp", "sftp", "ssh", "telnet", "vnc",
    "elasticsearch", "kibana", "grafana", "prometheus",
    "jenkins", "travis", "circleci", "gitlab",
    "adminer.php", "phpmyadmin/setup", "pma",
    ".svn", ".svn/entries", ".hg", ".bzr",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "thumbs.db", "Desktop.ini", ".DS_Store",
    "web.config", "Global.asax", "elmah.axd",
    "trace.axd", "error", "errors", "403", "404", "500",
]


def _find_wordlist(name="common"):
    """Find an installed wordlist, falling back to built-in."""
    paths = WORDLISTS.get(name, WORDLISTS["common"])
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def _write_builtin_wordlist(artifact_dir=None):
    """Write the built-in wordlist to a file scoped to this run."""
    if artifact_dir is not None:
        path = artifact_dir / "ffuf_builtin_wordlist.txt"
        write_text(path, "\n".join(BUILTIN_WORDLIST))
        return str(path)
    path = "/tmp/ffuf_builtin_wordlist.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(BUILTIN_WORDLIST))
    return path


def _load_word_candidates(wl_path: str, max_words: int):
    out = []
    try:
        with open(wl_path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                value = raw.strip()
                if not value or value.startswith("#"):
                    continue
                out.append(value)
                if len(out) >= max_words:
                    break
    except Exception:
        return []
    return out


def _wfuzz_succeeded(text: str):
    blob = str(text or "").strip()
    if not blob:
        return False
    if blob.startswith("ERROR:"):
        return False
    if "binary not found on PATH" in blob:
        return False
    return True


def _run_internal_http_fallback(target_url: str, wl_path: str, threads: int, timeout: int, stream_callback=None):
    max_words = 600 if int(timeout) >= 120 else 300
    candidates = _load_word_candidates(wl_path, max_words=max_words)
    if not candidates:
        candidates = list(BUILTIN_WORDLIST[:200])

    interesting_status = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
    scan_budget = max(10, int(timeout))
    start_time = time.time()
    deadline = start_time + scan_budget
    request_timeout = 4 if int(timeout) >= 60 else 3
    max_workers = max(1, min(int(threads or 10), 24))
    results = []
    seen = set()

    emit(stream_callback, "tool_info", {
        "message": (
            f"Running internal HTTP path fallback against {target_url} "
            f"({len(candidates)} candidates, workers={max_workers})"
        ),
    })

    def _probe(word):
        if time.time() > deadline:
            return None
        url = f"{target_url}/{word.lstrip('/')}"
        try:
            resp = requests.get(
                url,
                timeout=request_timeout,
                allow_redirects=False,
                verify=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"},
            )
        except Exception:
            return None
        if resp.status_code not in interesting_status:
            return None
        return {
            "status": int(resp.status_code),
            "length": len(resp.content or b""),
            "url": url,
            "redirectlocation": resp.headers.get("Location", ""),
        }

    processed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_probe, word) for word in candidates]
        for future in as_completed(futures):
            processed += 1
            if time.time() > deadline:
                break
            item = future.result()
            if item:
                key = (item["status"], item["url"], item["redirectlocation"])
                if key not in seen:
                    seen.add(key)
                    results.append(item)
            if processed % 25 == 0:
                emit(stream_callback, "ffuf_progress", {
                    "elapsed": round(max(0.0, time.time() - start_time), 1),
                    "timeout": timeout,
                    "fallback": True,
                    "processed": processed,
                    "total": len(candidates),
                })

    elapsed = round(max(0.0, time.time() - start_time), 1)
    lines = [
        "=== Internal HTTP Path Fallback Scan ===",
        f"Target: {target_url}",
        f"Candidates tested: {min(processed, len(candidates))}",
        f"Completed in {elapsed}s | Found {len(results)} results",
        "",
    ]
    if results:
        lines.append(f"{'Status':<8} {'Size':<10} {'Path':<50} {'Redirect'}")
        lines.append("-" * 90)
        for item in sorted(results, key=lambda x: x.get("status", 0)):
            status = item.get("status", "?")
            length = item.get("length", 0)
            url = item.get("url", "?")
            redir = item.get("redirectlocation", "")
            path = url.replace(target_url, "") if isinstance(url, str) else str(url)
            redir_str = f"-> {redir}" if redir else ""
            lines.append(f"{status:<8} {_format_size(length):<10} {path:<50} {redir_str}")
    else:
        lines.append("No interesting paths discovered.")
    return "\n".join(lines)


def run_ffuf(target_url: str, mode: str = "dir", wordlist: str = "common",
             extensions: str = "", threads: int = 50, timeout: int = 120,
             stream_callback=None) -> str:
    """Run ffuf web fuzzer against a target.
    
    Args:
        target_url: Base URL to fuzz (e.g. https://example.com)
        mode: Scan mode - 'dir' (directory), 'vhost' (virtual hosts)
        wordlist: Wordlist to use - 'common', 'big', 'raft-medium', 'api', or path
        extensions: Comma-separated file extensions to check (e.g. 'php,html,txt')
        threads: Number of concurrent threads (default 50)
        timeout: Max seconds to run (default 120)
        stream_callback: Optional callback(event_type, data) for streaming
    """
    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"
    target_url = target_url.rstrip("/")

    artifact_dir = create_artifact_dir("ffuf")
    stdout_file = artifact_dir / "stdout.log"
    stderr_file = artifact_dir / "stderr.log"
    report_file = artifact_dir / "ffuf_output.json"
    meta_file = artifact_dir / "meta.json"

    if os.path.isfile(wordlist):
        wl_path = wordlist
    else:
        wl_path = _find_wordlist(wordlist)
    if not wl_path:
        wl_path = _write_builtin_wordlist(artifact_dir)
        emit(stream_callback, "tool_info", {
            "message": "Using built-in ffuf wordlist (200 paths). Install seclists for broader coverage.",
        })

    ffuf_bin, _, missing_error = find_binary_or_auto_install(
        ["ffuf"],
        tool_name="ffuf",
        stream_callback=stream_callback,
        install_timeout=max(120, int(timeout)),
    )
    if not ffuf_bin:
        emit(stream_callback, "coverage_degraded", {
            "tool": "run_ffuf",
            "code": "BIN_MISSING",
            "message": "ffuf unavailable; fallback executed.",
            "fallback": "wfuzz -> internal-http-path-probe",
        })
        wfuzz_output = ""
        try:
            from tools.wfuzz_scan import run_wfuzz
            emit(stream_callback, "tool_info", {
                "message": "ffuf unavailable; attempting wfuzz fallback.",
            })
            wfuzz_output = run_wfuzz(
                target_url=target_url,
                wordlist=wordlist,
                hide_codes="404",
                threads=min(int(threads), 25),
                timeout=timeout,
                stream_callback=stream_callback,
            )
            if _wfuzz_succeeded(wfuzz_output):
                return (
                    "COVERAGE DOWNGRADE: ffuf unavailable; wfuzz fallback executed.\n"
                    f"{missing_error}\n\n{wfuzz_output}"
                )
        except Exception as exc:
            wfuzz_output = f"wfuzz fallback error: {str(exc)}"

        internal = _run_internal_http_fallback(
            target_url=target_url,
            wl_path=wl_path,
            threads=max(1, min(int(threads), 20)),
            timeout=max(15, int(timeout)),
            stream_callback=stream_callback,
        )
        return (
            "COVERAGE DOWNGRADE: ffuf and wfuzz unavailable; internal HTTP path fallback executed.\n"
            f"{missing_error}\n\n"
            f"WFUZZ_RESULT:\n{wfuzz_output or 'wfuzz fallback unavailable'}\n\n"
            f"{internal}"
        )

    cmd = [
        ffuf_bin,
        "-u",
        f"{target_url}/FUZZ",
        "-w",
        wl_path,
        "-t",
        str(threads),
        "-timeout",
        "10",
        "-mc",
        "200,201,204,301,302,307,401,403,405,500",
        "-o",
        str(report_file),
        "-of",
        "json",
        "-s",
    ]

    if extensions:
        cmd.extend(["-e", ",".join(f".{e.strip('.')}" for e in extensions.split(","))])

    if mode == "vhost":
        parsed = urlparse(target_url)
        cmd = [
            ffuf_bin,
            "-u",
            target_url,
            "-w",
            wl_path,
            "-H",
            f"Host: FUZZ.{parsed.hostname}",
            "-t",
            str(threads),
            "-timeout",
            "10",
            "-mc",
            "200,201,204,301,302,307",
            "-fs",
            "0",
            "-o",
            str(report_file),
            "-of",
            "json",
            "-s",
        ]

    emit(stream_callback, "ffuf_start", {
        "target": target_url,
        "mode": mode,
        "wordlist": os.path.basename(wl_path),
    })

    result = run_command(cmd, timeout=timeout, stream_callback=stream_callback)
    write_text(stdout_file, result["stdout"])
    write_text(stderr_file, result["stderr"])
    write_text(meta_file, json.dumps({
        "tool": "ffuf",
        "command": result["command"],
        "elapsed": result["elapsed"],
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "target_url": target_url,
        "mode": mode,
        "wordlist": wl_path,
        "extensions": extensions,
        "threads": threads,
    }, indent=2))

    findings = []
    if report_file.exists():
        try:
            payload = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                findings = payload.get("results", [])
        except Exception:
            findings = []

    emit(stream_callback, "ffuf_done", {"elapsed": result["elapsed"], "found": len(findings)})

    lines = [
        f"=== ffuf Directory/File Scan: {target_url} ===",
        f"Mode: {mode} | Wordlist: {os.path.basename(wl_path)} | Threads: {threads}",
    ]
    if result["timed_out"]:
        lines.append(f"Timed out in {result['elapsed']}s | Found {len(findings)} results\n")
    else:
        lines.append(f"Completed in {result['elapsed']}s | Found {len(findings)} results\n")

    if findings:
        lines.append(f"{'Status':<8} {'Size':<10} {'Path':<50} {'Redirect'}")
        lines.append("-" * 90)
        for item in sorted(findings, key=lambda x: x.get("status", 0)):
            status = item.get("status", "?")
            length = item.get("length", 0)
            url = item.get("url", item.get("input", {}).get("FUZZ", "?"))
            redir = item.get("redirectlocation", "")
            path = url.replace(target_url, "") if isinstance(url, str) else str(url)
            redir_str = f"-> {redir}" if redir else ""
            lines.append(f"{status:<8} {_format_size(length):<10} {path:<50} {redir_str}")
    else:
        lines.append("No interesting paths discovered.")

    lines.append(f"\nArtifacts: {artifact_dir}")
    return "\n".join(lines)


def _format_size(bytes_count):
    if bytes_count > 1024 * 1024:
        return f"{bytes_count / (1024*1024):.1f} MB"
    elif bytes_count > 1024:
        return f"{bytes_count / 1024:.1f} KB"
    return f"{bytes_count} B"


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_ffuf",
        "description": "Run ffuf web fuzzer to discover hidden directories, files, and virtual hosts on a target. Much more thorough than manual path checking. Uses wordlists to brute-force paths. Streams results in real-time. Supports directory fuzzing and vhost discovery. Install seclists for better wordlists: brew install seclists.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target URL to fuzz (e.g. https://example.com)"
                },
                "mode": {
                    "type": "string",
                    "enum": ["dir", "vhost"],
                    "description": "Scan mode: 'dir' for directory/file discovery, 'vhost' for virtual host discovery. Default: dir",
                    "default": "dir"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist: 'common' (default), 'big', 'raft-medium', 'api', or an absolute file path",
                    "default": "common"
                },
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated file extensions to append (e.g. 'php,html,txt,bak'). Empty = directories only.",
                    "default": ""
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of concurrent threads. Default: 50",
                    "default": 50
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to run. Default: 120",
                    "default": 120
                }
            },
            "required": ["target_url"]
        }
    }
}
