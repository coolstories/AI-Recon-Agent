import subprocess
import threading
import time
import json
import os
import shutil


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


def _write_builtin_wordlist():
    """Write the built-in wordlist to a temp file."""
    path = "/tmp/ffuf_builtin_wordlist.txt"
    with open(path, "w") as f:
        f.write("\n".join(BUILTIN_WORDLIST))
    return path


def _find_ffuf_binary():
    """Find ffuf binary from PATH or common local bin directories."""
    ffuf_bin = shutil.which("ffuf")
    if ffuf_bin:
        return ffuf_bin

    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".local", "bin", "ffuf"),
        "/usr/local/bin/ffuf",
        "/opt/homebrew/bin/ffuf",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


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

    # Resolve wordlist
    if os.path.isfile(wordlist):
        wl_path = wordlist
    else:
        wl_path = _find_wordlist(wordlist)
    if not wl_path:
        wl_path = _write_builtin_wordlist()
        if stream_callback:
            stream_callback("tool_info", {"message": "Using built-in wordlist (200 paths). Install seclists for more: brew install seclists"})

    ffuf_bin = _find_ffuf_binary()
    if not ffuf_bin:
        # Optional fallback: try wfuzz wrapper when ffuf is unavailable.
        try:
            from tools.wfuzz_scan import run_wfuzz
            if stream_callback:
                stream_callback("tool_info", {
                    "message": "ffuf not installed; attempting wfuzz fallback.",
                })
            fallback = run_wfuzz(
                target_url=target_url,
                wordlist=wordlist,
                hide_codes="404",
                threads=min(threads, 25),
                timeout=timeout,
                stream_callback=stream_callback,
            )
            return (
                "ffuf not installed. Fallback executed with wfuzz.\n"
                f"{fallback}\n\n"
                "Install ffuf/nuclei quickly with: ./scripts/install_security_tools.sh"
            )
        except Exception:
            return (
                "ERROR: ffuf not installed.\n"
                "Install missing scanners with: ./scripts/install_security_tools.sh\n"
                "Manual fallback: install ffuf or wfuzz."
            )

    # Build ffuf command
    cmd = [ffuf_bin, "-u", f"{target_url}/FUZZ", "-w", wl_path,
           "-t", str(threads), "-timeout", "10",
           "-mc", "200,201,204,301,302,307,401,403,405,500",
           "-o", "/tmp/ffuf_output.json", "-of", "json",
           "-s"]  # silent mode, JSON output

    if extensions:
        cmd.extend(["-e", ",".join(f".{e.strip('.')}" for e in extensions.split(","))])

    if mode == "vhost":
        # For vhost fuzzing, we need a different approach
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        cmd = [ffuf_bin, "-u", target_url, "-w", wl_path,
               "-H", f"Host: FUZZ.{parsed.hostname}",
               "-t", str(threads), "-timeout", "10",
               "-mc", "200,201,204,301,302,307",
               "-fs", "0",  # filter empty responses
               "-o", "/tmp/ffuf_output.json", "-of", "json",
               "-s"]

    if stream_callback:
        stream_callback("ffuf_start", {
            "target": target_url,
            "mode": mode,
            "wordlist": os.path.basename(wl_path),
        })

    start_time = time.time()
    
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )

        stdout_lines = []
        stderr_lines = []

        def read_stream(stream, line_list):
            for line in iter(stream.readline, ''):
                line_list.append(line)
                if stream_callback and line.strip():
                    stream_callback("ffuf_output", {"text": line})
            stream.close()

        t_out = threading.Thread(target=read_stream, args=(proc.stdout, stdout_lines), daemon=True)
        t_err = threading.Thread(target=read_stream, args=(proc.stderr, stderr_lines), daemon=True)
        t_out.start()
        t_err.start()

        last_update = start_time
        while proc.poll() is None:
            elapsed = time.time() - start_time
            if stream_callback and time.time() - last_update >= 3:
                stream_callback("ffuf_progress", {
                    "elapsed": round(elapsed, 1),
                    "timeout": timeout,
                })
                last_update = time.time()
            if elapsed > timeout:
                proc.kill()
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                break
            time.sleep(0.2)

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        elapsed = round(time.time() - start_time, 1)

        # Parse JSON output
        results = []
        try:
            with open("/tmp/ffuf_output.json") as f:
                data = json.load(f)
                results = data.get("results", [])
        except Exception:
            pass

        if stream_callback:
            stream_callback("ffuf_done", {"elapsed": elapsed, "found": len(results)})

        # Build output
        output = []
        output.append(f"=== ffuf Directory/File Scan: {target_url} ===")
        output.append(f"Mode: {mode} | Wordlist: {os.path.basename(wl_path)} | Threads: {threads}")
        output.append(f"Completed in {elapsed}s | Found {len(results)} results\n")

        if results:
            output.append(f"{'Status':<8} {'Size':<10} {'Path':<50} {'Redirect'}")
            output.append("-" * 90)
            for r in sorted(results, key=lambda x: x.get("status", 0)):
                status = r.get("status", "?")
                length = r.get("length", 0)
                url = r.get("url", r.get("input", {}).get("FUZZ", "?"))
                redir = r.get("redirectlocation", "")
                path = url.replace(target_url, "") if isinstance(url, str) else str(url)
                size_str = _format_size(length)
                redir_str = f"→ {redir}" if redir else ""
                output.append(f"{status:<8} {size_str:<10} {path:<50} {redir_str}")
        else:
            output.append("No interesting paths discovered.")

        return "\n".join(output)

    except FileNotFoundError:
        return "ERROR: ffuf not installed. Install with: ./scripts/install_security_tools.sh"
    except Exception as e:
        return f"ERROR: {str(e)}"


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
