import subprocess
import sys
import threading
import time
import select
from utils.display import confirm_command, print_warning, console

DANGEROUS_COMMANDS = ["rm ", "rm -rf", "mkfs", "dd ", "> /dev/", "shutdown", "reboot", "halt", "init "]


def is_dangerous(command):
    cmd_lower = command.lower().strip()
    for d in DANGEROUS_COMMANDS:
        if cmd_lower.startswith(d) or f" {d}" in cmd_lower:
            return True
    return False


def run_terminal(command: str, timeout: int = 180, require_confirm: bool = True, stream_callback=None) -> str:
    """Execute a shell command with live output streaming.
    
    Args:
        command: Shell command to execute
        timeout: Max seconds to wait
        require_confirm: Whether to prompt user for confirmation
        stream_callback: Optional callback(event_type, data) for streaming updates
    """
    if is_dangerous(command):
        return f"BLOCKED: Command '{command}' was blocked for safety reasons (destructive operation)."

    if require_confirm:
        if not confirm_command(command):
            return "CANCELLED: User denied permission to run this command."

    console.print(f"[dim]⏳ Running: {command}[/dim]")

    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stdout_lines = []
        stderr_lines = []
        start_time = time.time()
        last_update = start_time

        # Emit start event
        if stream_callback:
            stream_callback("terminal_start", {"command": command, "timeout": timeout})

        # Read stdout in a thread
        def read_stream(stream, line_list, label):
            for line in iter(stream.readline, ''):
                line_list.append(line)
                stripped = line.rstrip()
                if stripped:
                    console.print(f"[dim]{stripped}[/dim]")
                    # Stream output to callback
                    if stream_callback:
                        stream_callback("terminal_output", {"text": line})
            stream.close()

        t_out = threading.Thread(target=read_stream, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
        t_err = threading.Thread(target=read_stream, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        # Wait for process with timeout, emit progress updates
        while proc.poll() is None:
            elapsed = time.time() - start_time
            
            # Emit progress every 3 seconds (reduced frequency for less overhead)
            if stream_callback and time.time() - last_update >= 3:
                remaining = max(0, timeout - elapsed)
                stream_callback("terminal_progress", {
                    "elapsed": round(elapsed, 1),
                    "timeout": timeout,
                    "remaining": round(remaining, 1),
                })
                last_update = time.time()
            
            if elapsed > timeout:
                proc.kill()
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                partial = "".join(stdout_lines)
                if stream_callback:
                    stream_callback("terminal_timeout", {"elapsed": round(elapsed, 1)})
                if partial:
                    return f"TIMEOUT after {timeout}s. Partial output:\n{partial}"
                return f"ERROR: Command timed out after {timeout} seconds."
            time.sleep(0.2)  # Reduced from 0.5s for faster response

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        output = "".join(stdout_lines)
        errors = "".join(stderr_lines)

        result = ""
        if output:
            result += output
        if errors:
            result += "\n[STDERR]\n" + errors
        if proc.returncode != 0:
            result += f"\n[EXIT CODE: {proc.returncode}]"

        elapsed = time.time() - start_time
        console.print(f"[dim]✓ Command finished in {elapsed:.1f}s[/dim]")

        # Emit completion
        if stream_callback:
            stream_callback("terminal_done", {"elapsed": round(elapsed, 1), "exit_code": proc.returncode})

        return result.strip() if result.strip() else "(command produced no output)"
    except Exception as e:
        if stream_callback:
            stream_callback("terminal_error", {"error": str(e)})
        return f"ERROR: {str(e)}"


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_terminal",
        "description": "Execute a shell command on the local system and return stdout/stderr. Output is streamed live so the user can see progress. Use this for nmap, whois, dig, curl, nikto, subfinder, httpx, or any other CLI tool. The user will be prompted to confirm before execution. IMPORTANT: For nmap, always use fast flags like -T4 --top-ports 1000 to avoid hanging. Default timeout is 180 seconds.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute. Examples: 'nmap -T4 -sV --top-ports 1000 target.com', 'whois target.com', 'dig target.com ANY', 'curl -sI https://target.com'"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Maximum seconds to wait. Default: 180. Use 300 for slow scans like nmap.",
                    "default": 180
                }
            },
            "required": ["command"]
        }
    }
}
