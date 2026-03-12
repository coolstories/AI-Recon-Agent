import subprocess
import threading
import time
import json
import os
from tools._cli_runner import find_binary_or_auto_install


def run_nuclei(target: str, templates: str = "auto", severity: str = "critical,high,medium",
               timeout: int = 300, rate_limit: int = 150, stream_callback=None) -> str:
    """Run Nuclei vulnerability scanner against a target.
    
    Args:
        target: Target URL or host (e.g. https://example.com)
        templates: Template category - 'auto' (smart selection), 'cves', 'vulnerabilities',
                   'exposures', 'misconfigurations', 'technologies', 'all', or a specific path
        severity: Comma-separated severity filter (critical,high,medium,low,info)
        timeout: Max seconds to run (default 300)
        rate_limit: Requests per second limit (default 150)
        stream_callback: Optional callback(event_type, data) for streaming
    """
    if not target.startswith("http"):
        target = f"https://{target}"

    nuclei_bin, _, missing_error = find_binary_or_auto_install(
        ["nuclei"],
        tool_name="Nuclei",
        stream_callback=stream_callback,
        install_timeout=max(180, int(timeout)),
    )
    if not nuclei_bin:
        fallback_sections = []
        if stream_callback:
            stream_callback("coverage_degraded", {
                "tool": "run_nuclei",
                "code": "BIN_MISSING",
                "message": "nuclei unavailable after auto-install attempt.",
                "fallback": "testssl + exposed paths",
            })
            stream_callback("tool_info", {
                "message": "nuclei unavailable; running fallback checks (testssl + exposed paths).",
            })
        try:
            from tools.testssl_scan import run_testssl
            fallback_sections.append(
                run_testssl(
                    target=target,
                    mode="fast",
                    timeout=min(timeout, 180),
                    stream_callback=stream_callback,
                )
            )
        except Exception as e:
            fallback_sections.append(f"testssl fallback error: {str(e)}")
        try:
            from tools.vuln_check import check_exposed_paths
            fallback_sections.append(
                check_exposed_paths(
                    base_url=target,
                    stream_callback=stream_callback,
                )
            )
        except Exception as e:
            fallback_sections.append(f"exposed-path fallback error: {str(e)}")

        return (
            "COVERAGE DOWNGRADE: nuclei unavailable; fallback checks executed.\n"
            f"{missing_error}\n\n"
            + "\n\n".join(fallback_sections)
        )

    # Build nuclei command
    cmd = [
        nuclei_bin,
        "-u", target,
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-retries", "1",
        "-jsonl",           # JSON Lines output for parsing
        "-silent",          # Minimal console output
        "-no-color",
        "-stats",           # Show stats
        "-stats-interval", "5",
    ]

    # Template selection
    if templates == "auto":
        # Smart selection: focus on high-value templates
        cmd.extend(["-tags", "cve,exposure,misconfig,tech,login,panel,takeover"])
    elif templates == "all":
        pass  # Use all templates
    elif templates in ("cves", "vulnerabilities", "exposures", "misconfigurations", "technologies"):
        cmd.extend(["-tags", templates.rstrip("s")])
    elif os.path.exists(templates):
        cmd.extend(["-t", templates])
    else:
        cmd.extend(["-tags", templates])

    if stream_callback:
        stream_callback("nuclei_start", {
            "target": target,
            "templates": templates,
            "severity": severity,
        })

    start_time = time.time()
    findings = []

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )

        stderr_lines = []

        def read_stderr(stream):
            for line in iter(stream.readline, ''):
                stderr_lines.append(line)
                stripped = line.strip()
                if stripped and stream_callback:
                    # Parse nuclei stats lines
                    if "templates loaded" in stripped.lower() or "targets" in stripped.lower():
                        stream_callback("nuclei_info", {"message": stripped})
                    elif any(k in stripped for k in ["Templates:", "Hosts:", "RPS:", "Matched:"]):
                        stream_callback("nuclei_stats", {"message": stripped})
            stream.close()

        def read_stdout(stream):
            for line in iter(stream.readline, ''):
                stripped = line.strip()
                if not stripped:
                    continue
                # Try to parse JSON finding
                try:
                    finding = json.loads(stripped)
                    findings.append(finding)
                    if stream_callback:
                        name = finding.get("info", {}).get("name", finding.get("template-id", "unknown"))
                        sev = finding.get("info", {}).get("severity", "unknown")
                        matched = finding.get("matched-at", finding.get("host", ""))
                        stream_callback("nuclei_finding", {
                            "name": name,
                            "severity": sev,
                            "matched_at": matched,
                        })
                except json.JSONDecodeError:
                    # Not JSON, might be a plain text finding
                    if stripped and stream_callback:
                        stream_callback("nuclei_output", {"text": stripped})
            stream.close()

        t_out = threading.Thread(target=read_stdout, args=(proc.stdout,), daemon=True)
        t_err = threading.Thread(target=read_stderr, args=(proc.stderr,), daemon=True)
        t_out.start()
        t_err.start()

        last_update = start_time
        while proc.poll() is None:
            elapsed = time.time() - start_time
            if stream_callback and time.time() - last_update >= 5:
                stream_callback("nuclei_progress", {
                    "elapsed": round(elapsed, 1),
                    "timeout": timeout,
                    "findings_so_far": len(findings),
                })
                last_update = time.time()
            if elapsed > timeout:
                proc.kill()
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                break
            time.sleep(0.3)

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        elapsed = round(time.time() - start_time, 1)

        if stream_callback:
            stream_callback("nuclei_done", {"elapsed": elapsed, "total_findings": len(findings)})

        # Build report
        output = []
        output.append(f"=== Nuclei Vulnerability Scan: {target} ===")
        output.append(f"Templates: {templates} | Severity: {severity} | Rate: {rate_limit} rps")
        output.append(f"Completed in {elapsed}s | {len(findings)} vulnerabilities found\n")

        if findings:
            # Group by severity
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
            findings.sort(key=lambda x: sev_order.get(x.get("info", {}).get("severity", "unknown"), 5))

            sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            
            for f in findings:
                info = f.get("info", {})
                name = info.get("name", f.get("template-id", "Unknown"))
                sev = info.get("severity", "unknown")
                desc = info.get("description", "")
                matched = f.get("matched-at", f.get("host", ""))
                template_id = f.get("template-id", "")
                matcher_name = f.get("matcher-name", "")
                curl_cmd = f.get("curl-command", "")
                
                icon = sev_icons.get(sev, "❓")
                output.append(f"{icon} [{sev.upper()}] {name}")
                if template_id:
                    output.append(f"   Template: {template_id}")
                if matched:
                    output.append(f"   Matched: {matched}")
                if matcher_name:
                    output.append(f"   Matcher: {matcher_name}")
                if desc:
                    output.append(f"   Description: {desc[:200]}")
                if curl_cmd:
                    output.append(f"   Reproduce: {curl_cmd[:200]}")
                
                # References
                refs = info.get("reference", [])
                if refs and isinstance(refs, list):
                    output.append(f"   References: {', '.join(refs[:3])}")
                output.append("")
        else:
            output.append("No vulnerabilities found with the selected templates and severity filter.")
            output.append("Try: templates='all' or severity='critical,high,medium,low,info' for broader scan.")

        return "\n".join(output)

    except FileNotFoundError:
        return "ERROR: nuclei not installed. Install with: ./scripts/install_security_tools.sh"
    except Exception as e:
        return f"ERROR: {str(e)}"


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "run_nuclei",
        "description": "Run Nuclei vulnerability scanner — a fast, template-based scanner with 8000+ community templates for CVEs, misconfigurations, exposures, and technology detection. Much more powerful than manual checks. Streams findings in real-time. Use after initial recon (nmap, ffuf) to find specific vulnerabilities.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or host (e.g. https://example.com)"
                },
                "templates": {
                    "type": "string",
                    "description": "Template selection: 'auto' (smart high-value selection), 'cves', 'vulnerabilities', 'exposures', 'misconfigurations', 'technologies', 'all', or a path to templates",
                    "default": "auto"
                },
                "severity": {
                    "type": "string",
                    "description": "Severity filter: comma-separated (critical,high,medium,low,info). Default: 'critical,high,medium'",
                    "default": "critical,high,medium"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds to run. Default: 300 (5 min)",
                    "default": 300
                },
                "rate_limit": {
                    "type": "integer",
                    "description": "Max requests per second. Default: 150. Lower for stealth.",
                    "default": 150
                }
            },
            "required": ["target"]
        }
    }
}
