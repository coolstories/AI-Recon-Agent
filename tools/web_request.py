import requests
import json
import ssl
import socket
import time
from urllib.parse import urlparse


def make_web_request(url: str, method: str = "GET", headers: dict = None, follow_redirects: bool = True) -> str:
    """Make an HTTP request and return detailed response info."""
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            timeout=30,
            allow_redirects=follow_redirects,
            verify=True,
        )
        output_parts = []
        output_parts.append(f"Status: {resp.status_code} {resp.reason}")
        output_parts.append(f"URL: {resp.url}")
        output_parts.append("\n--- Response Headers ---")
        for k, v in resp.headers.items():
            output_parts.append(f"  {k}: {v}")

        body = resp.text[:5000]
        output_parts.append(f"\n--- Response Body (first 5000 chars) ---\n{body}")

        return "\n".join(output_parts)
    except requests.exceptions.SSLError as e:
        return f"SSL ERROR: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return f"CONNECTION ERROR: {str(e)}"
    except requests.exceptions.Timeout:
        return "ERROR: Request timed out after 30 seconds."
    except Exception as e:
        return f"ERROR: {str(e)}"


def _normalize_ssl_host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path or ""
    raw = raw.strip().split("/", 1)[0]
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.find("]")]
    if raw.count(":") == 1:
        host_part, port_part = raw.rsplit(":", 1)
        if port_part.isdigit():
            return host_part
    return raw


def _resolve_ssl_targets(host: str):
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except Exception:
        return []

    targets = []
    seen = set()
    for info in infos:
        sockaddr = info[4] if len(info) > 4 else ()
        ip = sockaddr[0] if sockaddr else ""
        if not ip or ip in seen:
            continue
        seen.add(ip)
        targets.append(ip)
    return targets


def check_ssl_cert(hostname: str) -> str:
    """Check SSL/TLS certificate details for a hostname or URL."""
    host = _normalize_ssl_host(hostname)
    if not host:
        return "SSL CHECK ERROR: hostname is required"

    targets = _resolve_ssl_targets(host)
    if not targets:
        return f"SSL CHECK ERROR: could not resolve host '{host}'"

    connect_timeout = 6
    max_cycles = 2
    max_attempts = min(12, max(2, len(targets) * max_cycles))
    budget_seconds = 22
    started = time.time()
    context = ssl.create_default_context()

    attempts = 0
    errors = []
    for _ in range(max_cycles):
        for ip in targets:
            if attempts >= max_attempts:
                break
            if time.time() - started > budget_seconds:
                break
            attempts += 1
            try:
                with socket.create_connection((ip, 443), timeout=connect_timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        protocol = ssock.version()

                        output = []
                        output.append(f"Host: {host}")
                        output.append(f"Resolved IP: {ip}")
                        output.append(f"Attempts: {attempts}")
                        output.append(f"Protocol: {protocol}")
                        output.append(f"Cipher: {ssock.cipher()}")
                        output.append(f"Subject: {cert.get('subject', 'N/A')}")
                        output.append(f"Issuer: {cert.get('issuer', 'N/A')}")
                        output.append(f"Not Before: {cert.get('notBefore', 'N/A')}")
                        output.append(f"Not After: {cert.get('notAfter', 'N/A')}")
                        output.append(f"Serial Number: {cert.get('serialNumber', 'N/A')}")
                        sans = cert.get('subjectAltName', [])
                        if sans:
                            output.append(f"SANs: {', '.join([s[1] for s in sans])}")
                        return "\n".join(output)
            except Exception as exc:
                errors.append(f"{ip}={type(exc).__name__}:{str(exc)}")
        if attempts >= max_attempts or (time.time() - started > budget_seconds):
            break

    elapsed = round(time.time() - started, 1)
    tail = "; ".join(errors[-3:]) if errors else "none"
    return (
        "SSL CHECK ERROR: timed out or handshake failed "
        f"(host={host}, resolved_ips={len(targets)}, attempts={attempts}, "
        f"connect_timeout={connect_timeout}s, elapsed={elapsed}s). "
        f"Last errors: {tail}"
    )


TOOL_DEFINITION_WEB = {
    "type": "function",
    "function": {
        "name": "web_request",
        "description": "Make an HTTP GET/POST request to a URL and return status code, headers, and response body. Useful for checking security headers, inspecting responses, finding exposed endpoints.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The full URL to request (include https://)"
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method: GET or POST. Default: GET",
                    "enum": ["GET", "POST", "HEAD", "OPTIONS"],
                    "default": "GET"
                }
            },
            "required": ["url"]
        }
    }
}

TOOL_DEFINITION_SSL = {
    "type": "function",
    "function": {
        "name": "check_ssl",
        "description": "Check the SSL/TLS certificate and configuration for a hostname. Returns protocol version, cipher, certificate details, expiry dates, and subject alternative names.",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The hostname to check (without https://, e.g. 'example.com')"
                }
            },
            "required": ["hostname"]
        }
    }
}
