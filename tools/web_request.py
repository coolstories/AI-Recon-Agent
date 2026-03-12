import requests
import json
import ssl
import socket
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


def check_ssl_cert(hostname: str) -> str:
    """Check SSL/TLS certificate details for a hostname."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                output = []
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
    except Exception as e:
        return f"SSL CHECK ERROR: {str(e)}"


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
