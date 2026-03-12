"""
Advanced async port scanner with service fingerprinting and banner grabbing.
Much faster than nmap for quick scans, with built-in vuln hints.
"""

import socket
import ssl
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Common service banners and their implications
SERVICE_SIGS = {
    b"SSH": "SSH",
    b"OpenSSH": "OpenSSH",
    b"220": "FTP/SMTP",
    b"HTTP": "HTTP",
    b"IMAP": "IMAP",
    b"POP": "POP3",
    b"+OK": "POP3",
    b"MySQL": "MySQL",
    b"MariaDB": "MariaDB",
    b"PostgreSQL": "PostgreSQL",
    b"redis": "Redis",
    b"REDIS": "Redis",
    b"mongo": "MongoDB",
    b"elastic": "Elasticsearch",
    b"RabbitMQ": "RabbitMQ",
    b"* OK": "IMAP",
    b"<?xml": "XML Service",
    b'{"': "JSON API",
    b"<!DOCTYPE": "HTTP/HTML",
    b"<html": "HTTP/HTML",
}

VULN_HINTS = {
    "FTP": "Check for anonymous login (USER anonymous / PASS anonymous). Known CVEs in vsftpd, ProFTPD.",
    "SSH": "Check for weak creds, old key exchange algorithms. CVE-2024-6387 (regreSSHion) if OpenSSH < 9.8.",
    "SMTP": "Check for open relay, VRFY/EXPN user enumeration. SPF/DKIM/DMARC misconfig.",
    "HTTP": "Run full web exploitation suite. Check for default creds, exposed admin panels.",
    "MySQL": "Check for remote root login, default creds (root:root, root:mysql, root:<empty>).",
    "MariaDB": "Same as MySQL — check default creds, remote access enabled.",
    "PostgreSQL": "Check for trust auth, default creds (postgres:postgres).",
    "Redis": "CRITICAL if no auth — try INFO, CONFIG GET *, dump keys. CVE-2022-0543.",
    "MongoDB": "Check for no-auth access. Try connecting without creds. Data exfil risk.",
    "Elasticsearch": "Check for no-auth. Try /_cat/indices, /_search. Full data exposure.",
    "RabbitMQ": "Default creds guest:guest. Management UI on 15672.",
    "IMAP": "Check for STARTTLS, weak creds. User enumeration via LOGIN.",
    "POP3": "Check for cleartext auth, weak creds.",
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2181: "ZooKeeper", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5672: "AMQP", 5900: "VNC", 6379: "Redis", 6380: "Redis-TLS",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt", 27017: "MongoDB",
    27018: "MongoDB", 50000: "SAP", 50070: "Hadoop-NameNode",
}

TOP_1000 = sorted(COMMON_PORTS.keys()) + [
    i for i in [
        81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 113, 119, 161, 162, 179,
        199, 389, 427, 464, 497, 500, 502, 514, 515, 520, 548, 554, 593,
        623, 625, 631, 636, 646, 691, 771, 789, 873, 888, 902, 990, 992,
        1025, 1080, 1099, 1194, 1234, 1311, 1434, 1500, 1723, 1741, 1812,
        1900, 1911, 2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
        2100, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3269, 3333,
        3690, 4000, 4040, 4369, 4443, 4444, 4567, 4711, 4848, 5000, 5001,
        5050, 5060, 5222, 5353, 5357, 5431, 5555, 5601, 5632, 5666, 5800,
        5984, 5985, 5986, 6000, 6001, 6443, 6660, 6661, 6662, 6663, 6664,
        6665, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7070, 7071, 7443,
        7474, 7547, 7777, 7778, 8001, 8002, 8008, 8009, 8010, 8020, 8081,
        8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8181,
        8222, 8333, 8400, 8500, 8834, 8880, 8888, 8899, 8983, 9000, 9001,
        9002, 9042, 9043, 9060, 9080, 9091, 9100, 9160, 9191, 9443, 9500,
        9898, 9999, 10000, 10001, 10250, 10443, 11211, 12345, 15672, 16080,
        18080, 20000, 27017, 27018, 28017, 32768, 49152, 49153, 49154
    ] if i not in COMMON_PORTS
]


def _iter_with_thread_fallback(items, worker_fn, max_workers, emit=None, warning=None):
    """Run worker_fn over items concurrently; degrade to sequential on thread exhaustion."""
    seq_items = list(items)
    if not seq_items:
        return

    try:
        with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as executor:
            futures = {executor.submit(worker_fn, item): item for item in seq_items}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    yield item, future.result(), None
                except Exception as exc:
                    yield item, None, exc
    except RuntimeError as exc:
        if "can't start new thread" not in str(exc).lower():
            raise
        if emit:
            emit(warning or "  ⚠️ Thread limit reached; switching to sequential mode.")
        for item in seq_items:
            try:
                yield item, worker_fn(item), None
            except Exception as item_exc:
                yield item, None, item_exc


def _grab_banner(host, port, timeout=3):
    """Grab service banner from an open port."""
    banner = ""
    service = COMMON_PORTS.get(port, "Unknown")
    version = ""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Try SSL first for HTTPS ports
        if port in (443, 8443, 993, 995, 465, 636, 6443, 9443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    version = f"TLS cert: {cert.get('subject', '')}"
                ssock.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
                data = ssock.recv(1024)
                banner = data[:256].decode("utf-8", errors="replace")
                ssock.close()
                return service, banner.strip(), version
            except Exception:
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))

        # For HTTP ports, send request
        if port in (80, 8080, 8000, 8888, 8081, 8082, 3000, 5000, 9090, 8008):
            sock.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
        else:
            # For other ports, try to receive banner first
            pass

        sock.settimeout(2)
        try:
            data = sock.recv(1024)
            banner = data[:256].decode("utf-8", errors="replace").strip()
        except socket.timeout:
            # Some services need a probe
            sock.send(b"\r\n")
            try:
                data = sock.recv(1024)
                banner = data[:256].decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        sock.close()

        # Identify service from banner
        for sig, svc_name in SERVICE_SIGS.items():
            if sig in (data if 'data' in dir() and isinstance(data, bytes) else banner.encode()):
                service = svc_name
                break

        # Extract version from banner
        if banner:
            import re
            ver_match = re.search(r'[\d]+\.[\d]+[\.\d]*', banner)
            if ver_match:
                version = ver_match.group(0)
            # Server header
            srv_match = re.search(r'Server:\s*(.+?)[\r\n]', banner)
            if srv_match:
                service = srv_match.group(1).strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, "", ""

    return service, banner[:200], version


def _scan_port(host, port, timeout=2):
    """Check if a single port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def port_scan(target, scan_type="top100", custom_ports="", timeout=120, stream_callback=None):
    """
    Scan target for open ports with banner grabbing.
    
    scan_type: 'top100' (fast), 'top1000' (thorough), 'full' (1-65535), 'custom'
    custom_ports: comma-separated ports or ranges like '80,443,8000-9000'
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("portscan_progress", {"message": msg})

    # Resolve host
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return f"ERROR: Cannot resolve hostname '{host}'"

    _emit(f"🎯 Target: {host} ({ip})")

    # Determine ports to scan
    if scan_type == "custom" and custom_ports:
        ports = []
        for part in custom_ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    elif scan_type == "full":
        ports = list(range(1, 65536))
    elif scan_type == "top1000":
        ports = TOP_1000[:250]
    else:  # top100
        ports = sorted(COMMON_PORTS.keys())

    _emit(f"🔍 Scanning {len(ports)} ports (type: {scan_type})...")
    start_time = time.time()

    # Phase 1: Fast port discovery
    open_ports = []
    threads = min(64, len(ports))
    scanned = 0

    def _scan_one(port):
        return _scan_port(ip, port, 2)

    for _, result, _ in _iter_with_thread_fallback(
        ports,
        _scan_one,
        max_workers=threads,
        emit=_emit,
        warning="  ⚠️ Thread limit reached; port discovery switched to sequential mode.",
    ):
        scanned += 1
        if scanned % 100 == 0:
            _emit(f"  Scanned {scanned}/{len(ports)} ports...")
        if result:
            open_ports.append(result)
            _emit(f"  ✅ Port {result} OPEN")

    if not open_ports:
        elapsed = time.time() - start_time
        return f"PORT SCAN RESULTS for {host} ({ip})\n{'='*50}\nNo open ports found ({len(ports)} ports scanned in {elapsed:.1f}s)\n\nNote: Host may be behind a firewall or not responding to probes."

    open_ports.sort()
    _emit(f"\n📡 {len(open_ports)} open ports found. Grabbing banners...")

    # Phase 2: Banner grabbing on open ports
    results = []
    def _grab_one(port):
        return _grab_banner(ip, port, 3)

    for port, payload, _ in _iter_with_thread_fallback(
        open_ports,
        _grab_one,
        max_workers=min(12, len(open_ports)),
        emit=_emit,
        warning="  ⚠️ Thread limit reached; banner grabbing switched to sequential mode.",
    ):
        service, banner, version = payload or (None, "", "")
        if service is None:
            service = COMMON_PORTS.get(port, "Unknown")
        results.append({
            "port": port,
            "service": service,
            "banner": banner,
            "version": version,
            "vuln_hint": "",
        })

    # Add vuln hints
    for r in results:
        for svc_key, hint in VULN_HINTS.items():
            if svc_key.lower() in r["service"].lower():
                r["vuln_hint"] = hint
                break

    results.sort(key=lambda x: x["port"])
    elapsed = time.time() - start_time

    # Format output
    lines = [
        f"PORT SCAN RESULTS for {host} ({ip})",
        f"{'='*60}",
        f"Scanned {len(ports)} ports in {elapsed:.1f}s — {len(open_ports)} OPEN\n",
    ]

    for r in results:
        lines.append(f"  PORT {r['port']}/tcp  OPEN  {r['service']}")
        if r["version"]:
            lines.append(f"    Version: {r['version']}")
        if r["banner"]:
            clean = r["banner"].replace("\n", " ").replace("\r", "")[:120]
            lines.append(f"    Banner: {clean}")
        if r["vuln_hint"]:
            lines.append(f"    ⚠️  {r['vuln_hint']}")
        lines.append("")

    # Attack surface summary
    lines.append("ATTACK SURFACE SUMMARY")
    lines.append("-" * 40)
    web_ports = [r for r in results if any(w in r["service"].lower() for w in ["http", "html", "web", "nginx", "apache", "iis"])]
    db_ports = [r for r in results if any(d in r["service"].lower() for d in ["mysql", "maria", "postgres", "mongo", "redis", "elastic", "memcache", "mssql", "oracle"])]
    if web_ports:
        lines.append(f"  Web services: {', '.join(str(r['port']) for r in web_ports)} → Run exploit_target on each")
    if db_ports:
        lines.append(f"  Databases: {', '.join(str(r['port']) + '/' + r['service'] for r in db_ports)} → Check for default creds / no-auth")
    ssh_ports = [r for r in results if "ssh" in r["service"].lower()]
    if ssh_ports:
        lines.append(f"  SSH: {', '.join(str(r['port']) for r in ssh_ports)} → Brute force, check key exchange")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "port_scan",
        "description": "Fast multi-threaded port scanner with banner grabbing and service fingerprinting. Faster than nmap for quick discovery. Identifies services, versions, and provides vuln hints for each open port. Use scan_type='top100' for fast scan, 'top1000' for thorough, 'custom' with custom_ports for specific ranges.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target hostname or IP address"
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["top100", "top1000", "full", "custom"],
                    "description": "Scan intensity. top100=fast (common ports), top1000=thorough, full=all 65535, custom=specify ports"
                },
                "custom_ports": {
                    "type": "string",
                    "description": "Comma-separated ports or ranges for custom scan, e.g. '80,443,8000-9000'"
                }
            },
            "required": ["target"]
        }
    }
}
