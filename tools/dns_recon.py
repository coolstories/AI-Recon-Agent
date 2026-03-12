"""
DNS reconnaissance — zone transfer attempts, record enumeration, DNSSEC check,
mail security (SPF/DKIM/DMARC), and DNS-based service discovery.
"""

import socket
import time
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]

# SRV records that reveal internal services
SRV_SERVICES = [
    "_http._tcp", "_https._tcp", "_ftp._tcp", "_ssh._tcp",
    "_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp",
    "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
    "_gc._tcp", "_kpasswd._tcp", "_kpasswd._udp",
    "_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
    "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
    "_submission._tcp", "_smtps._tcp",
    "_matrix._tcp", "_turn._tcp", "_stun._tcp",
    "_minecraft._tcp", "_ts3._udp",
]


def _resolve(domain, rtype, timeout=5):
    """Resolve DNS records."""
    if not DNS_AVAILABLE:
        # Fallback to dig
        try:
            result = subprocess.run(
                ["dig", domain, rtype, "+short", "+time=3"],
                capture_output=True, text=True, timeout=timeout
            )
            return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        except Exception:
            return []

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, rtype)
        return [str(r) for r in answers]
    except Exception:
        return []


def _attempt_zone_transfer(domain, ns):
    """Try AXFR zone transfer from a nameserver."""
    if not DNS_AVAILABLE:
        return None
    try:
        ns_ip = socket.gethostbyname(ns.rstrip("."))
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
        records = []
        for name, node in z.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{domain} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
        return records
    except Exception:
        return None


def _check_spf(domain):
    """Analyze SPF record for weaknesses."""
    txts = _resolve(domain, "TXT")
    for txt in txts:
        if "v=spf1" in txt.lower():
            issues = []
            if "+all" in txt:
                issues.append("CRITICAL: +all allows ANY server to send email (SPF is effectively disabled)")
            elif "~all" in txt:
                issues.append("WEAK: ~all (softfail) — emails from unauthorized senders may still be delivered")
            elif "?all" in txt:
                issues.append("WEAK: ?all (neutral) — SPF provides no protection")
            if "include:" in txt:
                includes = re.findall(r'include:(\S+)', txt)
                if len(includes) > 8:
                    issues.append(f"WARNING: {len(includes)} SPF includes — may exceed 10-lookup limit")
            if not issues:
                issues.append("OK: -all (hardfail) configured")
            return {"record": txt, "issues": issues}
    return {"record": None, "issues": ["MISSING: No SPF record — anyone can spoof emails from this domain"]}


def _check_dmarc(domain):
    """Analyze DMARC record."""
    txts = _resolve(f"_dmarc.{domain}", "TXT")
    for txt in txts:
        if "v=dmarc1" in txt.lower():
            issues = []
            if "p=none" in txt.lower():
                issues.append("WEAK: p=none — DMARC only monitors, does not reject spoofed emails")
            elif "p=quarantine" in txt.lower():
                issues.append("MODERATE: p=quarantine — spoofed emails sent to spam")
            elif "p=reject" in txt.lower():
                issues.append("GOOD: p=reject — spoofed emails rejected")
            if "pct=" in txt.lower():
                pct = re.search(r'pct=(\d+)', txt)
                if pct and int(pct.group(1)) < 100:
                    issues.append(f"WARNING: pct={pct.group(1)} — only {pct.group(1)}% of emails checked")
            if "rua=" not in txt.lower():
                issues.append("WARNING: No rua= — no aggregate reports sent")
            return {"record": txt, "issues": issues}
    return {"record": None, "issues": ["MISSING: No DMARC record — email spoofing not prevented"]}


def _check_dkim(domain):
    """Check common DKIM selectors."""
    selectors = ["default", "google", "mail", "dkim", "selector1", "selector2",
                 "k1", "k2", "s1", "s2", "mandrill", "amazonses", "sendgrid",
                 "mailgun", "postmark", "zendesk"]
    found = []
    for sel in selectors:
        records = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        if records:
            found.append({"selector": sel, "record": records[0][:120]})
    return found


def dns_recon(target, stream_callback=None):
    """
    Comprehensive DNS reconnaissance.
    Enumerates records, attempts zone transfers, checks mail security,
    discovers services via SRV records.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("dnsrecon_progress", {"message": msg})

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    _emit(f"🎯 DNS Reconnaissance: {domain}")
    start = time.time()

    # ── Phase 1: Standard record enumeration ──
    _emit("📋 Enumerating DNS records...")
    records = {}
    for rtype in RECORD_TYPES:
        results = _resolve(domain, rtype)
        if results:
            records[rtype] = results
            _emit(f"  {rtype}: {', '.join(results[:3])}")

    # ── Phase 2: Zone transfer attempts ──
    _emit("🔓 Attempting zone transfers (AXFR)...")
    zone_records = None
    nameservers = records.get("NS", [])
    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        _emit(f"  Trying AXFR on {ns_clean}...")
        result = _attempt_zone_transfer(domain, ns_clean)
        if result:
            zone_records = result
            _emit(f"  🔴 ZONE TRANSFER SUCCESSFUL on {ns_clean} — {len(result)} records dumped!")
            break
        else:
            _emit(f"  ✗ {ns_clean} — transfer refused")

    # ── Phase 3: Mail security ──
    _emit("📧 Checking mail security (SPF/DMARC/DKIM)...")
    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain)

    # ── Phase 4: SRV service discovery ──
    _emit("🔍 Discovering services via SRV records...")
    srv_found = []

    def _check_srv(svc):
        results = _resolve(f"{svc}.{domain}", "SRV")
        if results:
            return {"service": svc, "records": results}
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_srv, svc): svc for svc in SRV_SERVICES}
        for future in as_completed(futures):
            result = future.result()
            if result:
                srv_found.append(result)
                _emit(f"  ✅ {result['service']}: {', '.join(result['records'][:2])}")

    # ── Phase 5: Wildcard detection ──
    _emit("🔍 Checking for DNS wildcards...")
    wildcard = False
    random_sub = f"nonexistent-{int(time.time())}"
    wild_results = _resolve(f"{random_sub}.{domain}", "A")
    if wild_results:
        wildcard = True
        _emit(f"  ⚠️ Wildcard DNS detected: *.{domain} → {', '.join(wild_results)}")

    # ── Phase 6: DNSSEC check ──
    _emit("🔐 Checking DNSSEC...")
    dnssec = False
    dnskey = _resolve(domain, "DNSKEY") if DNS_AVAILABLE else []
    if dnskey:
        dnssec = True
        _emit("  ✅ DNSSEC enabled")
    else:
        _emit("  ⚠️ DNSSEC not enabled")

    # ── Phase 7: Reverse DNS on discovered IPs ──
    ips = records.get("A", [])
    reverse_dns = {}
    for ip in ips[:5]:
        try:
            hostname = socket.gethostbyaddr(ip)
            reverse_dns[ip] = hostname[0]
        except Exception:
            pass

    elapsed = time.time() - start

    # ── Format output ──
    lines = [
        f"DNS RECONNAISSANCE for {domain}",
        f"{'='*60}",
        f"Time: {elapsed:.1f}s\n",
    ]

    # Records
    lines.append("📋 DNS RECORDS")
    lines.append("-" * 40)
    for rtype, vals in records.items():
        for v in vals:
            lines.append(f"  {rtype:6s} {v}")
    if reverse_dns:
        for ip, host in reverse_dns.items():
            lines.append(f"  PTR    {ip} → {host}")
    lines.append("")

    # Zone transfer
    if zone_records:
        lines.append("🔴 ZONE TRANSFER SUCCESSFUL (CRITICAL)")
        lines.append("-" * 40)
        lines.append(f"  Dumped {len(zone_records)} records — full DNS zone exposed!")
        for rec in zone_records[:30]:
            lines.append(f"  {rec}")
        if len(zone_records) > 30:
            lines.append(f"  ... and {len(zone_records) - 30} more records")
        lines.append("  CWE-200 | CVSS: 7.5 (High)")
        lines.append("  Impact: Complete internal network mapping, subdomain discovery")
        lines.append("")

    # Mail security
    lines.append("📧 MAIL SECURITY")
    lines.append("-" * 40)
    lines.append(f"  SPF: {spf['record'] or 'MISSING'}")
    for issue in spf["issues"]:
        lines.append(f"    → {issue}")
    lines.append(f"  DMARC: {dmarc['record'] or 'MISSING'}")
    for issue in dmarc["issues"]:
        lines.append(f"    → {issue}")
    if dkim:
        lines.append(f"  DKIM: {len(dkim)} selectors found ({', '.join(d['selector'] for d in dkim)})")
    else:
        lines.append("  DKIM: No common selectors found")
    lines.append("")

    # Email spoofing risk assessment
    spoofable = False
    if "MISSING" in str(spf["issues"]) or "+all" in str(spf.get("record", "")):
        spoofable = True
    if "MISSING" in str(dmarc["issues"]) or "p=none" in str(dmarc.get("record", "")):
        spoofable = True
    if spoofable:
        lines.append("  ⚠️ EMAIL SPOOFING RISK: Domain is vulnerable to email spoofing")
        lines.append("    Impact: Phishing attacks using this domain's identity")
        lines.append("")

    # SRV services
    if srv_found:
        lines.append(f"🔧 DISCOVERED SERVICES ({len(srv_found)})")
        lines.append("-" * 40)
        for svc in srv_found:
            lines.append(f"  {svc['service']}: {', '.join(svc['records'][:2])}")
        lines.append("")

    # Other findings
    if wildcard:
        lines.append("⚠️ WILDCARD DNS")
        lines.append("-" * 40)
        lines.append(f"  *.{domain} resolves to {', '.join(wild_results)}")
        lines.append("  Impact: Subdomain enumeration may return false positives")
        lines.append("")

    lines.append(f"🔐 DNSSEC: {'Enabled' if dnssec else 'NOT enabled — DNS responses can be spoofed'}")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "dns_recon",
        "description": "Comprehensive DNS reconnaissance. Enumerates all record types (A, AAAA, MX, NS, TXT, SOA, SRV, CAA). Attempts zone transfers (AXFR) on every nameserver. Checks mail security (SPF, DMARC, DKIM) for email spoofing risk. Discovers internal services via SRV records. Checks DNSSEC and wildcard DNS.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain for DNS reconnaissance"
                }
            },
            "required": ["target"]
        }
    }
}
