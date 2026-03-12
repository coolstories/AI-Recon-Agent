from __future__ import annotations

import os
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import urllib3

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None
else:
    dns = dns.resolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HDR = {"User-Agent": "AIReconAgent-TruthVerifier/1.0"}
URL_RE = re.compile(r"https?://[^\s<>'\"`)\]]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

BIG_PROGRAM_HINTS = {
    "google", "microsoft", "apple", "meta", "facebook", "amazon", "aws",
    "cloudflare", "github", "gitlab", "adobe", "paypal", "uber", "atlassian",
}

BIG_PROGRAM_ROOT_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "meta.com",
    "facebook.com",
    "amazon.com",
    "aws.amazon.com",
    "cloudflare.com",
    "github.com",
    "gitlab.com",
    "adobe.com",
    "paypal.com",
    "uber.com",
    "atlassian.com",
}

VALID_VERIFICATION_POLICIES = {"strict", "balanced", "aggressive"}
DEFAULT_VERIFICATION_POLICY = "balanced"

TAKEOVER_FINGERPRINTS = [
    "NoSuchBucket",
    "The specified bucket does not exist",
    "There isn't a GitHub Pages site here",
    "No such app",
    "404 Site Not Found",
    "project not found",
]


def verify_bug_bounty_truth(
    chat_query: str,
    report_text: str,
    tool_outputs: list[str | dict] | None = None,
    verification_policy: str = DEFAULT_VERIFICATION_POLICY,
    primary_target: str = "",
) -> dict:
    """Deterministically validate findings from generated report + tool evidence."""
    tool_rows = _prioritize_tool_outputs(_normalize_tool_outputs(tool_outputs or []))
    policy = _normalize_verification_policy(verification_policy)

    tool_corpus = "\n".join([str((row or {}).get("text", "") or "") for row in tool_rows if str((row or {}).get("text", "")).strip()])
    combined = "\n".join([tool_corpus, report_text or ""]).strip()
    # Tool evidence is authoritative; report text is supplemental context only.
    evidence_text = tool_corpus if tool_corpus.strip() else combined

    urls = _extract_urls(combined)
    hosts = _extract_hosts(combined, urls)
    primary_host = _extract_primary_host(primary_target, chat_query)
    root_domain = _registrable_domain(primary_host)
    profile = _detect_program_profile(chat_query, primary_host, root_domain, policy)

    findings = [
        _verify_public_cloud_storage(tool_rows, evidence_text),
        _verify_xmlrpc_auth_surface(tool_rows, evidence_text),
        _verify_header_misconfiguration(tool_rows, evidence_text),
        _verify_cors(evidence_text, urls, tool_rows, primary_host, root_domain),
        _verify_ssti(evidence_text, urls, primary_host),
        _verify_vault(evidence_text, hosts),
        _verify_secret_claims(evidence_text, urls),
        _verify_hardcoded_passwords(evidence_text, urls),
        _verify_login_surface(evidence_text, urls, tool_rows, primary_host),
        _verify_subdomain_takeover(evidence_text),
    ]

    for finding in findings:
        _enrich_finding_metadata(finding)
        finding["bounty_ready"] = _is_bounty_ready(finding, profile)
        finding["attacker_action"] = _derive_attacker_action(finding)

    ready_count = sum(1 for f in findings if f["bounty_ready"])
    confirmed_count = sum(1 for f in findings if f["status"] == "confirmed")
    manual_count = sum(1 for f in findings if f["status"] in {"partial", "needs_manual"})
    rejected_count = sum(1 for f in findings if f["status"] == "not_confirmed")
    actionable_count = sum(
        1 for f in findings
        if f.get("status") in {"confirmed", "partial"}
        and int(f.get("evidence_count", 0) or 0) > 0
    )

    summary = {
        "profile": profile["label"],
        "strictness": profile["strictness"],
        "min_confidence": int(profile["min_confidence"]),
        "verification_policy": policy,
        "ready_count": ready_count,
        "actionable_count": actionable_count,
        "confirmed_count": confirmed_count,
        "manual_count": manual_count,
        "rejected_count": rejected_count,
        "total_findings": len(findings),
    }

    markdown = _format_markdown(summary, findings)
    return {
        "summary": summary,
        "findings": findings,
        "markdown": markdown,
    }


def _normalize_verification_policy(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw in VALID_VERIFICATION_POLICIES:
        return raw
    env_val = str(os.getenv("TRUTH_VERIFICATION_POLICY", DEFAULT_VERIFICATION_POLICY) or DEFAULT_VERIFICATION_POLICY).strip().lower()
    if env_val in VALID_VERIFICATION_POLICIES:
        return env_val
    return DEFAULT_VERIFICATION_POLICY


def _normalize_tool_outputs(tool_outputs: list[str | dict]) -> list[dict]:
    rows = []
    for item in tool_outputs or []:
        if isinstance(item, dict):
            name = str(item.get("name", "unknown") or "unknown").strip().lower()
            text = str(item.get("text", "") or item.get("result", "") or "").strip()
            if text:
                rows.append({"name": name, "text": text})
            continue
        txt = str(item or "").strip()
        if txt:
            rows.append({"name": "unknown", "text": txt})
    return rows


def _prioritize_tool_outputs(tool_outputs: list[dict]) -> list[dict]:
    if not tool_outputs:
        return []
    keywords = (
        "vault",
        "/v1/sys/",
        "cve-",
        "leader_address",
        "sealed",
        "coverage downgrade",
        "severe path",
        "severe_path",
        "control plane",
    )
    high_signal = []
    standard = []
    for item in tool_outputs:
        txt = str((item or {}).get("text", "") or "")
        lt = txt.lower()
        name = str((item or {}).get("name", "") or "").lower()
        if any(k in lt for k in keywords) or name in {"cloud_recon", "api_fuzz", "check_exposed_paths", "cors_scan", "header_audit"}:
            high_signal.append({"name": name or "unknown", "text": txt})
        else:
            standard.append({"name": name or "unknown", "text": txt})

    merged = high_signal[-80:] + standard[-40:]
    # de-dupe while preserving order
    seen = set()
    out = []
    for row in merged:
        key = (str((row or {}).get("name", "") or "unknown"), str((row or {}).get("text", "") or "").strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        out.append({"name": key[0], "text": key[1]})
    return out


def _extract_primary_host(primary_target: str, chat_query: str) -> str:
    raw = str(primary_target or "").strip()
    if not raw:
        match = re.search(r"https?://[^\s]+|(?:\b[a-z0-9-]+\.)+[a-z]{2,}\b", chat_query or "", flags=re.IGNORECASE)
        raw = match.group(0) if match else ""
    if not raw:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    try:
        host = (urlparse(raw).hostname or "").strip().lower()
    except Exception:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host


def _registrable_domain(host: str) -> str:
    h = (host or "").strip().lower().strip(".")
    if not h:
        return ""
    labels = [x for x in h.split(".") if x]
    if len(labels) <= 2:
        return h
    common_second_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(labels[-1]) == 2 and labels[-2] in common_second_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _tool_texts(tool_rows: list[dict], name: str) -> list[str]:
    out = []
    for row in tool_rows or []:
        if str((row or {}).get("name", "")).lower() == str(name).lower():
            txt = str((row or {}).get("text", "") or "")
            if txt:
                out.append(txt)
    return out


def _extract_urls(text: str) -> list[str]:
    found = []
    seen = set()
    for m in URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;:)]}>\"'")
        if url not in seen:
            seen.add(url)
            found.append(url)
    return found[:80]


def _extract_hosts(text: str, urls: list[str]) -> list[str]:
    hosts = set()
    for url in urls:
        p = urlparse(url)
        if p.netloc:
            hosts.add(p.netloc.lower())
    for m in DOMAIN_RE.finditer(text or ""):
        host = m.group(0).lower()
        if "." in host:
            hosts.add(host)
    filtered = []
    for host in sorted(hosts):
        if host.startswith("www."):
            host = host[4:]
        if host not in filtered:
            filtered.append(host)
    return filtered[:50]


def _detect_program_profile(chat_query: str, primary_host: str, root_domain: str, verification_policy: str) -> dict:
    text = f"{chat_query or ''} {primary_host or ''} {root_domain or ''}".lower()
    is_big = False
    if root_domain and root_domain in BIG_PROGRAM_ROOT_DOMAINS:
        is_big = True
    elif primary_host and any(primary_host == hint or primary_host.endswith("." + hint) for hint in BIG_PROGRAM_HINTS):
        is_big = True
    elif any(hint in text for hint in BIG_PROGRAM_HINTS):
        # This applies only to query text + primary host data (not noisy tool-output hosts).
        is_big = True

    base = {
        "label": "Big Program" if is_big else "Standard Program",
        "strictness": "high" if is_big else "normal",
        "min_confidence": 85 if is_big else 75,
        "requires_direct_impact": bool(is_big),
    }

    policy = _normalize_verification_policy(verification_policy)
    if policy == "strict":
        base["label"] = f"{base['label']} (strict verification)"
        base["strictness"] = "high"
        base["min_confidence"] = max(int(base["min_confidence"]), 90)
        base["requires_direct_impact"] = True
    elif policy == "aggressive":
        base["label"] = f"{base['label']} (aggressive verification)"
        base["strictness"] = "low"
        base["min_confidence"] = max(60, int(base["min_confidence"]) - 12)
        base["requires_direct_impact"] = False
    else:
        base["label"] = f"{base['label']} (balanced verification)"
        base["strictness"] = "medium" if is_big else "normal"
        base["min_confidence"] = max(70, int(base["min_confidence"]) - (3 if is_big else 0))
        # Keep direct-impact requirement only for big programs in balanced mode.
        base["requires_direct_impact"] = bool(is_big)
    return base


def _verify_public_cloud_storage(tool_rows: list[dict], evidence_text: str) -> dict:
    cloud_text = "\n".join(_tool_texts(tool_rows, "cloud_recon"))
    corpus = cloud_text or (evidence_text or "")
    public_urls = re.findall(r"https://[a-z0-9.-]+\.s3\.amazonaws\.com", corpus, flags=re.IGNORECASE)
    unique_urls = []
    seen = set()
    for u in public_urls:
        lu = u.lower().rstrip("/")
        if lu not in seen:
            seen.add(lu)
            unique_urls.append(lu)

    listable = "publicly listable" in corpus.lower() or "public s3 buckets" in corpus.lower()
    xml_listing = "<listbucketresult" in corpus.lower() or bool(re.search(r"<name>[a-z0-9.-]+</name>", corpus, flags=re.IGNORECASE))
    evidence = []
    for url in unique_urls[:4]:
        evidence.append(f"{url} (public cloud storage candidate)")
    if listable:
        evidence.append("Tool output indicates unauthenticated public listability.")
    if xml_listing:
        evidence.append("Live S3 XML listing evidence observed.")

    if unique_urls and listable:
        severity = "critical" if xml_listing else "high"
        confidence = 92 if xml_listing else 86
        return _finding(
            "Public Cloud Storage Exposure",
            severity,
            "confirmed",
            confidence,
            "Public cloud object storage was observed as listable without authentication.",
            evidence[:6],
            True,
        )
    if unique_urls:
        return _finding(
            "Public Cloud Storage Exposure",
            "high",
            "partial",
            68,
            "Cloud storage endpoints were discovered, but unauth list/read proof is incomplete.",
            evidence[:6],
            False,
        )
    return _finding(
        "Public Cloud Storage Exposure",
        "medium",
        "not_confirmed",
        24,
        "No deterministic public cloud storage exposure signal was reproduced.",
        [],
        False,
    )


def _verify_xmlrpc_auth_surface(tool_rows: list[dict], evidence_text: str) -> dict:
    api_text = "\n".join(_tool_texts(tool_rows, "api_fuzz"))
    path_text = "\n".join(_tool_texts(tool_rows, "check_exposed_paths"))
    run_text = "\n".join(_tool_texts(tool_rows, "run_terminal"))
    corpus = "\n".join([api_text, path_text, run_text, evidence_text or ""])

    has_xmlrpc = "/xmlrpc.php" in corpus.lower()
    post_200 = bool(re.search(r"/xmlrpc\.php.*(?:POST=200|HTTP/2 200|HTTP/1\.1 200)", corpus, flags=re.IGNORECASE))
    method_diff = bool(re.search(r"GET=405\s*→\s*POST=200", corpus, flags=re.IGNORECASE))
    xmlrpc_fault = bool(re.search(r"faultString.*parse error", corpus, flags=re.IGNORECASE))

    evidence = []
    if method_diff:
        evidence.append("api_fuzz reproduced method behavior change: GET=405 -> POST=200 on /xmlrpc.php.")
    if post_200:
        evidence.append("Live verification showed HTTP 200 on XML-RPC POST.")
    if xmlrpc_fault:
        evidence.append("XML-RPC parser fault response indicates endpoint is actively processing requests.")

    if has_xmlrpc and (post_200 or method_diff):
        return _finding(
            "Exposed XML-RPC / Auth Surface",
            "medium" if not method_diff else "high",
            "confirmed",
            84 if method_diff else 78,
            "XML-RPC endpoint behavior is reproducible and exposes an authentication attack surface.",
            evidence[:6],
            False,
        )
    if has_xmlrpc:
        return _finding(
            "Exposed XML-RPC / Auth Surface",
            "medium",
            "partial",
            62,
            "XML-RPC endpoint presence was observed but reproducible auth-surface behavior is incomplete.",
            evidence[:5],
            False,
        )
    return _finding(
        "Exposed XML-RPC / Auth Surface",
        "low",
        "not_confirmed",
        20,
        "No deterministic XML-RPC/auth-surface signal was reproduced.",
        [],
        False,
    )


def _verify_header_misconfiguration(tool_rows: list[dict], evidence_text: str) -> dict:
    header_text = "\n".join(_tool_texts(tool_rows, "header_audit"))
    corpus = header_text or (evidence_text or "")
    if not corpus.strip():
        return _finding(
            "Critical Header Misconfiguration",
            "low",
            "not_confirmed",
            20,
            "No deterministic header-audit evidence was available.",
            [],
            False,
        )

    missing = []
    for hdr in (
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ):
        if re.search(rf"Missing:\s*{re.escape(hdr)}", corpus, flags=re.IGNORECASE):
            missing.append(hdr)

    evidence = [f"Missing security header: {hdr}" for hdr in missing[:6]]
    has_high = any(h in {"Strict-Transport-Security", "Content-Security-Policy"} for h in missing)

    if len(missing) >= 2 and has_high:
        return _finding(
            "Critical Header Misconfiguration",
            "high",
            "confirmed",
            78,
            "Multiple foundational web security headers are missing.",
            evidence[:6],
            False,
        )
    if missing:
        return _finding(
            "Critical Header Misconfiguration",
            "medium",
            "partial",
            64,
            "Some security-header hardening gaps were reproduced.",
            evidence[:6],
            False,
        )
    return _finding(
        "Critical Header Misconfiguration",
        "low",
        "not_confirmed",
        28,
        "Header misconfiguration signals were not reproduced.",
        [],
        False,
    )


def _verify_cors(report_text: str, urls: list[str], tool_rows: list[dict], primary_host: str, root_domain: str) -> dict:
    cors_text = "\n".join(_tool_texts(tool_rows, "cors_scan"))
    if cors_text:
        m = re.search(r"Found:\s*(\d+)\s+misconfigurations", cors_text, flags=re.IGNORECASE)
        if m:
            count = int(m.group(1))
            if count == 0:
                return _finding(
                    "CORS Misconfiguration",
                    "medium",
                    "not_confirmed",
                    65,
                    "Deterministic CORS scanner output reported zero misconfigurations.",
                    ["cors_scan: Found 0 misconfigurations"],
                    False,
                )
            findings = []
            for line in cors_text.splitlines():
                if "URL:" in line or "ACAO:" in line or "Access-Control-Allow-Credentials" in line:
                    findings.append(line.strip())
            return _finding(
                "CORS Misconfiguration",
                "high",
                "partial",
                72,
                "CORS scanner reported misconfiguration indicators requiring direct exploit validation.",
                findings[:6],
                False,
            )

    targets = _collect_cors_targets(report_text, urls, primary_host, root_domain)[:10]
    if not targets:
        return _finding(
            "CORS Misconfiguration",
            "high",
            "needs_manual",
            25,
            "No API endpoints were extracted for deterministic CORS validation.",
            [],
            False,
        )

    origin = "https://evil.example"
    confirmed = []
    suspicious = []
    errors = []

    def check(url: str):
        records = []
        for method in ("OPTIONS", "GET"):
            try:
                if method == "OPTIONS":
                    headers = {
                        **HDR,
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                    }
                else:
                    headers = {**HDR, "Origin": origin}
                r = requests.request(
                    method, url, headers=headers, timeout=6, allow_redirects=False, verify=False
                )
                acao = (r.headers.get("Access-Control-Allow-Origin") or "").strip()
                acac = (r.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
                records.append((method, r.status_code, acao, acac))
            except Exception as e:
                records.append((method, None, "", f"error:{str(e)[:60]}"))
        return url, records

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(check, t) for t in targets]
        for future in as_completed(futures):
            url, records = future.result()
            exploitable = False
            maybe = False
            for method, status, acao, acac in records:
                if status is None:
                    continue
                if acao == origin and acac == "true":
                    exploitable = True
                elif acao in (origin, "*") or acac == "true":
                    maybe = True
            if exploitable:
                confirmed.append(url)
            elif maybe:
                suspicious.append(url)
            else:
                errors.append(url)

    if confirmed:
        return _finding(
            "CORS Misconfiguration",
            "critical",
            "confirmed",
            92,
            f"Arbitrary origin + credentials were observed on {len(confirmed)} endpoint(s).",
            confirmed[:5],
            True,
        )
    if suspicious:
        return _finding(
            "CORS Misconfiguration",
            "high",
            "partial",
            63,
            "CORS headers were present but full exploit conditions were not reproduced across all checks.",
            suspicious[:5],
            False,
        )
    return _finding(
        "CORS Misconfiguration",
        "high",
        "not_confirmed",
        28,
        "CORS exploit conditions were not reproduced on extracted endpoints.",
        errors[:5],
        False,
    )


def _collect_cors_targets(report_text: str, urls: list[str], primary_host: str = "", root_domain: str = "") -> list[str]:
    targets = set()
    base_hosts = []
    for url in urls:
        p = urlparse(url)
        if p.scheme and p.netloc:
            base = f"{p.scheme}://{p.netloc}"
            if base not in base_hosts:
                base_hosts.append(base)
        if "/api" in (p.path or "").lower():
            targets.add(_normalize_url(url))

    if primary_host:
        base_hosts.append(f"https://{primary_host}")
        if not primary_host.startswith("api."):
            base_hosts.append(f"https://api.{primary_host}")
    if root_domain and root_domain != primary_host:
        base_hosts.append(f"https://{root_domain}")
        if not root_domain.startswith("api."):
            base_hosts.append(f"https://api.{root_domain}")
    # De-duplicate while preserving order.
    dedup_base_hosts = []
    for host in base_hosts:
        if host not in dedup_base_hosts:
            dedup_base_hosts.append(host)
    base_hosts = dedup_base_hosts

    api_paths = re.findall(r"`(/api[^`]+)`", report_text or "", flags=re.IGNORECASE)
    if not base_hosts and primary_host:
        base_hosts = [f"https://{primary_host}"]

    preferred_hosts = [h for h in base_hosts if any(x in h for x in ("staging", "alpha", "api"))]
    if not preferred_hosts:
        preferred_hosts = base_hosts[:2]

    for path in api_paths[:10]:
        path = path.strip()
        for host in preferred_hosts[:2]:
            targets.add(_normalize_url(f"{host.rstrip('/')}{path}"))

    return sorted(targets)


def _verify_ssti(report_text: str, urls: list[str], primary_host: str = "") -> dict:
    targets = _collect_ssti_targets(urls, primary_host=primary_host)
    params = _collect_ssti_params(report_text)
    if not targets:
        return _finding(
            "Server-Side Template Injection (SSTI)",
            "high",
            "needs_manual",
            25,
            "No HTTP targets were extracted for SSTI probing.",
            [],
            False,
        )

    confirmed = []
    suspicious = []
    attempts = 0
    max_attempts = 12

    for target in targets[:4]:
        for param in params[:4]:
            if attempts >= max_attempts:
                break
            attempts += 1
            baseline = _safe_get(target, {param: "codex_probe_1337"})
            probe = _safe_get(target, {param: "{{7*7}}"})
            if not probe["ok"]:
                continue

            body_probe = probe["body"]
            body_base = baseline["body"] if baseline["ok"] else ""
            reflected = "{{7*7}}" in body_probe
            has_eval = "49" in body_probe and "49" not in body_base
            changed = body_probe != body_base if baseline["ok"] else False

            if has_eval and not reflected:
                confirmed.append(f"{probe['url']}?{param}=...")
            elif changed and not reflected:
                suspicious.append(f"{probe['url']}?{param}=...")
        if attempts >= max_attempts:
            break

    if confirmed:
        return _finding(
            "Server-Side Template Injection (SSTI)",
            "critical",
            "confirmed",
            90,
            f"SSTI behavior was reproduced on {len(confirmed)} parameter probe(s).",
            confirmed[:5],
            True,
        )
    if suspicious:
        return _finding(
            "Server-Side Template Injection (SSTI)",
            "high",
            "partial",
            58,
            "Responses changed during SSTI probes, but deterministic template evaluation was not confirmed.",
            suspicious[:5],
            False,
        )
    return _finding(
        "Server-Side Template Injection (SSTI)",
        "high",
        "not_confirmed",
        30,
        "Deterministic SSTI output was not observed in probe responses.",
        [],
        False,
    )


def _collect_ssti_targets(urls: list[str], primary_host: str = "") -> list[str]:
    targets = []
    for url in urls:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            continue
        host = p.netloc.lower()
        if any(k in host for k in ("staging", "alpha", "dev", "test")):
            path = p.path if p.path else "/"
            normalized = _normalize_url(f"{p.scheme}://{p.netloc}{path}")
            if normalized not in targets:
                targets.append(normalized)
    if not targets:
        for url in urls:
            p = urlparse(url)
            if p.scheme and p.netloc:
                normalized = _normalize_url(f"{p.scheme}://{p.netloc}{p.path or '/'}")
                if normalized not in targets:
                    targets.append(normalized)
    if not targets and primary_host:
        targets.append(_normalize_url(f"https://{primary_host}/"))
    return targets[:8]


def _collect_ssti_params(report_text: str) -> list[str]:
    params = ["q", "search", "name", "template", "message", "text", "content", "render"]
    extracted = re.findall(r"`([a-zA-Z_][a-zA-Z0-9_-]{0,20})`", report_text or "")
    for p in extracted:
        pl = p.lower()
        if pl not in params and "/" not in pl and "." not in pl:
            params.append(pl)
    return params


def _safe_get(url: str, params: dict[str, str]) -> dict:
    try:
        p = urlparse(url)
        merged = parse_qs(p.query, keep_blank_values=True)
        for k, v in params.items():
            merged[k] = [v]
        final_qs = urlencode(merged, doseq=True)
        final_url = urlunparse((p.scheme, p.netloc, p.path, p.params, final_qs, p.fragment))
        r = requests.get(final_url, headers=HDR, timeout=7, verify=False, allow_redirects=True)
        return {"ok": True, "status": r.status_code, "body": r.text[:12000], "url": urlunparse((p.scheme, p.netloc, p.path, "", "", ""))}
    except Exception:
        return {"ok": False, "status": None, "body": "", "url": url}


def _version_tuple(version: str):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(version or "").strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _vault_known_vulnerable_version(version: str) -> bool:
    vt = _version_tuple(version)
    if vt is None:
        return False
    # CVE-2025-12044 affected versions up to 1.20.4.
    return vt <= (1, 20, 4)


def _private_or_internal_target(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    host = raw
    if "://" in raw:
        try:
            host = (urlparse(raw).hostname or raw).strip()
        except Exception:
            host = raw
    host = host.strip().strip("[]").lower()
    if not host:
        return False
    if host.endswith(".internal") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False


def _probe_vault_management(host: str) -> dict:
    base = f"https://{host}"
    endpoints = ["/v1/sys/health", "/v1/sys/seal-status", "/v1/sys/leader", "/v1/sys/init"]
    reachable = 0
    unsealed = False
    version = ""
    topology_exposed = False
    evidence = []

    for path in endpoints:
        url = base + path
        try:
            r = requests.get(url, headers=HDR, timeout=6, verify=False, allow_redirects=False)
            status = int(r.status_code)
            if status < 500 and status not in {404, 405}:
                reachable += 1
            data = {}
            try:
                data = r.json() if r.text else {}
            except Exception:
                data = {}
            if isinstance(data, dict):
                if data.get("sealed") is False:
                    unsealed = True
                if not version and isinstance(data.get("version"), str):
                    version = str(data.get("version"))
                if path == "/v1/sys/leader":
                    if _private_or_internal_target(data.get("leader_address")):
                        topology_exposed = True
                    if _private_or_internal_target(data.get("leader_cluster_address")):
                        topology_exposed = True
            evidence.append(f"{host}{path} -> HTTP {status}")
        except Exception as e:
            evidence.append(f"{host}{path} -> error {str(e)[:70]}")
    return {
        "reachable": reachable,
        "unsealed": unsealed,
        "version": version,
        "topology_exposed": topology_exposed,
        "evidence": evidence,
    }


def _verify_vault(report_text: str, hosts: list[str]) -> dict:
    vault_hosts = [h for h in hosts if "vault." in h or h.startswith("vault")]
    if not vault_hosts:
        found = re.findall(r"\b(?:[a-z0-9-]+\.)*vault\.[a-z0-9.-]+\b", report_text or "", re.IGNORECASE)
        vault_hosts = sorted(set(h.lower() for h in found))

    if not vault_hosts:
        return _finding(
            "Exposed HashiCorp Vault",
            "medium",
            "not_confirmed",
            20,
            "No vault host was identified in extracted report artifacts.",
            [],
            False,
        )

    evidence = []
    high_impact_confirmed = False
    partial_signal = False

    for host in vault_hosts[:4]:
        probe = _probe_vault_management(host)
        host_evidence = probe.get("evidence") or []
        evidence.extend(host_evidence[:8])
        vulnerable_version = _vault_known_vulnerable_version(probe.get("version", ""))

        deterministic_high_impact = (
            int(probe.get("reachable", 0)) >= 2
            and bool(probe.get("unsealed", False))
            and (vulnerable_version or bool(probe.get("topology_exposed", False)))
            and len(host_evidence) >= 3
        )
        if deterministic_high_impact:
            high_impact_confirmed = True
            evidence.append(
                f"{host} deterministic criteria met (reachable_endpoints={probe.get('reachable')}, "
                f"unsealed={probe.get('unsealed')}, vulnerable_version={vulnerable_version}, "
                f"topology_exposed={probe.get('topology_exposed')})"
            )
        elif int(probe.get("reachable", 0)) >= 1:
            partial_signal = True

    if high_impact_confirmed:
        return _finding(
            "Exposed HashiCorp Vault",
            "high",
            "confirmed",
            88,
            (
                "Public management endpoints were reachable, service state was operational/unsealed, "
                "and direct-impact indicators (known vulnerable version or internal topology exposure) "
                "were reproduced deterministically."
            ),
            evidence[:8],
            True,
        )
    if partial_signal:
        return _finding(
            "Exposed HashiCorp Vault",
            "medium",
            "partial",
            60,
            "Vault endpoints were reachable, but deterministic direct-impact criteria were not fully met.",
            evidence[:5],
            False,
        )
    return _finding(
        "Exposed HashiCorp Vault",
        "medium",
        "not_confirmed",
        35,
        "Vault exposure could not be confirmed from live endpoint checks.",
        evidence[:5],
        False,
    )


def _verify_secret_claims(report_text: str, urls: list[str]) -> dict:
    evidence = []
    confidence = 45
    status = "partial"
    direct_impact = False

    uuid_like = re.findall(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        report_text or "",
    )
    hex32 = re.findall(r"\b[a-fA-F0-9]{32}\b", report_text or "")
    sentry_refs = re.findall(r"\b[a-fA-F0-9]{16,64}@sentry\.io\b", report_text or "", re.IGNORECASE)

    if uuid_like:
        evidence.append("UUID-like values were found; these are often identifiers, not API secrets.")
    if hex32:
        evidence.append(f"{len(hex32)} hex-32 token(s) found (possible secret material).")
        confidence = max(confidence, 62)
    if sentry_refs:
        evidence.append("Sentry DSN fragment found; DSNs are often intentionally public.")

    map_urls = [u for u in urls if u.lower().endswith(".map")][:5]
    exposed_maps = []
    for mu in map_urls:
        try:
            r = requests.get(mu, headers=HDR, timeout=6, verify=False, allow_redirects=True)
            ctype = (r.headers.get("Content-Type") or "").lower()
            if r.status_code == 200 and ("json" in ctype or "javascript" in ctype or len(r.text) > 200):
                exposed_maps.append(mu)
        except Exception:
            continue

    if exposed_maps:
        evidence.append(f"Accessible source map(s): {len(exposed_maps)}")
        status = "confirmed"
        confidence = 78
        direct_impact = False

    if not evidence:
        return _finding(
            "Hardcoded Secrets / JS Exposure",
            "medium",
            "not_confirmed",
            25,
            "No deterministic secret exposure signal was reproduced.",
            [],
            False,
        )
    return _finding(
        "Hardcoded Secrets / JS Exposure",
        "high" if status == "confirmed" else "medium",
        status,
        confidence,
        "Some exposure signals were reproduced, but token exploitability still needs manual validation.",
        evidence[:5],
        direct_impact,
    )


def _verify_hardcoded_passwords(report_text: str, urls: list[str]) -> dict:
    """Verify hardcoded password/credential signals from report + JS evidence."""
    evidence = []
    candidates = []

    # Static evidence from existing report text/tool summaries.
    static_hits = re.findall(
        r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\']([^"\']{4,120})["\']',
        report_text or "",
    )
    for key, value in static_hits[:8]:
        lv = (value or "").strip().lower()
        if lv in {"password", "changeme", "example", "test", "null", "undefined"}:
            continue
        masked = value[:2] + "***" + value[-2:] if len(value) > 4 else "***"
        evidence.append(f"{key}=\"{masked}\" found in collected artifacts")

    js_urls = [u for u in urls if ".js" in u.lower()][:8]
    if not js_urls and urls:
        # Try common JS bundles if direct JS URLs were not captured.
        seen = set()
        for u in urls[:4]:
            p = urlparse(u)
            if not p.scheme or not p.netloc:
                continue
            base = f"{p.scheme}://{p.netloc}"
            for path in ("/app.js", "/main.js", "/bundle.js", "/static/js/main.js"):
                cand = base + path
                if cand not in seen:
                    seen.add(cand)
                    js_urls.append(cand)
                if len(js_urls) >= 8:
                    break
            if len(js_urls) >= 8:
                break

    pat = re.compile(r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\']([^"\']{4,120})["\']')
    for js_url in js_urls[:8]:
        try:
            r = requests.get(js_url, headers=HDR, timeout=6, verify=False, allow_redirects=True)
            if r.status_code != 200:
                continue
            body = r.text[:300000]
            hits = pat.findall(body)
            for key, value in hits[:3]:
                lv = (value or "").strip().lower()
                if lv in {"password", "changeme", "example", "test", "null", "undefined"}:
                    continue
                masked = value[:2] + "***" + value[-2:] if len(value) > 4 else "***"
                candidates.append(f"{js_url} {key}=\"{masked}\"")
                if len(candidates) >= 8:
                    break
        except Exception:
            continue
        if len(candidates) >= 8:
            break

    if candidates:
        return _finding(
            "Hardcoded Password Candidates",
            "high",
            "confirmed",
            84,
            "Password-like client-side literals were reproduced from fetched assets.",
            (candidates + evidence)[:6],
            False,
        )
    if evidence:
        return _finding(
            "Hardcoded Password Candidates",
            "medium",
            "partial",
            62,
            "Password-like literals were present in collected evidence but were not fully reproduced from live assets.",
            evidence[:5],
            False,
        )
    return _finding(
        "Hardcoded Password Candidates",
        "medium",
        "not_confirmed",
        30,
        "No deterministic hardcoded password pattern was reproduced.",
        [],
        False,
    )


def _verify_login_surface(report_text: str, urls: list[str], tool_rows: list[dict], primary_host: str = "") -> dict:
    """Assess login endpoints and bounded brute-force/credential-stuffing chance indicators."""
    targets = _collect_login_targets(report_text, urls, tool_rows, primary_host=primary_host)
    if not targets:
        return _finding(
            "Login Attack Surface (Brute-force Chance)",
            "medium",
            "needs_manual",
            24,
            "No login endpoints were extracted for verification.",
            [],
            False,
        )

    weak_signals = []
    guarded_signals = []

    for target in targets[:8]:
        try:
            r = requests.get(target, headers=HDR, timeout=6, verify=False, allow_redirects=False)
        except Exception:
            continue

        status = r.status_code
        body = (r.text or "")[:120000]
        location = (r.headers.get("Location") or "")

        if status in {301, 302, 303, 307, 308} and any(k in location.lower() for k in ("login", "signin", "auth")):
            guarded_signals.append(f"{target} redirects to login flow ({status})")
            continue
        if status not in {200, 401, 403}:
            continue

        has_password = bool(re.search(r'type=["\']password["\']', body, re.I))
        if not has_password:
            continue
        has_captcha = bool(re.search(r'(g-recaptcha|hcaptcha|captcha)', body, re.I))
        has_rl_header = any(h in r.headers for h in ("X-RateLimit-Limit", "RateLimit-Limit", "Retry-After"))

        if not has_captcha and not has_rl_header:
            weak_signals.append(f"{target} (no captcha marker / no explicit rate-limit header)")
        else:
            guarded_signals.append(f"{target} (captcha={has_captcha}, ratelimit_header={has_rl_header})")

    if weak_signals:
        return _finding(
            "Login Attack Surface (Brute-force Chance)",
            "medium",
            "confirmed",
            74,
            "Public login surfaces were confirmed with weak anti-automation signals.",
            weak_signals[:5],
            False,
        )
    if guarded_signals:
        return _finding(
            "Login Attack Surface (Brute-force Chance)",
            "low",
            "partial",
            56,
            "Login endpoints exist, but at least some anti-automation protections are visible.",
            guarded_signals[:5],
            False,
        )
    return _finding(
        "Login Attack Surface (Brute-force Chance)",
        "medium",
        "not_confirmed",
        32,
        "No deterministic login attack-surface signal was reproduced.",
        [],
        False,
    )


def _collect_login_targets(report_text: str, urls: list[str], tool_rows: list[dict], primary_host: str = "") -> list[str]:
    targets = set()
    for url in urls:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            continue
        path = (p.path or "").lower()
        if any(k in path for k in ("login", "signin", "auth", "oauth", "sso")):
            targets.add(_normalize_url(url))

    # Pull explicit login links from text artifacts.
    for m in re.findall(r"https?://[^\s<>'\"`)]*(?:login|signin|auth|oauth|sso)[^\s<>'\"`)]*", report_text or "", re.IGNORECASE):
        targets.add(_normalize_url(m))

    check_paths_text = "\n".join(_tool_texts(tool_rows, "check_exposed_paths"))
    for m in re.findall(r"https?://[^\s<>'\"`)]*(?:login|signin|auth|oauth|sso|wp-login\.php)[^\s<>'\"`)]*", check_paths_text, re.IGNORECASE):
        targets.add(_normalize_url(m))

    # Try common login endpoints on known hosts.
    hosts = set()
    for u in urls[:20]:
        p = urlparse(u)
        if p.scheme and p.netloc:
            hosts.add((p.scheme, p.netloc))
    if primary_host:
        hosts.add(("https", primary_host))
    common = ["/login", "/signin", "/auth/login", "/user/login", "/account/login", "/admin/login", "/wp-login.php"]
    for scheme, host in list(hosts)[:6]:
        for path in common:
            targets.add(f"{scheme}://{host}{path}")

    return sorted(targets)[:20]


def _verify_subdomain_takeover(report_text: str) -> dict:
    hosts = re.findall(
        r"\*\*([a-z0-9][a-z0-9.-]+\.[a-z]{2,})\*\*\s*→",
        report_text or "",
        flags=re.IGNORECASE,
    )
    hosts = sorted(set(h.lower() for h in hosts))
    if not hosts:
        return _finding(
            "Subdomain Takeover",
            "medium",
            "not_confirmed",
            20,
            "No explicit takeover candidates were found in structured report lines.",
            [],
            False,
        )

    confirmed = []
    manual = []
    for host in hosts[:8]:
        cname = _lookup_cname(host)
        resolves = _resolves(host)
        body = _fetch_body(host)
        fp_hit = any(sig.lower() in body.lower() for sig in TAKEOVER_FINGERPRINTS) if body else False

        if (not resolves and cname) or fp_hit:
            manual.append(f"{host} cname={cname or 'none'} fingerprint={fp_hit}")
        else:
            confirmed.append(f"{host} resolves={resolves} cname={cname or 'none'}")

    if manual:
        return _finding(
            "Subdomain Takeover",
            "medium",
            "needs_manual",
            55,
            "Some takeover indicators exist, but provider-side claimability is not proven.",
            manual[:5],
            False,
        )
    return _finding(
        "Subdomain Takeover",
        "medium",
        "not_confirmed",
        32,
        "Candidates resolve to active infrastructure with no deterministic dangling signature.",
        confirmed[:5],
        False,
    )


def _lookup_cname(host: str) -> str:
    if not dns:
        return ""
    try:
        ans = dns.resolve(host, "CNAME")
        for r in ans:
            return str(r.target).rstrip(".")
    except Exception:
        return ""
    return ""


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443)
        return True
    except Exception:
        return False


def _fetch_body(host: str) -> str:
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", headers=HDR, timeout=6, verify=False, allow_redirects=True)
            return r.text[:5000]
        except Exception:
            continue
    return ""


def _normalize_url(url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    return urlunparse((p.scheme, p.netloc, path, "", "", ""))


def _finding(
    name: str,
    severity: str,
    status: str,
    confidence: int,
    reason: str,
    evidence: list[str],
    direct_impact: bool,
    verification_method: str = "",
    impact_scope: str = "",
    next_validation_step: str = "",
    remediation_hint: str = "",
    preconditions: str = "",
    reproducibility: str = "",
) -> dict:
    return {
        "name": name,
        "severity": severity,
        "status": status,
        "confidence": max(0, min(100, int(confidence))),
        "reason": reason,
        "evidence": evidence,
        "direct_impact": direct_impact,
        "evidence_count": len(evidence or []),
        "verification_method": verification_method,
        "impact_scope": impact_scope,
        "next_validation_step": next_validation_step,
        "remediation_hint": remediation_hint,
        "preconditions": preconditions,
        "reproducibility": reproducibility,
    }


def _is_bounty_ready(finding: dict, profile: dict) -> bool:
    if finding["status"] != "confirmed":
        return False
    if finding["severity"] not in {"critical", "high"}:
        return False
    if finding["confidence"] < profile["min_confidence"]:
        return False
    evidence_count = finding.get("evidence_count")
    if evidence_count is None:
        evidence_count = len(finding.get("evidence") or [])
    if evidence_count < 1:
        return False
    if profile["requires_direct_impact"] and not finding.get("direct_impact"):
        return False
    return True


def _enrich_finding_metadata(finding: dict) -> None:
    name = (finding.get("name") or "").lower()
    status = finding.get("status", "")
    evidence = finding.get("evidence") or []
    finding["evidence_count"] = len(evidence)

    if not finding.get("verification_method"):
        finding["verification_method"] = _derive_verification_method(name)
    if not finding.get("impact_scope"):
        finding["impact_scope"] = _derive_impact_scope(name)
    if not finding.get("next_validation_step"):
        finding["next_validation_step"] = _derive_next_validation_step(name, status)
    if not finding.get("remediation_hint"):
        finding["remediation_hint"] = _derive_remediation_hint(name)
    if not finding.get("preconditions"):
        finding["preconditions"] = _derive_preconditions(name)
    if not finding.get("reproducibility"):
        finding["reproducibility"] = _derive_reproducibility_notes(status, finding.get("confidence", 0), len(evidence))


def _derive_verification_method(name: str) -> str:
    if "public cloud storage" in name:
        return "Tool-backed cloud storage exposure parsing with deterministic public-list/read indicators."
    if "xml-rpc" in name:
        return "API/auth surface parsing plus deterministic XML-RPC POST behavior checks."
    if "header misconfiguration" in name:
        return "Deterministic header audit parsing for missing foundational security headers."
    if "cors" in name:
        return "Live cross-origin header validation (OPTIONS + GET) with controlled Origin."
    if "template injection" in name or "ssti" in name:
        return "Baseline vs probe response comparison using deterministic template markers."
    if "vault" in name:
        return "Deterministic unauth control-endpoint validation across /v1/sys/health, seal-status, leader, and init."
    if "secret" in name or "js exposure" in name:
        return "Static artifact token-pattern review with live source-map reachability checks."
    if "hardcoded password" in name:
        return "Credential-pattern extraction from artifacts plus live asset re-fetch validation."
    if "login attack surface" in name or "brute-force chance" in name:
        return "Login endpoint discovery with anti-automation signal checks (captcha/rate-limit hints)."
    if "takeover" in name:
        return "DNS resolution/CNAME analysis plus provider fingerprint probing."
    return "Deterministic live verification from tool-backed evidence."


def _derive_impact_scope(name: str) -> str:
    if "public cloud storage" in name:
        return "Publicly reachable cloud object storage that may expose internal artifacts."
    if "xml-rpc" in name:
        return "XML-RPC and authentication-adjacent web endpoints exposed to unauthenticated clients."
    if "header misconfiguration" in name:
        return "Web response hardening controls affecting client-side and transport-layer security."
    if "cors" in name:
        return "Cross-origin browser access risk on affected API endpoints."
    if "template injection" in name or "ssti" in name:
        return "Server-side rendering paths accepting unsanitized template-like input."
    if "vault" in name:
        return "Publicly reachable Vault control-plane interfaces and metadata surfaces."
    if "secret" in name or "js exposure" in name:
        return "Client-delivered artifacts that may disclose internal identifiers or development context."
    if "hardcoded password" in name:
        return "Client-side assets containing password-like literal strings."
    if "login attack surface" in name or "brute-force chance" in name:
        return "Public authentication endpoints with varying anti-automation controls."
    if "takeover" in name:
        return "Subdomain DNS mappings with possible dangling-provider risk."
    return "Observed target surfaces derived from collected scan evidence."


def _derive_next_validation_step(name: str, status: str) -> str:
    if status == "confirmed":
        return "Re-run the same deterministic checks after remediation to verify closure."
    if "public cloud storage" in name:
        return "Verify unauthenticated list/read access against representative objects and restrict ACL/policies."
    if "xml-rpc" in name:
        return "Confirm XML-RPC necessity and enforce tighter auth/rate controls if endpoint remains enabled."
    if "header misconfiguration" in name:
        return "Add missing headers and re-run deterministic header audits to verify hardening."
    if "cors" in name:
        return "Retest with multiple untrusted Origin values and credentialed requests across all API paths."
    if "template injection" in name or "ssti" in name:
        return "Perform controlled manual template-engine fingerprinting in a sanctioned test environment."
    if "vault" in name:
        return "Restrict external reachability and re-run multi-endpoint deterministic checks to verify closure."
    if "secret" in name or "js exposure" in name:
        return "Manually confirm token scope/validity in a safe, read-only validation workflow."
    if "hardcoded password" in name:
        return "Trace candidate literals to source origin and confirm whether they are active credentials."
    if "login attack surface" in name or "brute-force chance" in name:
        return "Run bounded rate-limit verification tests with explicit authorization."
    if "takeover" in name:
        return "Confirm dangling record claimability with provider-side ownership checks."
    return "Collect additional deterministic evidence to confirm or reject exploitability."


def _derive_remediation_hint(name: str) -> str:
    if "public cloud storage" in name:
        return "Disable public bucket listing/read unless explicitly required; apply least-privilege bucket policies."
    if "xml-rpc" in name:
        return "Disable XML-RPC if unused, or enforce strict authentication and abuse throttling controls."
    if "header misconfiguration" in name:
        return "Enforce HSTS/CSP/X-Frame-Options/X-Content-Type-Options with tested secure defaults."
    if "cors" in name:
        return "Use an explicit allowlist for trusted origins and avoid credentialed wildcard behavior."
    if "template injection" in name or "ssti" in name:
        return "Enforce strict server-side input handling and disable dangerous template execution paths."
    if "vault" in name:
        return "Restrict Vault control endpoints to trusted networks and harden unauth metadata exposure."
    if "secret" in name or "js exposure" in name:
        return "Remove sensitive artifacts from client bundles and rotate any potentially exposed credentials."
    if "hardcoded password" in name:
        return "Eliminate credential literals from code and move secrets to secure server-side storage."
    if "login attack surface" in name or "brute-force chance" in name:
        return "Add layered anti-automation controls and monitor authentication abuse patterns."
    if "takeover" in name:
        return "Remove unused DNS records and continuously monitor for dangling hostnames."
    return "Apply least-privilege controls and verify remediation with repeatable checks."


def _derive_preconditions(name: str) -> str:
    if "public cloud storage" in name:
        return "Bucket/object ACL or policy permits unauthenticated listing/read."
    if "xml-rpc" in name:
        return "XML-RPC endpoint is reachable from untrusted networks."
    if "header misconfiguration" in name:
        return "Clients rely on browser-enforced security controls for mitigation depth."
    if "cors" in name:
        return "Victim must be authenticated in a browser context where credentials are sent."
    if "template injection" in name or "ssti" in name:
        return "An input path that reaches template rendering logic must be reachable."
    if "vault" in name:
        return "Endpoint must remain externally reachable from untrusted networks."
    if "login attack surface" in name or "brute-force chance" in name:
        return "Authentication endpoints must be publicly reachable."
    if "takeover" in name:
        return "A DNS record must point to an unclaimed third-party resource."
    return "Target behavior must remain consistent with observed verification evidence."


def _derive_reproducibility_notes(status: str, confidence: int, evidence_count: int) -> str:
    if status == "confirmed":
        return (
            f"Reproduced with deterministic checks (confidence {confidence}%, evidence items {evidence_count})."
        )
    if status in {"partial", "needs_manual"}:
        return (
            f"Initial signals reproduced, but deterministic confirmation is incomplete (confidence {confidence}%)."
        )
    return (
        f"Current probe set did not reproduce exploit conditions (confidence {confidence}%)."
    )


def _derive_attacker_action(finding: dict) -> str:
    status = finding.get("status", "")
    name = (finding.get("name") or "").lower()

    if status == "not_confirmed":
        return "No reliable attacker action was confirmed from reproduced evidence."
    if status in {"partial", "needs_manual"}:
        return "Limited abuse may be possible, but exploitability is not yet confirmed without manual validation."

    if "public cloud storage" in name:
        return "Enumerate and retrieve publicly exposed cloud objects without authentication."
    if "xml-rpc" in name:
        return "Abuse XML-RPC/auth endpoints for automated attack traffic if safeguards are weak."
    if "header misconfiguration" in name:
        return "Leverage weaker browser/transport protections to increase exploit reliability."
    if "cors" in name:
        return "Read data from affected endpoints in victim browsers where cross-origin credentials are accepted."
    if "template injection" in name or "ssti" in name:
        return "Unauthorized server-side template evaluation may expose sensitive processing paths if confirmed in depth."
    if "vault" in name:
        return "Exposed control-plane metadata and vulnerable unauth endpoints can increase outage and compromise risk without requiring privileged access."
    if "hardcoded password" in name:
        return "Credential-like literals can increase unauthorized access risk if any values are active."
    if "secret" in name or "js exposure" in name:
        return "Exposed client artifacts may reveal identifiers that reduce attacker effort during reconnaissance."
    if "login attack surface" in name or "brute-force chance" in name:
        return "Weak anti-automation signals can increase the likelihood of automated authentication abuse."
    if "takeover" in name:
        return "A genuinely dangling and claimable hostname could permit trusted-subdomain content control."

    if finding.get("severity") in {"critical", "high"}:
        return "Confirmed conditions indicate meaningful risk to confidentiality or workflow integrity."
    return "Exploitability appears limited within the currently confirmed conditions."


def _format_markdown(summary: dict, findings: list[dict]) -> str:
    lines = []
    lines.append("# Final Truth Verification")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"Generated: {ts}")
    lines.append("")
    lines.append("## Verification Profile")
    lines.append(f"- Program profile: **{summary['profile']}**")
    lines.append(f"- Strictness: **{summary['strictness']}**")
    lines.append(f"- Verification policy: **{summary.get('verification_policy', DEFAULT_VERIFICATION_POLICY)}**")
    lines.append("")
    lines.append("## Verdict")
    lines.append(f"- Bug-bounty ready now: **{summary['ready_count']} / {summary['total_findings']}**")
    lines.append(f"- Actionable evidence-backed findings: **{summary.get('actionable_count', 0)}**")
    lines.append(f"- Confirmed findings: **{summary['confirmed_count']}**")
    lines.append(f"- Needs manual validation: **{summary['manual_count']}**")
    lines.append(f"- Not confirmed / likely false positives: **{summary['rejected_count']}**")
    lines.append("")
    lines.append("## Finding-by-Finding Truth")

    icon_map = {
        "confirmed": "✅",
        "partial": "🟡",
        "needs_manual": "🔎",
        "not_confirmed": "❌",
    }

    for f in findings:
        icon = icon_map.get(f["status"], "•")
        lines.append(f"### {icon} {f['name']} ({f['severity'].upper()})")
        lines.append(f"- Status: **{f['status'].replace('_', ' ').title()}**")
        lines.append(f"- Confidence: **{f['confidence']}%**")
        lines.append(f"- Bug bounty ready now: **{'YES' if f['bounty_ready'] else 'NO'}**")
        lines.append(f"- What attacker could realistically do: {f.get('attacker_action', 'Not determined.')}")
        lines.append(f"- Verification method: {f.get('verification_method', 'Not specified.')}")
        lines.append(f"- Impact scope: {f.get('impact_scope', 'Not specified.')}")
        lines.append(f"- Preconditions: {f.get('preconditions', 'Not specified.')}")
        lines.append(f"- Reproducibility: {f.get('reproducibility', 'Not specified.')}")
        lines.append(f"- Reason: {f['reason']}")
        lines.append(f"- Next deterministic validation step: {f.get('next_validation_step', 'Not specified.')}")
        lines.append(f"- Remediation hint: {f.get('remediation_hint', 'Not specified.')}")
        lines.append(f"- Evidence count: **{f.get('evidence_count', len(f.get('evidence') or []))}**")
        if f["evidence"]:
            lines.append("- Evidence:")
            for ev in f["evidence"][:5]:
                lines.append(f"  - `{ev}`")
        lines.append("")

    lines.append("## Notes")
    lines.append("- This verifier only marks issues as bounty-ready when exploit conditions are reproducible.")
    lines.append("- Strict policy requires stronger confidence and direct-impact proof before bounty-ready promotion.")
    lines.append("- Only test assets where you have permission to perform security testing.")
    return "\n".join(lines)
