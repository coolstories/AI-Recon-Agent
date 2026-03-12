"""
Cloud infrastructure recon — S3 bucket enumeration, Azure blob storage,
GCP storage, exposed cloud assets, metadata endpoints.
Targets like Apple/Google have massive cloud footprints.
"""

import requests
import json
import time
import re
import socket
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from tools.target_reachability import (
    format_fallback_notice,
    format_unreachable_error,
    resolve_web_target,
)

HDR = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# S3 bucket name permutations
def _generate_bucket_names(domain):
    """Generate potential S3 bucket names from domain."""
    base = domain.replace("www.", "").split(".")[0]
    tld = domain.replace("www.", "")
    names = set()
    
    # Direct names
    for name in [base, tld.replace(".", "-"), tld.replace(".", "")]:
        names.add(name)
        # Common suffixes
        for suffix in [
            "-backup", "-bak", "-old", "-dev", "-staging", "-stage", "-prod",
            "-production", "-test", "-qa", "-uat", "-data", "-db", "-database",
            "-assets", "-static", "-media", "-images", "-img", "-files",
            "-uploads", "-download", "-downloads", "-public", "-private",
            "-internal", "-logs", "-log", "-debug", "-temp", "-tmp",
            "-archive", "-archives", "-cdn", "-content", "-web", "-www",
            "-api", "-app", "-mobile", "-ios", "-android", "-docs",
            "-documentation", "-config", "-configs", "-secrets",
            "-deploy", "-deployment", "-ci", "-cd", "-build", "-builds",
            "-release", "-releases", "-packages", "-artifacts",
            "-reports", "-analytics", "-metrics", "-monitoring",
            "-email", "-mail", "-marketing", "-crm",
            ".backup", ".dev", ".staging", ".prod", ".assets", ".media",
        ]:
            names.add(f"{name}{suffix}")
        # Common prefixes
        for prefix in ["backup-", "dev-", "staging-", "prod-", "data-", "assets-", "cdn-", "static-"]:
            names.add(f"{prefix}{name}")
    
    return list(names)


def _check_s3_bucket(name):
    """Check if S3 bucket exists and its permissions."""
    results = {"name": name, "exists": False, "public_list": False, "public_read": False}
    
    # Check via HTTP
    for region_url in [
        f"https://{name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{name}",
    ]:
        try:
            r = requests.get(region_url, timeout=5, headers=HDR)
            if r.status_code == 200:
                results["exists"] = True
                if "<ListBucketResult" in r.text:
                    results["public_list"] = True
                    # Extract some file keys
                    keys = re.findall(r'<Key>([^<]+)</Key>', r.text)
                    results["files"] = keys[:20]
                    results["total_files"] = len(keys)
                return results
            elif r.status_code == 403:
                results["exists"] = True
                return results
            elif r.status_code == 301:
                # Bucket exists but in different region
                results["exists"] = True
                location = r.headers.get("x-amz-bucket-region", "")
                results["region"] = location
                return results
        except Exception:
            pass
    return results


def _check_azure_blob(name):
    """Check Azure blob storage containers."""
    results = {"name": name, "exists": False, "public_list": False}
    
    for container in ["$web", "public", "data", "assets", "media", "backup", "files", "uploads", "static", "images"]:
        url = f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
        try:
            r = requests.get(url, timeout=5, headers=HDR)
            if r.status_code == 200:
                results["exists"] = True
                if "<Blob>" in r.text or "<Name>" in r.text:
                    results["public_list"] = True
                    results["container"] = container
                    blobs = re.findall(r'<Name>([^<]+)</Name>', r.text)
                    results["files"] = blobs[:20]
                return results
            elif r.status_code == 403:
                results["exists"] = True
                return results
        except Exception:
            pass
    return results


def _check_gcp_bucket(name):
    """Check Google Cloud Storage buckets."""
    results = {"name": name, "exists": False, "public_list": False}
    
    url = f"https://storage.googleapis.com/{name}"
    try:
        r = requests.get(url, timeout=5, headers=HDR)
        if r.status_code == 200:
            results["exists"] = True
            if "<ListBucketResult" in r.text or "<Contents>" in r.text:
                results["public_list"] = True
                keys = re.findall(r'<Key>([^<]+)</Key>', r.text)
                results["files"] = keys[:20]
            return results
        elif r.status_code == 403:
            results["exists"] = True
            return results
    except Exception:
        pass
    return results


def _check_firebase(domain):
    """Check for exposed Firebase databases."""
    findings = []
    base = domain.replace("www.", "").split(".")[0]
    
    names = [base, f"{base}-default-rtdb", f"{base}-prod", f"{base}-dev"]
    for name in names:
        url = f"https://{name}.firebaseio.com/.json"
        try:
            r = requests.get(url, timeout=5, headers=HDR)
            if r.status_code == 200 and r.text != "null":
                try:
                    data = r.json()
                    if data:
                        findings.append({
                            "url": url,
                            "severity": "CRITICAL",
                            "desc": f"Firebase database exposed without auth! Data accessible at {url}",
                            "preview": str(data)[:300],
                        })
                except Exception:
                    pass
            elif r.status_code == 401:
                # Exists but requires auth
                findings.append({
                    "url": url,
                    "severity": "INFO",
                    "desc": f"Firebase database exists (auth required): {url}",
                })
        except Exception:
            pass
    return findings


def _check_cloud_metadata(base_url):
    """Check if SSRF to cloud metadata is possible via various params."""
    findings = []
    metadata_urls = {
        "AWS": "http://169.254.169.254/latest/meta-data/",
        "GCP": "http://metadata.google.internal/computeMetadata/v1/",
        "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    }
    
    # Check if any discovered endpoints proxy requests
    try:
        r = requests.get(base_url, timeout=10, headers=HDR, verify=False)
        # Look for cloud indicators in response
        cloud_indicators = {
            "AWS": ["amazonaws.com", "aws-", "x-amz-", "ec2", "elasticbeanstalk"],
            "GCP": ["googleapis.com", "appspot.com", "cloudfunctions", "run.app", "googleusercontent.com"],
            "Azure": ["azurewebsites.net", "azure.com", "cloudapp.net", "blob.core.windows.net"],
        }
        for cloud, indicators in cloud_indicators.items():
            for ind in indicators:
                if ind in r.text.lower() or ind in str(r.headers).lower():
                    findings.append({
                        "cloud": cloud,
                        "indicator": ind,
                        "severity": "INFO",
                        "desc": f"Cloud provider detected: {cloud} (indicator: {ind})",
                    })
                    break
    except Exception:
        pass
    
    return findings


def cloud_recon(target, stream_callback=None):
    """
    Enumerate cloud storage buckets, Firebase DBs, and detect cloud infrastructure.
    """
    def _emit(msg):
        if stream_callback:
            stream_callback("cloud_progress", {"message": msg})

    _emit("🌐 Resolving reachable target URL...")
    resolution = resolve_web_target(target, headers=HDR)
    if not resolution.get("ok"):
        _emit("  ❌ Target unreachable across allowed URL variants")
        return format_unreachable_error(target, resolution)

    base = (resolution.get("selected_url") or resolution.get("normalized_url") or target).rstrip("/")
    fallback_note = format_fallback_notice(resolution)
    if fallback_note:
        _emit("  ↪ %s" % fallback_note)

    domain = (urlparse(base).netloc or "").split("@")[-1].split(":")[0]

    _emit(f"🎯 Cloud Infrastructure Recon: {domain}")
    start = time.time()
    findings = []

    # Phase 1: Generate bucket names
    bucket_names = _generate_bucket_names(domain)
    _emit(f"🔍 Testing {len(bucket_names)} bucket name permutations...")

    # Phase 2: S3 bucket enumeration
    _emit("☁️ Phase 1: AWS S3 bucket enumeration...")
    s3_found = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_s3_bucket, n): n for n in bucket_names}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 20 == 0:
                _emit(f"  S3: {done}/{len(bucket_names)} checked...")
            result = future.result()
            if result["exists"]:
                s3_found.append(result)
                if result["public_list"]:
                    _emit(f"  🔴 PUBLIC S3 BUCKET: {result['name']} ({result.get('total_files', 0)} files!)")
                else:
                    _emit(f"  🟡 S3 bucket exists: {result['name']} (private)")

    # Phase 3: Azure blob storage
    _emit("☁️ Phase 2: Azure Blob Storage enumeration...")
    azure_found = []
    azure_names = _generate_bucket_names(domain)[:30]
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_check_azure_blob, n): n for n in azure_names}
        for future in as_completed(futures):
            result = future.result()
            if result["exists"]:
                azure_found.append(result)
                if result["public_list"]:
                    _emit(f"  🔴 PUBLIC AZURE BLOB: {result['name']} (container: {result.get('container','')})")

    # Phase 4: GCP storage
    _emit("☁️ Phase 3: Google Cloud Storage enumeration...")
    gcp_found = []
    gcp_names = _generate_bucket_names(domain)[:30]
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_check_gcp_bucket, n): n for n in gcp_names}
        for future in as_completed(futures):
            result = future.result()
            if result["exists"]:
                gcp_found.append(result)
                if result["public_list"]:
                    _emit(f"  🔴 PUBLIC GCP BUCKET: {result['name']}")

    # Phase 5: Firebase
    _emit("🔥 Phase 4: Firebase database check...")
    firebase = _check_firebase(domain)
    for fb in firebase:
        _emit(f"  {'🔴' if fb['severity'] == 'CRITICAL' else '🟡'} Firebase: {fb['desc']}")

    # Phase 6: Cloud provider detection
    _emit("🔍 Phase 5: Cloud provider detection...")
    cloud_info = _check_cloud_metadata(base)

    # Phase 7: Check for exposed cloud config files
    _emit("📂 Phase 6: Checking for exposed cloud configs...")
    config_paths = [
        ("/.env", "Environment variables"),
        ("/.aws/credentials", "AWS credentials file"),
        ("/aws.yml", "AWS config"),
        ("/docker-compose.yml", "Docker compose (may contain cloud creds)"),
        ("/terraform.tfstate", "Terraform state (contains all cloud resources!)"),
        ("/terraform.tfvars", "Terraform variables"),
        ("/.terraform/", "Terraform directory"),
        ("/kubernetes.yml", "Kubernetes config"),
        ("/k8s.yml", "Kubernetes config"),
        ("/.kube/config", "Kubernetes kubeconfig"),
        ("/serverless.yml", "Serverless framework config"),
        ("/amplify.yml", "AWS Amplify config"),
        ("/firebase.json", "Firebase config"),
        ("/google-credentials.json", "GCP service account key"),
        ("/service-account.json", "GCP service account"),
        ("/cloudbuild.yaml", "GCP Cloud Build"),
        ("/azure-pipelines.yml", "Azure DevOps pipeline"),
        ("/Dockerfile", "Dockerfile (may contain secrets)"),
        ("/.dockerenv", "Docker environment indicator"),
        ("/wp-config.php.bak", "WordPress config backup"),
        ("/.git/config", "Git config (may contain tokens)"),
    ]
    
    exposed_configs = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        def check_config(path_info):
            path, desc = path_info
            try:
                r = requests.get(f"{base}{path}", timeout=5, headers=HDR, verify=False)
                if r.status_code == 200 and len(r.text) > 10:
                    if "404" not in r.text[:200].lower() and "not found" not in r.text[:200].lower():
                        return {"path": path, "desc": desc, "size": len(r.text), "preview": r.text[:200]}
            except Exception:
                pass
            return None
        
        futures = {executor.submit(check_config, p): p for p in config_paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                exposed_configs.append(result)
                _emit(f"  🔴 EXPOSED: {result['path']} — {result['desc']}")

    elapsed = time.time() - start

    # Format output
    lines = [
        f"CLOUD RECON for {domain}",
        f"{'='*60}",
        f"Tested: {len(bucket_names)} bucket names across AWS/Azure/GCP",
        f"Time: {elapsed:.1f}s\n",
    ]
    if fallback_note:
        lines = [fallback_note, ""] + lines

    # S3 findings
    public_s3 = [b for b in s3_found if b["public_list"]]
    private_s3 = [b for b in s3_found if not b["public_list"]]
    
    if public_s3:
        lines.append("🔴 PUBLIC S3 BUCKETS (CRITICAL)")
        lines.append("-" * 40)
        for b in public_s3:
            lines.append(f"  https://{b['name']}.s3.amazonaws.com")
            lines.append(f"    Files: {b.get('total_files', '?')} — PUBLICLY LISTABLE")
            if b.get("files"):
                for f in b["files"][:10]:
                    lines.append(f"      {f}")
            lines.append(f"    PoC: curl 'https://{b['name']}.s3.amazonaws.com'")
            lines.append(f"    aws s3 ls s3://{b['name']}/ --no-sign-request")
        lines.append("")

    if private_s3:
        lines.append(f"🟡 PRIVATE S3 BUCKETS ({len(private_s3)} found)")
        lines.append("-" * 40)
        for b in private_s3[:10]:
            lines.append(f"  {b['name']} (exists, ACL blocks listing)")
        lines.append("")

    # Azure findings
    public_azure = [b for b in azure_found if b["public_list"]]
    if public_azure:
        lines.append("🔴 PUBLIC AZURE BLOBS (CRITICAL)")
        lines.append("-" * 40)
        for b in public_azure:
            lines.append(f"  https://{b['name']}.blob.core.windows.net/{b.get('container','')}")
            if b.get("files"):
                for f in b["files"][:10]:
                    lines.append(f"    {f}")
        lines.append("")

    # GCP findings
    public_gcp = [b for b in gcp_found if b["public_list"]]
    if public_gcp:
        lines.append("🔴 PUBLIC GCP BUCKETS (CRITICAL)")
        lines.append("-" * 40)
        for b in public_gcp:
            lines.append(f"  https://storage.googleapis.com/{b['name']}")
            if b.get("files"):
                for f in b["files"][:10]:
                    lines.append(f"    {f}")
        lines.append("")

    # Firebase
    if firebase:
        for fb in firebase:
            icon = "🔴" if fb["severity"] == "CRITICAL" else "🟡"
            lines.append(f"{icon} FIREBASE: {fb['desc']}")
            if fb.get("preview"):
                lines.append(f"  Data preview: {fb['preview'][:200]}")
        lines.append("")

    # Cloud info
    if cloud_info:
        lines.append("☁️ CLOUD PROVIDER DETECTED")
        lines.append("-" * 40)
        for ci in cloud_info:
            lines.append(f"  {ci['cloud']}: {ci['indicator']}")
        lines.append("")

    # Exposed configs
    if exposed_configs:
        lines.append("🔴 EXPOSED CLOUD CONFIGS")
        lines.append("-" * 40)
        for c in exposed_configs:
            lines.append(f"  {c['path']} — {c['desc']} ({c['size']} bytes)")
            lines.append(f"    curl '{base}{c['path']}'")
        lines.append("")

    total = len(public_s3) + len(public_azure) + len(public_gcp) + len(firebase) + len(exposed_configs)
    if total == 0:
        lines.append("No publicly accessible cloud storage or configs found.")
        if s3_found or azure_found or gcp_found:
            lines.append(f"However, {len(s3_found) + len(azure_found) + len(gcp_found)} private buckets were confirmed to exist.")

    return "\n".join(lines)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "cloud_recon",
        "description": "Enumerate cloud storage buckets (AWS S3, Azure Blob, GCP Storage), Firebase databases, and exposed cloud configuration files. Generates bucket name permutations from the target domain and tests for public listing, read access, and sensitive file exposure. Also checks for exposed Terraform state, Docker configs, Kubernetes configs, and cloud credentials.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain or URL for cloud recon"
                }
            },
            "required": ["target"]
        }
    }
}
