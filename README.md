# AI Recon Agent

An autonomous AI-powered security reconnaissance and OSINT agent. Give it a URL to find vulnerabilities, or describe a location to find nearby CCTV cameras — all using real data, zero hallucination.

## Features

- **Website Vulnerability Research** — Autonomous recon: port scanning, header analysis, SSL checks, tech fingerprinting, CVE lookup
- **CCTV Camera Finder** — Real OpenStreetMap data for surveillance cameras near any location
- **Terminal Access** — The AI agent can run shell commands (nmap, whois, dig, nikto, curl, etc.)
- **Web Search** — OSINT via DuckDuckGo
- **No Hallucination** — Agent only reports findings backed by real tool output

## Setup

```bash
# 1. Clone and enter the project
cd "Ai model"

# 2. Install dependencies
pip install -r requirements.txt

# 2b. (Optional, recommended) install external security scanners
./scripts/install_security_tools.sh

# 3. Configure your API key
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY
# Optional: set NETLAS_API_KEY for passive recon (primary backend)
# Optional: set SHODAN_API_KEY as auth/quota fallback backend
# Optional: add WPSCAN_API_TOKEN for WPScan vulnerability intelligence
# Optional: set TRUTH_VERIFICATION_POLICY (strict|balanced|aggressive) for deep-scan verification gating

# 4. Run
python main.py
```

## Usage

```
python main.py
```

Then type your task:
- `Scan https://example.com for vulnerabilities`
- `Deep scan https://example.com and gather tool-backed exploit evidence`
- `I'm at a coffee shop in Shibuya, Tokyo. Find all CCTV cameras around me.`
- `Run run_trufflehog on ./web`
- `Run run_semgrep on . with config auto`
- `Run run_naabu against example.com`
- `Run run_wpscan against https://blog.example.com`
- Type `exit` or `quit` to leave.

## Advanced On-Demand Tools

The following tools are integrated as first-class wrappers and are available on-demand:

- `run_trufflehog` (secret detection)
- `run_gitleaks` (credential leak detection)
- `run_aquatone` (visual recon screenshots/report)
- `run_testssl` (TLS/SSL configuration scan)
- `run_naabu` (fast port scan)
- `run_waybackurls` (historical endpoint discovery)
- `run_arjun` (hidden parameter discovery)
- `run_wfuzz` (web fuzzing)
- `run_semgrep` (static code security analysis)
- `run_wpscan` (WordPress enumeration and vulnerability intelligence)

Default scan chains remain unchanged; these are used when explicitly requested or contextually relevant.
The web UI also includes a `Deep Scan` toggle for aggressive full-coverage runs.

## Artifacts

External scanner artifacts are saved under:

`data/artifacts/<session_id_or_cli>/<tool>/<timestamp>/`

This includes raw output, JSON reports, logs, and visual assets when generated.

## Requirements

- Python 3.11+
- OpenRouter API key
- Optional passive recon keys: `NETLAS_API_KEY` (primary), `SHODAN_API_KEY` (fallback on Netlas auth/quota limits)
- Optional core CLI tools: nmap, nikto, whois, dig
- Optional advanced tools: trufflehog, gitleaks, aquatone, testssl.sh, naabu, waybackurls, arjun, wfuzz, semgrep, wpscan

## Railway Deploy Notes

- Start command (safe): `python -c "import os,uvicorn; uvicorn.run('main:app', host='0.0.0.0', port=int(os.getenv('PORT','8000')))"`  
  (A `Procfile` is included with this command.)
- Required Railway variables:
  - `OPENROUTER_API_KEY` (must be a valid OpenRouter key)
  - `OPENROUTER_MODEL` (for example `openai/gpt-5.4`)
- Optional variables:
  - `TRUTH_VERIFICATION_POLICY`
  - `SHODAN_API_KEY`, `WPSCAN_API_TOKEN`, etc.

If logs show `401 User not found`, the `OPENROUTER_API_KEY` configured in Railway is invalid/revoked or belongs to a different provider.

Important: put the command above in **Start Command**, not **Build Command**.

## Disclaimer

**Only scan websites you own or have explicit permission to test.** Unauthorized scanning is illegal in most jurisdictions.
