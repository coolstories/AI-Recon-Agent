#!/usr/bin/env bash
set -u

ok() { printf "[OK] %s\n" "$1"; }
warn() { printf "[WARN] %s\n" "$1"; }
info() { printf "[INFO] %s\n" "$1"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }
LOCAL_BIN="${HOME}/.local/bin"

try_brew_install() {
  local formula="$1"
  if has_cmd brew; then
    info "brew install ${formula}"
    if brew install "${formula}"; then
      ok "Installed ${formula} via brew"
      return 0
    fi
    warn "brew install ${formula} failed"
  else
    warn "brew not found; cannot install ${formula} via brew"
  fi
  return 1
}

try_go_install() {
  local pkg="$1"
  if has_cmd go; then
    info "go install ${pkg}"
    if go install "${pkg}"; then
      ok "Installed ${pkg} via go install"
      return 0
    fi
    warn "go install ${pkg} failed"
  else
    warn "go not found; cannot install ${pkg}"
  fi
  return 1
}

try_pip_install() {
  local pkg="$1"
  if has_cmd pip3; then
    info "pip3 install ${pkg}"
    if pip3 install "${pkg}"; then
      ok "Installed ${pkg} via pip3"
      return 0
    fi
    warn "pip3 install ${pkg} failed"
  elif has_cmd python3; then
    info "python3 -m pip install ${pkg}"
    if python3 -m pip install "${pkg}"; then
      ok "Installed ${pkg} via python3 -m pip"
      return 0
    fi
    warn "python3 -m pip install ${pkg} failed"
  else
    warn "pip3/python3 not found; cannot install ${pkg}"
  fi
  return 1
}

try_gem_install() {
  local pkg="$1"
  if has_cmd gem; then
    info "gem install ${pkg}"
    if gem install "${pkg}"; then
      ok "Installed ${pkg} via gem"
      return 0
    fi
    warn "gem install ${pkg} failed"
  else
    warn "gem not found; cannot install ${pkg}"
  fi
  return 1
}

try_github_binary_install() {
  local repo="$1"
  local binary="$2"
  local name_regex="$3"

  if ! has_cmd python3; then
    warn "python3 not found; cannot fetch release metadata for ${binary}"
    return 1
  fi
  if ! has_cmd curl; then
    warn "curl not found; cannot download ${binary}"
    return 1
  fi

  mkdir -p "${LOCAL_BIN}"

  local url
  url="$(python3 - "$repo" "$name_regex" <<'PY'
import json
import re
import sys
import urllib.request

repo = sys.argv[1]
name_regex = re.compile(sys.argv[2])
api = f"https://api.github.com/repos/{repo}/releases/latest"
req = urllib.request.Request(api, headers={"User-Agent": "ai-recon-agent-installer"})

try:
    with urllib.request.urlopen(req, timeout=25) as resp:
        payload = json.load(resp)
except Exception:
    print("")
    raise SystemExit(0)

for asset in payload.get("assets", []):
    name = asset.get("name", "")
    if name_regex.search(name):
        print(asset.get("browser_download_url", ""))
        raise SystemExit(0)

print("")
PY
)"

  if [ -z "${url}" ]; then
    warn "Could not find matching ${binary} release asset for this platform"
    return 1
  fi

  local tmpdir archive bin_path
  tmpdir="$(mktemp -d)"
  archive="${tmpdir}/artifact"

  info "Downloading ${binary} from ${url}"
  if ! curl -fsSL "${url}" -o "${archive}"; then
    warn "Download failed for ${binary}"
    rm -rf "${tmpdir}"
    return 1
  fi

  case "${url}" in
    *.tar.gz|*.tgz)
      tar -xzf "${archive}" -C "${tmpdir}" >/dev/null 2>&1 || {
        warn "Failed to extract ${binary} tarball"
        rm -rf "${tmpdir}"
        return 1
      }
      ;;
    *.zip)
      unzip -q "${archive}" -d "${tmpdir}" >/dev/null 2>&1 || {
        warn "Failed to extract ${binary} zip"
        rm -rf "${tmpdir}"
        return 1
      }
      ;;
    *)
      warn "Unknown archive type for ${binary}: ${url}"
      rm -rf "${tmpdir}"
      return 1
      ;;
  esac

  bin_path="$(find "${tmpdir}" -type f -name "${binary}" | head -n 1)"
  if [ -z "${bin_path}" ]; then
    warn "Could not find binary '${binary}' inside downloaded archive"
    rm -rf "${tmpdir}"
    return 1
  fi

  chmod +x "${bin_path}" || true
  cp "${bin_path}" "${LOCAL_BIN}/${binary}" || {
    warn "Failed to copy ${binary} into ${LOCAL_BIN}"
    rm -rf "${tmpdir}"
    return 1
  }
  rm -rf "${tmpdir}"

  export PATH="${LOCAL_BIN}:${PATH}"
  ok "Installed ${binary} in ${LOCAL_BIN}/${binary}"
  return 0
}

ensure_or_install() {
  local binary="$1"
  local label="$2"
  local install_fn="$3"
  local install_arg="$4"

  if has_cmd "${binary}"; then
    ok "${label} already installed (${binary})"
    return 0
  fi

  warn "${label} not found (${binary})"
  "${install_fn}" "${install_arg}" || true

  if has_cmd "${binary}"; then
    ok "${label} installed (${binary})"
  else
    warn "${label} still missing (${binary})"
  fi
}

info "Bootstrapping external security tools..."
mkdir -p "${LOCAL_BIN}"
export PATH="${LOCAL_BIN}:${PATH}"

# Core scan engines used by normal/deep scan chains
if ! has_cmd ffuf; then
  warn "ffuf not found"
  try_brew_install "ffuf" || true
fi
if ! has_cmd ffuf; then
  try_go_install "github.com/ffuf/ffuf/v2@latest" || true
fi
if ! has_cmd ffuf; then
  try_github_binary_install "ffuf/ffuf" "ffuf" "(?i)(darwin|macos).*(arm64|aarch64).*(\\.tar\\.gz|\\.tgz)$" || true
fi
if has_cmd ffuf; then
  ok "ffuf installed ($(command -v ffuf))"
else
  warn "ffuf still missing"
fi

if ! has_cmd nuclei; then
  warn "nuclei not found"
  try_brew_install "nuclei" || true
fi
if ! has_cmd nuclei; then
  try_go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" || true
fi
if ! has_cmd nuclei; then
  try_github_binary_install "projectdiscovery/nuclei" "nuclei" "(?i)(darwin|macos).*(arm64|aarch64).*\\.zip$" || true
fi
if has_cmd nuclei; then
  ok "nuclei installed ($(command -v nuclei))"
else
  warn "nuclei still missing"
fi

# Secret/code scanners
ensure_or_install "trufflehog" "TruffleHog" try_brew_install "trufflehog"
ensure_or_install "gitleaks" "GitLeaks" try_brew_install "gitleaks"
ensure_or_install "semgrep" "Semgrep" try_pip_install "semgrep"

# Recon/fuzzing tools
ensure_or_install "naabu" "Naabu" try_go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
ensure_or_install "waybackurls" "Waybackurls" try_go_install "github.com/tomnomnom/waybackurls@latest"
ensure_or_install "arjun" "Arjun" try_pip_install "arjun"
ensure_or_install "wfuzz" "Wfuzz" try_pip_install "wfuzz"
if has_cmd wpscan; then
  ok "WPScan already installed ($(command -v wpscan))"
else
  warn "WPScan not found"
  if has_cmd brew; then
    info "brew install wpscanteam/tap/wpscan"
    brew install wpscanteam/tap/wpscan || true
  fi
fi
if ! has_cmd wpscan; then
  try_gem_install "wpscan" || true
fi
if has_cmd wpscan; then
  ok "WPScan installed ($(command -v wpscan))"
else
  warn "WPScan still missing; install with:"
  info "brew install wpscanteam/tap/wpscan"
  info "or: gem install wpscan"
  info "or docker: docker run --rm wpscanteam/wpscan --help"
fi

# TLS and visual recon
if has_cmd testssl.sh || has_cmd testssl; then
  ok "testssl already installed"
else
  warn "testssl/testssl.sh not found"
  try_brew_install "testssl" || true
  if has_cmd testssl.sh || has_cmd testssl; then
    ok "testssl installed"
  else
    warn "testssl still missing; manual install: git clone https://github.com/testssl/testssl.sh"
  fi
fi

if has_cmd aquatone; then
  ok "Aquatone already installed"
else
  warn "Aquatone not found; no reliable package manager formula detected"
  info "Install Aquatone manually from release binaries:"
  info "https://github.com/michenriksen/aquatone/releases"
fi

info "Bootstrap complete. Verify with:"
info "ffuf -h && nuclei -h && trufflehog --help && gitleaks --help && semgrep --help"
info "If binaries were installed in ${LOCAL_BIN}, ensure your shell PATH includes it:"
info "export PATH=\"${LOCAL_BIN}:\$PATH\""
