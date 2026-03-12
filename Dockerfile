FROM python:3.11-slim

# Bring in a modern Go toolchain for scanner installs.
COPY --from=golang:1.22-bookworm /usr/local/go /usr/local/go

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/usr/local/go/bin:/root/go/bin:/root/.local/bin:${PATH}"

WORKDIR /app

# System packages required by scanner installers and runtime wrappers.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    unzip \
    build-essential \
    libcurl4-openssl-dev \
    ruby-full \
    dnsutils \
    whois \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

COPY . .

# Install external scanner binaries where possible.
RUN chmod +x ./scripts/install_security_tools.sh && ./scripts/install_security_tools.sh || true

# testssl is not auto-installed by the script on Linux; install it explicitly.
RUN git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

EXPOSE 8000

CMD ["python", "-c", "import os,uvicorn; uvicorn.run('main:app', host='0.0.0.0', port=int(os.getenv('PORT','8000')))"]

