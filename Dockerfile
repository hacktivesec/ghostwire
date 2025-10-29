# syntax=docker/dockerfile:1

#######################################################################
# Make BASE_IMAGE available to any FROM (must be before the first FROM)
#######################################################################
ARG BASE_IMAGE=ubuntu:24.04

# --- Stage 0: build bulk_extractor from source ---
FROM ubuntu:24.04 AS bulkbuilder
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends \
    ca-certificates curl \
    build-essential autoconf automake libtool pkg-config git \
    python3 flex \
    libewf-dev libafflib-dev libtre-dev zlib1g-dev libssl-dev \
    libexpat1-dev libpcap-dev libsqlite3-dev libre2-dev libpcre3-dev; \
  update-ca-certificates; \
  git clone --depth=1 --recurse-submodules \
    https://github.com/simsong/bulk_extractor.git /src/bulk_extractor; \
  cd /src/bulk_extractor; \
  ./bootstrap.sh; \
  ./configure; \
  make -j"$(nproc)"; \
  make install DESTDIR=/opt/be-install


############################
# Stage 1: main image
############################
FROM ${BASE_IMAGE} AS base

LABEL org.opencontainers.image.title="ghostwire" \
      org.opencontainers.image.description="Ultra-lean web/network/AD toolkit + hashcat. SOCKS-ready. SecLists baked. Minimal bloat." \
      org.opencontainers.image.vendor="ghostwire" \
      org.opencontainers.image.version="dev" \
      org.opencontainers.image.licenses="CC0-1.0"

ARG SECLISTS_SHA=HEAD

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LC_ALL=C.UTF-8 LANG=C.UTF-8 \
    PIP_NO_CACHE_DIR=1 \
    TERM=xterm-256color \
    SECLISTS=/opt/seclists \
    ARTIFACTS=/shared \
    GHOST_LABEL=security \
    SOCKS5_HOST=127.0.0.1 \
    SOCKS5_PORT=1080

# ---- Core packages (no recommends) ----
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates tzdata curl wget git jq sudo \
      nano less bash-completion \
      python3 python3-pip python3-venv \
      # web (dirsearch removed)
      gobuster nikto sqlmap wfuzz whatweb wafw00f testssl.sh \
      # network
      nmap masscan dnsutils iputils-ping traceroute netcat-openbsd socat tcpdump iproute2 openssl \
      # AD/auth
      samba-common-bin krb5-user ldap-utils smbclient python3-impacket \
      # cracking
      hashcat ocl-icd-libopencl1 pocl-opencl-icd clinfo john hydra \
      # QoL/cli
      ripgrep fd-find fzf whois tree rsync bat proxychains4 openssh-client unzip zip procps tini tar \
      # tiny hardware sanity tools
      iw wireless-tools usbutils kmod \
    && apt-get autoremove -y --purge && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/cache/apt/archives/* && \
    rm -rf /usr/share/man/* /usr/share/doc/* /usr/share/locale/* || true

# ---- Wordlists (SecLists) ----
RUN set -eux; \
    git clone https://github.com/danielmiessler/SecLists "${SECLISTS}"; \
    if [ "${SECLISTS_SHA}" != "HEAD" ]; then cd "${SECLISTS}" && git fetch --depth=1 origin "${SECLISTS_SHA}" && git checkout "${SECLISTS_SHA}"; fi; \
    rm -rf "${SECLISTS}/.git" || true

# ---- Python venv (base toolset) ----
RUN python3 -m venv /opt/ghost-venv && \
    /opt/ghost-venv/bin/python -m pip install --upgrade pip "setuptools<81" wheel && \
    /opt/ghost-venv/bin/pip install --no-cache-dir \
      "httpx[socks]" httpx-ntlm requests requests-ntlm requests-toolbelt PySocks \
      jinja2 markupsafe cryptography cffi pyopenssl colorama beautifulsoup4 defusedxml pyparsing \
      "psycopg[binary]" mysql-connector-python \
      ldapdomaindump bloodhound smbmap sublist3r "sslyze==6.2.0" \
    && true

# ---- SecretFinder (repo is not a pip package; clone + reqs + wrapper) ----
RUN git clone --depth=1 https://github.com/m4ll0k/SecretFinder.git /opt/secretfinder && \
    /opt/ghost-venv/bin/pip install --no-cache-dir -r /opt/secretfinder/requirements.txt && \
    printf '#!/bin/sh\nexec /opt/ghost-venv/bin/python /opt/secretfinder/SecretFinder.py "$@"\n' \
      > /usr/local/bin/secretfinder && \
    chmod +x /usr/local/bin/secretfinder

# ---- PATH shims to venv CLIs ----
RUN set -eux; \
  mkdir -p /usr/local/bin; \
  for name in bloodhound bloodhound-python smbmap sublist3r sslyze ldapdomaindump; do \
    tgt="$name"; src="$name"; [ "$name" = "bloodhound-python" ] && src="bloodhound"; \
    printf '%s\n' '#!/usr/bin/env bash' "exec /opt/ghost-venv/bin/${src} \"\$@\"" > "/usr/local/bin/${tgt}"; \
    chmod +x "/usr/local/bin/${tgt}"; \
  done

# ---- Helpers ----
RUN cat > /usr/local/bin/savehere <<'SH' && chmod +x /usr/local/bin/savehere
#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then echo "usage: savehere <file|dir> [...]" >&2; exit 2; fi
mkdir -p "${ARTIFACTS}"
for p in "$@"; do
  base=$(basename "$p")
  target="${ARTIFACTS}/${base}"
  [ -e "$target" ] && target="${target}_$(date +%s)"
  cp -a "$p" "$target"
done
echo "saved to ${ARTIFACTS}"
SH

RUN cat > /usr/local/bin/update-seclists <<'SH' && chmod +x /usr/local/bin/update-seclists
#!/usr/bin/env bash
set -euo pipefail
SECLISTS="${SECLISTS:-/opt/seclists}"
tmp="$(mktemp -d)"
echo "[gw] refreshing SecLists..."
git clone --depth=1 https://github.com/danielmiessler/SecLists "$tmp"
rsync -a --delete "$tmp"/ "$SECLISTS"/
rm -rf "$tmp"
echo "[gw] SecLists refreshed."
SH

# px: run any command via SOCKS5 (DNS resolved on proxy)
RUN cat > /usr/local/bin/px <<'PC' && chmod +x /usr/local/bin/px
#!/usr/bin/env bash
set -euo pipefail
H="${SOCKS5_HOST:-127.0.0.1}"
P="${SOCKS5_PORT:-1080}"
CFG="$(mktemp /tmp/proxychains.XXXXXX)"
trap 'rm -f "$CFG"' EXIT INT TERM
cat >"$CFG"<<PCFG
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 $H $P
PCFG
exec proxychains4 -q -f "$CFG" "$@"
PC

RUN printf '#!/usr/bin/env bash\nexec px curl "$@"\n' > /usr/local/bin/pxcurl && chmod +x /usr/local/bin/pxcurl && \
    printf '#!/usr/bin/env bash\nexec px wget "$@"\n' > /usr/local/bin/pxwget && chmod +x /usr/local/bin/pxwget

RUN cat > /usr/local/bin/out <<'SH' && chmod +x /usr/local/bin/out
#!/usr/bin/env bash
set -euo pipefail
if [ $# -eq 0 ]; then
  echo "usage: out <command> [args...]" >&2
  exit 2
fi
cmd="$1"; shift
log="${ARTIFACTS:-/shared}/$(basename "$cmd")_$(date +%s).log"
( "$cmd" "$@" ; exit $? ) 2>&1 | tee "$log"
exit ${PIPESTATUS[0]}
SH

RUN cat > /usr/local/bin/session-log <<'SH' && chmod +x /usr/local/bin/session-log
#!/usr/bin/env bash
set -euo pipefail
mkdir -p /shared/history
export HISTFILE="/shared/history/$(date +%F_%H%M%S).bash_history"
export PROMPT_COMMAND='history -a'
exec bash -l
SH

# ---- Hardware helpers (lean) ----
RUN cat > /usr/local/bin/gw-wifi-capture <<'SH' && chmod +x /usr/local/bin/gw-wifi-capture
#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-}"; OUT="${2:-/shared/wifi.pcap}"
if [ -z "$IFACE" ]; then
  echo "usage: gw-wifi-capture <iface> [outfile]" >&2
  echo "prepare monitor mode on HOST, then run inside container: gw-wifi-capture wlan0 /shared/wifi.pcap" >&2
  exit 2
fi
echo "[gw] iface: $IFACE  out: $OUT"
iw dev 2>/dev/null || true
echo "[gw] starting capture (needs NET_RAW/NET_ADMIN caps or sudo rights)"
sudo -n tcpdump -i "$IFACE" -s 0 -w "$OUT"
echo "[gw] saved: $OUT"
SH

RUN cat > /usr/local/bin/gw-usb-capture <<'SH' && chmod +x /usr/local/bin/gw-usb-capture
#!/usr/bin/env bash
set -euo pipefail
MON="${1:-usbmon0}"; OUT="${2:-/shared/usb.pcap}"
if [ ! -e /sys/kernel/debug/usb/usbmon ] && [ ! -e /sys/kernel/debug/usb/"$MON" ]; then
  echo "usbmon unavailable. On HOST: sudo modprobe usbmon && sudo mount -t debugfs none /sys/kernel/debug" >&2
  echo "run container with: -v /sys/kernel/debug:/sys/kernel/debug:ro -v /dev/bus/usb:/dev/bus/usb:ro" >&2
fi
lsusb 2>/dev/null || true
echo "[gw] capturing from $MON -> $OUT"
sudo -n tcpdump -i "$MON" -s 0 -w "$OUT"
echo "[gw] saved: $OUT"
SH

RUN cat > /usr/local/bin/gw-ssh-agent-check <<'SH' && chmod +x /usr/local/bin/gw-ssh-agent-check
#!/usr/bin/env bash
set -euo pipefail
if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "${SSH_AUTH_SOCK}" ]; then
  echo "[gw] SSH agent socket mounted: $SSH_AUTH_SOCK"
  exit 0
fi
echo "[gw] No SSH agent. Set and mount: export SSH_AUTH_SOCK; run with -e SSH_AUTH_SOCK -v "$SSH_AUTH_SOCK:/ssh-agent" and point env to /ssh-agent" >&2
exit 1
SH

RUN cat > /usr/local/bin/gw-gpu-check <<'SH' && chmod +x /usr/local/bin/gw-gpu-check
#!/usr/bin/env bash
set -euo pipefail
echo "[gw] hashcat devices:"
hashcat -I || true
if command -v nvidia-smi >/dev/null 2>&1; then
  echo "[gw] nvidia-smi:"
  nvidia-smi || true
else
  echo "[gw] nvidia-smi not found. For NVIDIA: install nvidia-container-toolkit on host and run --gpus all"
fi
SH

# ---- QoL: aliases + prompt (bash-only guard) ----
RUN ln -s /usr/bin/fdfind /usr/local/bin/fd || true && \
    ln -s /usr/bin/batcat /usr/local/bin/bat || true && \
    cat > /etc/profile.d/ghostwire.sh <<'PSH' && chmod 0644 /etc/profile.d/ghostwire.sh
[ -n "$BASH_VERSION" ] || return 0
export SECLISTS=/opt/seclists
export ARTIFACTS=/shared
alias ll='ls -alF --color=auto'
alias bat='bat --paging=never'
alias fd='fdfind'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignorespace:erasedups
GHOST_LABEL=${GHOST_LABEL:-security}
ghost_prompt(){ local r=$?; if [ $r -eq 0 ]; then GS="\[\e[1;32m\]✔"; else GS="\[\e[1;31m\]✘"; fi; export GS; }
PROMPT_COMMAND=ghost_prompt
PS1="\[\e[90m\][\A]\[\e[0m\] \[\e[1;32m\]ghostwire\[\e[0m\]\[\e[90m\]@\[\e[0m\]\[\e[90m\]${GHOST_LABEL}\[\e[0m\] \[\e[90m\](\w)\[\e[0m\]\n${GS}\[\e[90m\]>\[\e[0m\] "
if [ -n "${SOCKS5_HOST:-}" ]; then echo "[px] SOCKS5 target: ${SOCKS5_HOST}:${SOCKS5_PORT:-1080}"; fi
PSH

# ---- CRLF guard for scripts ----
RUN sed -i 's/\r$//' \
  /usr/local/bin/px \
  /usr/local/bin/savehere \
  /usr/local/bin/update-seclists \
  /usr/local/bin/pxcurl \
  /usr/local/bin/pxwget \
  /usr/local/bin/session-log \
  /usr/local/bin/out \
  /usr/local/bin/gw-wifi-capture \
  /usr/local/bin/gw-usb-capture \
  /usr/local/bin/gw-ssh-agent-check \
  /usr/local/bin/gw-gpu-check \
  /usr/local/bin/secretfinder \
  /usr/local/bin/sublist3r \
  /usr/local/bin/sslyze \
  /usr/local/bin/smbmap \
  /usr/local/bin/bloodhound \
  /usr/local/bin/bloodhound-python \
  /usr/local/bin/ldapdomaindump \
  /etc/profile.d/ghostwire.sh || true

# ---- Non-root + sudo (NOPASSWD:ALL) ----
RUN groupadd -r ghost && useradd -m -g ghost -s /bin/bash ghost && \
    mkdir -p /work "${ARTIFACTS}" /opt/tools && \
    chown -R ghost:ghost /work "${ARTIFACTS}" /opt/tools /opt/ghost-venv "${SECLISTS}" && \
    printf 'ghost ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/ghost && \
    chmod 0440 /etc/sudoers.d/ghost

USER ghost
WORKDIR /work

VOLUME ["/shared", "/work"]

# ---- Healthcheck (dirsearch removed) ----
HEALTHCHECK --interval=1h --timeout=10s --start-period=20s --retries=3 \
  CMD sh -c 'command -v nmap >/dev/null 2>&1 && command -v hashcat >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || exit 1'

STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/bin/bash"]


# =========================
# ONLY ADDITIONS BELOW
# =========================

# become root for the added installs
USER root

# ---- APT: network/service, wireless, forensics, apktool, dirb, wpscan deps (NO apt bulk-extractor here) ----
RUN set -eux; \
  mkdir -p /usr/share/man/man1; \
  apt-get update; \
  apt-get install -y --no-install-recommends \
    # Network & Service Exploitation
    snmp onesixtyone ike-scan patator medusa \
    # Wireless
    aircrack-ng reaver bully \
    # Stego & Forensics
    steghide libimage-exiftool-perl binwalk foremost \
    # Mobile (needs Java)
    apktool \
    # Web extras
    dirb \
    # WPScan deps
    libcurl4-openssl-dev \
  ; \
  rm -rf /var/lib/apt/lists/*

# ---- enum4linux (classic) ----
RUN set -eux; \
  git clone --depth=1 https://github.com/portcullislabs/enum4linux /opt/enum4linux && \
  rm -rf /opt/enum4linux/.git && \
  ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux

# ---- joomscan (Perl wrapper to upstream) ----
RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends perl libwww-perl liblwp-protocol-https-perl; \
  git clone --depth=1 https://github.com/OWASP/joomscan /opt/joomscan && rm -rf /opt/joomscan/.git; \
  printf '#!/usr/bin/env bash\nexec perl /opt/joomscan/joomscan.pl "$@"\n' >/usr/local/bin/joomscan; \
  chmod +x /usr/local/bin/joomscan; \
  rm -rf /var/lib/apt/lists/*

# ---- jadx (release zip) ----
RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends default-jre-headless unzip; \
  curl -fsSL -o /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip; \
  rm -rf /opt/jadx && mkdir -p /opt/jadx; \
  unzip -q /tmp/jadx.zip -d /opt/jadx; \
  if [ -d /opt/jadx/bin ]; then :; \
  elif ls -d /opt/jadx/jadx-*/bin >/dev/null 2>&1; then jd="$(ls -d /opt/jadx/jadx-*)"; mv "$jd"/* /opt/jadx/; rmdir "$jd" || true; \
  else echo "jadx: no bin/ found after unzip"; find /opt/jadx -maxdepth=2 -type d -print; exit 1; fi; \
  ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx; \
  ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui; \
  rm -f /tmp/jadx.zip; \
  rm -rf /var/lib/apt/lists/*

# ---- bulk_extractor: bring in binaries from builder stage ----
COPY --from=bulkbuilder /opt/be-install/usr/local/ /usr/local/

# ---- Post-Exploitation repos: PowerSploit, Empire (clone only) ----
RUN set -eux; \
  git clone --depth=1 https://github.com/PowerShellMafia/PowerSploit /opt/PowerSploit || true; \
  rm -rf /opt/PowerSploit/.git || true; \
  git clone --depth=1 https://github.com/BC-SECURITY/Empire /opt/empire || true; \
  rm -rf /opt/empire/.git || true

# ---- CloudMapper (clone only) & MobSF (clone only) ----
RUN set -eux; \
  git clone --depth=1 https://github.com/duo-labs/cloudmapper /opt/cloudmapper || true; \
  rm -rf /opt/cloudmapper/.git || true; \
  git clone --depth=1 https://github.com/MobSF/Mobile-Security-Framework-MobSF /opt/mobsf || true; \
  rm -rf /opt/mobsf/.git || true

# ---- Python tools into the existing venv (more) + NetExec in dedicated venv ----
RUN set -eux; \
  apt-get update; \
  # need a compiler to build arc4 (pulled via aardwolf) + python headers
  apt-get install -y --no-install-recommends python3-dev build-essential; \
  # ensure builds find a GCC named exactly as some packages expect
  command -v x86_64-linux-gnu-gcc >/dev/null 2>&1 || ln -s /usr/bin/gcc /usr/bin/x86_64-linux-gnu-gcc; \
  \
  /opt/ghost-venv/bin/pip install --no-cache-dir \
    pypykatz \
    arjun commix \
    volatility3 \
    objection frida-tools \
  ; \
  \
  python3 -m venv /opt/nxc-venv; \
  /opt/nxc-venv/bin/pip install --upgrade pip; \
  # ensure builds use gcc (avoids looking for non-existent triplet compilers)
  CC=gcc CXX=g++ /opt/nxc-venv/bin/pip install --no-cache-dir \
    'git+https://github.com/Pennyw0rth/NetExec'; \
  \
  # clean up build deps to keep image slim
  apt-get purge -y --auto-remove python3-dev build-essential; \
  rm -rf /var/lib/apt/lists/*; \
  \
  # expose extra venv CLIs via wrappers
  for n in pypykatz arjun commix volatility3 objection frida-ps; do \
    printf '%s\n' '#!/usr/bin/env bash' "exec /opt/ghost-venv/bin/${n} \"\$@\"" > "/usr/local/bin/${n}"; \
    chmod +x "/usr/local/bin/${n}"; \
  done; \
  printf '%s\n' '#!/usr/bin/env bash' 'exec /opt/nxc-venv/bin/nxc "$@"' > /usr/local/bin/nxc; \
  chmod +x /usr/local/bin/nxc; \
  printf '%s\n' '#!/usr/bin/env bash' 'exec /opt/nxc-venv/bin/crackmapexec "$@"' > /usr/local/bin/crackmapexec; \
  chmod +x /usr/local/bin/crackmapexec; \
  # volatility3 may ship as vol.py – provide a stable name too
  if [ -x /opt/ghost-venv/bin/vol.py ] && [ ! -e /usr/local/bin/volatility3 ]; then \
    printf '%s\n' '#!/usr/bin/env bash' 'exec /opt/ghost-venv/bin/vol.py "$@"' > /usr/local/bin/volatility3; \
    chmod +x /usr/local/bin/volatility3; \
  fi

# ---- Evil-WinRM + WPScan (Ruby gems) ----
RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends ruby-full build-essential libcurl4; \
  gem install --no-document evil-winrm; \
  gem install --no-document wpscan; \
  printf '#!/usr/bin/env bash\nset -euo pipefail\nexec wpscan "$@"\n' >/usr/local/bin/wp; \
  chmod +x /usr/local/bin/wp; \
  rm -rf /var/lib/apt/lists/*

# ---- Go tools ----
RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends golang-go libpcap0.8-dev pkg-config; \
  export GOBIN=/usr/local/bin GOPATH=/root/go GOTOOLCHAIN=auto; \
  go install github.com/ffuf/ffuf/v2@latest; \
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
  go install github.com/jaeles-project/jaeles@latest; \
  go install github.com/arminc/clair-scanner@latest || true; \
  go install github.com/quay/clair/v4/cmd/clairctl@latest || true; \
  go install github.com/owasp-amass/amass/v4/...@latest; \
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest; \
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; \
  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest; \
  go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest; \
  go install github.com/projectdiscovery/katana/cmd/katana@latest; \
  go install github.com/tomnomnom/waybackurls@latest; \
  go install github.com/tomnomnom/anew@latest; \
  go install github.com/tomnomnom/unfurl@latest; \
  go install github.com/sa7mon/s3scanner@latest; \
  go install github.com/ropnop/kerbrute@latest; \
  go install github.com/zricethezav/gitleaks/v8@latest; \
  go install github.com/trufflesecurity/trufflehog/v3@latest || true; \
  apt-get purge -y --auto-remove golang-go; \
  rm -rf /var/lib/apt/lists/* /root/go /home/*/go || true

# ---- Trivy ----
RUN set -eux; \
  curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ---- AWS CLI v2 (official installer) ----
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" ;; \
    arm64) url="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" ;; \
    *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
  esac; \
  curl -fsSL -o /tmp/awscliv2.zip "$url"; \
  unzip -q /tmp/awscliv2.zip -d /tmp; \
  /tmp/aws/install -i /usr/local/aws-cli -b /usr/local/bin; \
  rm -rf /tmp/aws /tmp/awscliv2.zip

# ---- Impacket module-style wrappers (robust; no .py path issues) ----
RUN set -eux; \
  for n in psexec secretsdump wmiexec ntlmrelayx atexec ticketer GetUserSPNs GetNPUsers addcomputer smbserver; do \
    printf '#!/usr/bin/env bash\nexec python3 -m impacket.examples.%s "$@"\n' "$n" > "/usr/local/bin/${n}"; \
    chmod +x "/usr/local/bin/${n}"; \
    ln -sf "/usr/local/bin/${n}" "/usr/local/bin/${n}.py"; \
  done

# ---- linPEAS ----
RUN set -eux; \
  mkdir -p /opt/peass; \
  curl -fsSL -o /opt/peass/linpeas.sh https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh; \
  chmod +x /opt/peass/linpeas.sh; \
  ln -sf /opt/peass/linpeas.sh /usr/local/bin/linpeas.sh

# normalize ownership back to ghost for cloned dirs & venv
RUN set -eux; \
  chown -R ghost:ghost /opt/ghost-venv /opt/enum4linux /opt/joomscan /opt/jadx /opt/PowerSploit /opt/empire /opt/cloudmapper /opt/mobsf /opt/peass || true

# back to the original user
USER ghost
