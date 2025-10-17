# syntax=docker/dockerfile:1

ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE} AS base

LABEL org.opencontainers.image.title="ghostwire" \
      org.opencontainers.image.description="Ultra-lean web/network/AD toolkit + hashcat. SOCKS-ready. SecLists baked. dirsearch via venv. Minimal bloat." \
      org.opencontainers.image.vendor="ghostwire" \
      org.opencontainers.image.version="dev" \
      org.opencontainers.image.licenses="CC0-1.0"

ARG SECLISTS_SHA=HEAD
ARG DIRSEARCH_SHA=HEAD

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LC_ALL=C.UTF-8 LANG=C.UTF-8 \
    PIP_NO_CACHE_DIR=1 \
    TERM=xterm-256color \
    SECLISTS=/opt/seclists \
    DIRSEARCH_DIR=/opt/dirsearch \
    ARTIFACTS=/shared \
    GHOST_LABEL=security \
    SOCKS5_HOST=127.0.0.1 \
    SOCKS5_PORT=1080

# ---- Core packages (no recommends) ----
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates tzdata curl wget git jq sudo \
      nano less vim-tiny bash-completion \
      python3 python3-pip python3-venv \
      # web
      gobuster nikto sqlmap wfuzz whatweb wafw00f testssl.sh \
      # network
      nmap masscan dnsutils iputils-ping traceroute netcat-openbsd socat tcpdump iproute2 openssl \
      # AD/auth
      samba-common-bin krb5-user ldap-utils smbclient python3-impacket \
      # cracking
      hashcat ocl-icd-libopencl1 pocl-opencl-icd clinfo john hydra \
      # QoL/cli
      ripgrep fd-find fzf whois tree rsync bat proxychains4 openssh-client unzip zip procps tini \
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

# ---- dirsearch source ----
RUN set -eux; \
    git clone https://github.com/maurosoria/dirsearch "${DIRSEARCH_DIR}"; \
    if [ "${DIRSEARCH_SHA}" != "HEAD" ]; then cd "${DIRSEARCH_DIR}" && git fetch --depth=1 origin "${DIRSEARCH_SHA}" && git checkout "${DIRSEARCH_SHA}"; fi; \
    rm -rf "${DIRSEARCH_DIR}/.git" || true

# ---- Python venv + tools ----
RUN python3 -m venv /opt/ghost-venv && \
    /opt/ghost-venv/bin/python -m pip install --upgrade pip setuptools wheel && \
    /opt/ghost-venv/bin/pip install --no-cache-dir "setuptools<81" && \
    /opt/ghost-venv/bin/pip install --no-cache-dir \
      "httpx[socks]" httpx-ntlm requests requests-ntlm requests-toolbelt PySocks \
      jinja2 markupsafe certifi urllib3 cryptography cffi pyopenssl idna chardet charset-normalizer \
      colorama beautifulsoup4 defusedxml pyparsing \
      "psycopg[binary]" mysql-connector-python \
      ldapdomaindump bloodhound smbmap && \
    /opt/ghost-venv/bin/pip install --no-cache-dir -r "${DIRSEARCH_DIR}/requirements.txt" && \
    ln -s /opt/ghost-venv/bin/ldapdomaindump /usr/local/bin/ldapdomaindump || true && \
    ln -s /opt/ghost-venv/bin/bloodhound   /usr/local/bin/bloodhound-python || true && \
    ln -s /opt/ghost-venv/bin/smbmap       /usr/local/bin/smbmap || true

# ---- Wrappers + helpers ----
# dirsearch wrapper (use venv python)
RUN printf '#!/usr/bin/env bash\nexec /opt/ghost-venv/bin/python3 %s/dirsearch.py "$@"\n' "${DIRSEARCH_DIR}" > /usr/local/bin/dirsearch && \
    chmod +x /usr/local/bin/dirsearch

# savehere: copy artifacts out
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

# update-seclists: shallow re-clone (works without .git)
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

# QoL wrappers + session logging
RUN printf '#!/usr/bin/env bash\nexec px curl "$@"\n' > /usr/local/bin/pxcurl && chmod +x /usr/local/bin/pxcurl && \
    printf '#!/usr/bin/env bash\nexec px wget "$@"\n' > /usr/local/bin/pxwget && chmod +x /usr/local/bin/pxwget

# out: run a command and tee to /shared/<cmd>_<ts>.log (with usage + correct exit)
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

# session-log: start bash with persistent history in /shared/history
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
echo "[gw] No SSH agent. Run with: -e SSH_AUTH_SOCK=/ssh-agent -v \"$SSH_AUTH_SOCK:/ssh-agent\"" >&2
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
  /usr/local/bin/dirsearch \
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
  /etc/profile.d/ghostwire.sh || true

# ---- Non-root + sudo (NOPASSWD:ALL) ----
RUN groupadd -r ghost && useradd -m -g ghost -s /bin/bash ghost && \
    mkdir -p /work "${ARTIFACTS}" /opt/tools && \
    chown -R ghost:ghost /work "${ARTIFACTS}" /opt/tools /opt/ghost-venv "${SECLISTS}" "${DIRSEARCH_DIR}" && \
    printf 'ghost ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/ghost && \
    chmod 0440 /etc/sudoers.d/ghost

USER ghost
WORKDIR /work

VOLUME ["/shared", "/work"]

# ---- Healthcheck ----
HEALTHCHECK --interval=1h --timeout=10s --start-period=20s --retries=3 \
  CMD sh -c 'command -v nmap >/dev/null 2>&1 && command -v hashcat >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && [ -x /usr/local/bin/dirsearch ] || exit 1'

STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/bin/bash"]


