#!/usr/bin/env bash
# smoke-test.sh — runtime sanity check per variant.
# Verifies tool presence, runs version/dry-run probes, optional SOCKS reachability,
# and SecLists integrity where applicable. Exit code = number of failures.
set -uo pipefail

VARIANT="${1:-${GHOST_LABEL:-base}}"
PASS=0; FAIL=0; SKIP=0

c_red()   { printf '\033[1;31m%s\033[0m' "$*"; }
c_grn()   { printf '\033[1;32m%s\033[0m' "$*"; }
c_dim()   { printf '\033[90m%s\033[0m' "$*"; }

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  %s %s\n' "$(c_grn '✔')" "$name"
    PASS=$((PASS+1))
  else
    printf '  %s %s\n' "$(c_red '✘')" "$name"
    FAIL=$((FAIL+1))
  fi
}

skip() {
  printf '  %s %s\n' "$(c_dim '○')" "$1"
  SKIP=$((SKIP+1))
}

cmd() { check "$1" command -v "$1"; }

# ---- common (every image) ----
echo "[smoke] variant: ${VARIANT}"
echo
echo "--- common ---"
for c in bash curl wget git python3 tini jq tar unzip proxychains4; do cmd "$c"; done
check "ghost-venv" test -x /opt/ghost-venv/bin/python
check "ghost-user" sh -c 'id ghost | grep -q "uid=1001"'
check "/work writable" test -w /work
check "/shared writable" test -w /shared

if [ -d /opt/seclists ]; then
  check "seclists has top1k subdomains" test -s /opt/seclists/Discovery/DNS/subdomains-top1million-20000.txt
  check "seclists has common.txt" test -s /opt/seclists/Discovery/Web-Content/common.txt
fi

if [ -n "${SOCKS5_HOST:-}" ] && [ "${SOCKS5_HOST}" != "127.0.0.1" ] && [ "${GW_SMOKE_TEST_SOCKS:-0}" = "1" ]; then
  check "socks reachable ${SOCKS5_HOST}:${SOCKS5_PORT:-1080}" \
    bash -c "exec 3<>/dev/tcp/${SOCKS5_HOST}/${SOCKS5_PORT:-1080}"
else
  skip "socks reachability (set GW_SMOKE_TEST_SOCKS=1 to enable)"
fi

case "$VARIANT" in
  base)
    : # base only needs the common checks
    ;;
  web)
    echo
    echo "--- web ---"
    for c in nmap gobuster nikto whatweb wafw00f wfuzz arjun commix xsstrike testssl \
             ffuf nuclei httpx dnsx subfinder waybackurls anew gf; do cmd "$c"; done
    check "ffuf -V"      ffuf -V
    check "nuclei -version" nuclei -version
    check "sqlmap --version" sqlmap --version
    ;;
  net)
    echo
    echo "--- net ---"
    for c in nmap masscan tcpdump tshark hydra socat openssl ike-scan onesixtyone \
             snmpwalk sshuttle openvpn wg chisel dnsx httpx subfinder; do cmd "$c"; done
    check "nmap -V"     nmap -V
    check "chisel -v"   chisel --version
    ;;
  wifi)
    echo
    echo "--- wifi ---"
    for c in aircrack-ng airodump-ng aireplay-ng reaver pixiewps \
             hcxdumptool hcxpcapngtool tshark tcpdump iw; do cmd "$c"; done
    check "aircrack-ng version" aircrack-ng --help
    ;;
  mobile)
    echo
    echo "--- mobile ---"
    for c in adb aapt apktool jadx radare2 frida-ps objection ipatool \
             idevice_id mobsfscan apkid androguard yara; do cmd "$c"; done
    check "jadx --help"    jadx --help
    check "frida-ps --version"    frida-ps --version
    ;;
  ad)
    echo
    echo "--- ad ---"
    for c in nxc bloodhound-python kerbrute certipy psexec secretsdump \
             wmiexec ntlmrelayx smbclient ldapsearch hashcat john hydra \
             aws az gcloud scoutsuite enum4linux-ng coercer responder mitm6 \
             bulk_extractor; do cmd "$c"; done
    check "aws --version"  aws --version
    check "az version"     az version
    ;;
  pivot)
    echo
    echo "--- pivot ---"
    for c in microsocks chisel sshuttle openvpn wg wg-quick \
             ssh sshd iptables nft; do cmd "$c"; done
    check "chisel --version" chisel --version
    ;;
  *)
    echo "unknown variant: $VARIANT" >&2
    echo "usage: smoke-test [base|web|net|wifi|mobile|ad|pivot]" >&2
    exit 2
    ;;
esac

echo
echo "[smoke] ${PASS} passed · ${FAIL} failed · ${SKIP} skipped"
[ "$FAIL" -eq 0 ]
