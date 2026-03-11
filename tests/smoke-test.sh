#!/usr/bin/env bash
# smoke-test.sh — verify tools are present per image variant
set -euo pipefail

VARIANT="${1:-total}"
PASS=0; FAIL=0

check() {
  if command -v "$1" >/dev/null 2>&1; then
    printf "  ✔ %s\n" "$1"
    ((PASS++))
  else
    printf "  ✘ %s\n" "$1"
    ((FAIL++))
  fi
}

echo "[smoke] testing variant: $VARIANT"
echo ""

# ---- common (every image should have these) ----
echo "--- common ---"
for c in bash curl wget git python3 tini; do check "$c"; done

case "$VARIANT" in
  web)
    echo "--- web ---"
    for c in ffuf nuclei gobuster nikto sqlmap whatweb wafw00f httpx dnsx \
             waybackurls arjun commix xsstrike testssl; do
      check "$c"
    done
    ;;
  net)
    echo "--- network ---"
    for c in nmap masscan tcpdump tshark chisel dnsx httpx hydra \
             socat openssl ike-scan; do
      check "$c"
    done
    ;;
  wifi)
    echo "--- wifi ---"
    for c in aircrack-ng airodump-ng reaver tshark tcpdump \
             hcxdumptool hcxpcapngtool iw; do
      check "$c"
    done
    ;;
  mobile)
    echo "--- mobile ---"
    for c in adb jadx apktool radare2 frida-ps objection ipatool \
             idevice_id mobsfscan; do
      check "$c"
    done
    ;;
  ad)
    echo "--- ad ---"
    for c in nxc bloodhound-python kerbrute certipy psexec secretsdump \
             wmiexec ntlmrelayx smbclient ldapsearch hashcat john hydra \
             aws az gcloud scoutsuite enum4linux-ng; do
      check "$c"
    done
    ;;
  total)
    echo "--- core ---"
    for c in nmap masscan gobuster nikto sqlmap whatweb wafw00f hashcat \
             john hydra ffuf nuclei httpx dnsx subfinder katana amass \
             waybackurls anew unfurl gitleaks kerbrute s3scanner \
             nxc bloodhound-python smbmap evil-winrm wpscan \
             psexec secretsdump wmiexec ntlmrelayx \
             pypykatz arjun commix objection frida-ps \
             trivy aws jadx apktool aircrack-ng reaver \
             steghide exiftool binwalk foremost bulk_extractor \
             secretfinder linpeas.sh enum4linux joomscan sslyze; do
      check "$c"
    done
    ;;
  *)
    echo "unknown variant: $VARIANT" >&2
    echo "usage: smoke-test.sh [web|net|wifi|mobile|ad|total]" >&2
    exit 2
    ;;
esac

echo ""
echo "[smoke] $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
