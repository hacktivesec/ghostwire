GW_NAME=ghostwire-web GW_COLOR="1;33m" GW_LABEL=web
. /etc/profile.d/ghostwire-base.sh 2>/dev/null || true
echo "[web] Recon: httpx, gospider, waybackurls, dnsx, katana"
echo "[web] Fuzzing: ffuf, gobuster, wfuzz, arjun"
echo "[web] Vuln: nuclei, sqlmap, xsstrike, commix, nikto, testssl"
