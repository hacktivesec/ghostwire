GW_NAME=ghostwire-ad GW_COLOR="1;34m" GW_LABEL=ad-tools
. /etc/profile.d/ghostwire-base.sh 2>/dev/null || true
alias ad-quick='gw-ad-quick'
alias cloud-audit='gw-cloud-audit'
echo "[gw] AD tools: nxc, bloodhound-python, kerbrute, certipy, coercer, responder, mitm6"
echo "[gw] Cloud: scoutsuite, pacu, aws, az, gcloud"
