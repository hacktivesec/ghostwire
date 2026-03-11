[ -n "$BASH_VERSION" ] || return 0
case $- in *i*) : ;; *) return 0 ;; esac

export SECLISTS=/opt/seclists
export ARTIFACTS=/shared
alias ll='ls -alF --color=auto'
alias bat='bat --paging=never'
alias fd='fdfind'
alias ad-quick='gw-ad-quick'
alias cloud-audit='gw-cloud-audit'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignorespace:erasedups
GHOST_LABEL=${GHOST_LABEL:-ad-tools}

ghost_prompt(){
  local r=$?
  if [ $r -eq 0 ]; then GS="\[\e[1;32m\]✔"; else GS="\[\e[1;31m\]✘"; fi
  export GS
}
PROMPT_COMMAND=ghost_prompt
PS1="\[\e[90m\][\A]\[\e[0m\] \[\e[1;34m\]ghostwire-ad\[\e[0m\]\[\e[90m\]@\[\e[0m\]\[\e[90m\]${GHOST_LABEL}\[\e[0m\] \[\e[90m\](\w)\[\e[0m\]\n${GS}\[\e[90m\]>\[\e[0m\] "
if [ -n "${SOCKS5_HOST:-}" ]; then echo "[px] SOCKS5 target: ${SOCKS5_HOST}:${SOCKS5_PORT:-1080}"; fi
echo "[gw] AD tools: nxc, bloodhound-python, kerbrute, certipy, coercer, responder, mitm6"
echo "[gw] Cloud: scoutsuite, pacu, aws, az, gcloud"
