[ -n "$BASH_VERSION" ] || return 0
export ARTIFACTS=${ARTIFACTS:-/shared}
export SECLISTS=${SECLISTS:-/opt/seclists}
alias ll='ls -alF --color=auto'
alias bat='bat --paging=never'
alias fd='fdfind'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignorespace:erasedups
ghost_prompt(){ local r=$?; if [ $r -eq 0 ]; then GS="\[\e[1;32m\]✔"; else GS="\[\e[1;31m\]✘"; fi; export GS; }
PROMPT_COMMAND=ghost_prompt
PS1="\[\e[90m\][\A]\[\e[0m\] \[\e[1;33m\]ghostwire-web\[\e[0m\]\[\e[90m\]@\[\e[0m\]\[\e[90m\]web\[\e[0m\] \[\e[90m\](\w)\[\e[0m\]\n${GS}\[\e[90m\]>\[\e[0m\] "
if [ -n "${SOCKS5_HOST:-}" ]; then echo "[px] SOCKS5 target: ${SOCKS5_HOST}:${SOCKS5_PORT:-1080}"; fi
echo "[web] Recon: httpx, gospider, waybackurls, dnsx, katana"
echo "[web] Fuzzing: ffuf, gobuster, wfuzz, arjun"
echo "[web] Vuln: nuclei, sqlmap, xsstrike, commix, nikto, testssl"
