[ -n "$BASH_VERSION" ] || return 0
export ARTIFACTS=/shared
alias ll='ls -alF --color=auto'
alias bat='bat --paging=never'
alias fd='fdfind'
alias net-scan='gw-net-scan'
alias net-tunnel='gw-net-tunnel'
alias net-traffic='gw-net-traffic'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignorespace:erasedups
GHOST_LABEL=${GHOST_LABEL:-network}
ghost_prompt(){ local r=$?; if [ $r -eq 0 ]; then GS="\[\e[1;32m\]✔"; else GS="\[\e[1;31m\]✘"; fi; export GS; }
PROMPT_COMMAND=ghost_prompt
PS1="\[\e[90m\][\A]\[\e[0m\] \[\e[1;34m\]ghostwire-net\[\e[0m\]\[\e[90m\]@\[\e[0m\]\[\e[90m\]${GHOST_LABEL}\[\e[0m\] \[\e[90m\](\w)\[\e[0m\]\n${GS}\[\e[90m\]>\[\e[0m\] "
if [ -n "${SOCKS5_HOST:-}" ]; then echo "[px] SOCKS5 target: ${SOCKS5_HOST}:${SOCKS5_PORT:-1080}"; fi
echo "[net] Tools: nmap, masscan, tshark, chisel, openvpn, wireguard, dnsx, httpx"
