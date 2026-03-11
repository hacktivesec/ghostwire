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

# Variant scripts set GW_NAME, GW_COLOR, GW_LABEL before sourcing this
GW_NAME=${GW_NAME:-ghostwire}
GW_COLOR=${GW_COLOR:-"1;37m"}
GW_LABEL=${GHOST_LABEL:-${GW_LABEL:-tools}}
PS1="\[\e[90m\][\A]\[\e[0m\] \[\e[${GW_COLOR}\]${GW_NAME}\[\e[0m\]\[\e[90m\]@\[\e[0m\]\[\e[90m\]${GW_LABEL}\[\e[0m\] \[\e[90m\](\w)\[\e[0m\]\n${GS}\[\e[90m\]>\[\e[0m\] "

if [ -n "${SOCKS5_HOST:-}" ]; then echo "[px] SOCKS5 target: ${SOCKS5_HOST}:${SOCKS5_PORT:-1080}"; fi
