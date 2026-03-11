[ -n "$BASH_VERSION" ] || return 0
export ARTIFACTS=/shared
alias ll='ls -alF --color=auto'
alias bat='bat --paging=never'
alias fd='fdfind'
alias mobile-apk='gw-mobile-apk'
alias mobile-ios='gw-mobile-ios'
alias mobile-frida='gw-mobile-frida'
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignorespace:erasedups
GHOST_LABEL=${GHOST_LABEL:-mobile}
ghost_prompt(){ local r=$?; if [ $r -eq 0 ]; then GS="\[\e[1;32m\]✔"; else GS="\[\e[1;31m\]✘"; fi; export GS; }
PROMPT_COMMAND=ghost_prompt
PS1="\[\e[90m\][\A]\[\e[0m\] \[\e[1;35m\]ghostwire-mobile\[\e[0m\]\[\e[90m\]@\[\e[0m\]\[\e[90m\]${GHOST_LABEL}\[\e[0m\] \[\e[90m\](\w)\[\e[0m\]\n${GS}\[\e[90m\]>\[\e[0m\] "
echo "[mobile] Android: jadx, apkid, objection, adb, aapt, androguard"
echo "[mobile] iOS: idevice, radare2, objection, frida, ipatool"
