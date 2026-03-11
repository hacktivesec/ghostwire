# ghostwire – Dependencies

All images use `ubuntu:24.04` as base.

---

## Web (`Dockerfile.web`)

APT: `gobuster`, `nikto`, `whatweb`, `wafw00f`, `wfuzz`, `nmap`, `dnsutils`, `netcat-openbsd`, `proxychains4`

Python venv (`/opt/ghost-venv`): `sqlmap`, `wafw00f`, `arjun`, `commix`

Cloned: `XSStrike`, `testssl.sh`

Go: `ffuf`, `nuclei`, `httpx`, `dnsx`, `katana`, `waybackurls`, `gf`, `unfurl`, `qsreplace`, `jaeles`, `gospider`

---

## Network (`Dockerfile.net`)

APT: `nmap`, `masscan`, `dnsutils`, `tcpdump`, `tshark`, `socat`, `traceroute`, `openssl`, `openvpn`, `wireguard-tools`, `sshuttle`, `hydra`, `ike-scan`, `onesixtyone`, `snmp`

Python venv: `scapy`, `impacket`, `requests`, `PySocks`

Go: `chisel`, `dnsx`, `httpx`

---

## Active Directory & Cloud (`Dockerfile.ad`)

APT: `nmap`, `masscan`, `hashcat` (CPU/POCL), `john`, `hydra`, `samba-common-bin`, `krb5-user`, `ldap-utils`, `smbclient`

Python venv (`/opt/ghost-venv`): `httpx[socks]`, `ldapdomaindump`, `bloodhound`, `smbmap`, `impacket`, `certipy-ad`, `pypykatz`, `boto3`, `azure-mgmt-*`, `scoutsuite`

Python venv (`/opt/nxc-venv`): `NetExec`

Go: `kerbrute`

Cloned: `SecLists`, `enum4linux-ng`, `Responder`, `Pacu`, `Coercer`

Cloud CLIs: `aws` (v2), `az` (Microsoft repo), `gcloud` (Google SDK)

Compiled: `bulk_extractor` (multi-stage build)

Impacket wrappers: `psexec`, `secretsdump`, `wmiexec`, `ntlmrelayx`, `atexec`, `ticketer`, `GetUserSPNs`, `GetNPUsers`, `addcomputer`, `smbserver`

---

## Mobile (`Dockerfile.mobile`)

APT: `adb`, `aapt`, `apktool`, `radare2`, `libimobiledevice-utils`, `ideviceinstaller`, `usbmuxd`

Python venv: `frida-tools`, `objection`, `androguard`, `apkid`, `mobsfscan`, `pyaxmlparser`

Downloaded: `jadx` v1.5.0, `ipatool` v2.2.0 (built from source)

---

## Wireless (`Dockerfile.wifi`)

APT: `aircrack-ng`, `reaver`, `pixiewps`, `hcxdumptool`, `hcxtools`, `tcpdump`, `tshark`, `iw`, `wireless-tools`, `rfkill`, `wpasupplicant`

---

## Shared (all images)

APT: `ca-certificates`, `curl`, `wget`, `git`, `python3`, `python3-pip`, `python3-venv`, `sudo`, `nano`, `less`, `procps`, `tini`, `ripgrep`, `fd-find`, `fzf`, `bat`, `tree`, `rsync`, `proxychains4`, `openssh-client`

Scripts: `px`, `pxcurl`, `pxwget`, `savehere`, `out`, `session-log`, `gw-versions`, `update-seclists`, `smoke-test`

Wordlists: SecLists at `/opt/seclists` (`$SECLISTS`)
