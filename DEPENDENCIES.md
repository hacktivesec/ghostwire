# ghostwire – Dependencies

All images derive from `ghostwire-base` (Ubuntu 24.04). Every external pin
lives in the relevant Dockerfile via build-args (`*_REF`) so a single grep
shows what's locked: `git grep '_REF=' Dockerfile.*`.

---

## Base (`Dockerfile.base`)

APT: `ca-certificates`, `tzdata`, `locales`, `curl`, `wget`, `git`, `jq`,
`sudo`, `file`, `nano`, `less`, `bash-completion`, `python3`, `python3-pip`,
`python3-venv`, `python3-dev`, `build-essential`, `libffi-dev`, `libssl-dev`,
`pkg-config`, `ripgrep`, `fd-find`, `fzf`, `tree`, `rsync`, `bat`,
`proxychains4`, `openssh-client`, `unzip`, `zip`, `procps`, `tini`, `tar`,
`gnupg`, `lsb-release`, `apt-transport-https`, `netcat-openbsd`, `dnsutils`,
`iputils-ping`, `traceroute`, `iproute2`, `socat`, `openssl`, `whois`.

Python venv (`/opt/ghost-venv`): `requests`, `httpx[socks]`, `PySocks`,
`beautifulsoup4`, `jinja2`, `cryptography`, `pyopenssl`, `colorama`,
`defusedxml`.

Scripts: `px`, `pxcurl`, `pxwget`, `savehere`, `out`, `session-log`,
`update-seclists`, `gw-versions`, `gw`, `gw-engagement`, `gw-ssh-agent-check`,
`smoke-test`.

User: non-root `ghost` (UID/GID 1001).

---

## Web (`Dockerfile.web`)

APT (added on top of base): `default-jre-headless`, `nmap`, `nikto`, `whatweb`,
`wafw00f`, `wfuzz`, `gobuster`.

Python venv: `sqlmap`, `arjun`, `commix`, `wafw00f`.

Pinned clones: `SecLists` (`SECLISTS_REF`), `XSStrike` (`XSSTRIKE_REF`),
`testssl.sh` (`TESTSSL_REF`).

Go (pinned): `ffuf`, `nuclei`, `httpx`, `dnsx`, `subfinder`,
`waybackurls`, `gf` (commit), `unfurl`, `qsreplace`, `anew`, `assetfinder`,
`jaeles` (`v0.17.1`), `gospider`.

---

## Network (`Dockerfile.net`)

APT: `nmap`, `masscan`, `tcpdump`, `tshark`, `tcpflow`, `ngrep`, `hydra`,
`ike-scan`, `onesixtyone`, `snmp`, `sshuttle`, `openvpn`, `wireguard-tools`,
`libplist-utils`.

Python venv: `scapy`, `impacket`.

Go (pinned): `chisel`, `dnsx`, `httpx`, `subfinder`.

---

## Active Directory & Cloud (`Dockerfile.ad`)

APT: `samba-common-bin`, `krb5-user`, `ldap-utils`, `smbclient`, `nmap`,
`tcpdump`, `hashcat`, OpenCL ICDs, `john`, `hydra`.

Python venv: `httpx[socks]`, `httpx-ntlm`, `requests-ntlm`, `requests-toolbelt`,
`ldapdomaindump`, `bloodhound`, `smbmap`, `pypykatz`, `boto3`,
`azure-identity`/`azure-mgmt-*`, `impacket`, `scoutsuite`, `certipy-ad`,
`mitm6`.

Pinned clones: `SecLists`, `NetExec` (`NETEXEC_REF`),
`enum4linux-ng` (`ENUM4LINUX_NG_REF`), `Responder` (`RESPONDER_REF`),
`coercer` (`COERCER_REF`).

PyPI (pinned): `pacu` (`PACU_REF`).

Compiled (pinned): `bulk_extractor` (`BULK_EXTRACTOR_REF`).

Cloud CLIs: `aws` (v2, multi-arch), `az` (Microsoft repo), `gcloud`
(Google SDK, multi-arch).

Go (pinned): `kerbrute v1.0.3`.

Impacket wrappers: `psexec`, `secretsdump`, `wmiexec`, `ntlmrelayx`,
`atexec`, `ticketer`, `GetUserSPNs`, `GetNPUsers`, `addcomputer`,
`smbserver`.

---

## Mobile (`Dockerfile.mobile`)

APT: `default-jre-headless`, `adb`, `aapt`, `apktool`, `libusb-1.0-0`,
`libimobiledevice6`, `libzip4`, `ideviceinstaller`, `ifuse`,
`libimobiledevice-utils`, `usbmuxd`, `libplist-utils`, `yara`, `nmap`,
`radare2`.

Python venv: `frida-tools`, `objection`, `androguard`, `apkid`, `mobsfscan`,
`pyaxmlparser`, `quark-engine`.

Pinned clones: `MobSF` (`MOBSF_REF`).

Pinned downloads: `jadx` (`JADX_VERSION`), `ipatool` `v2.2.0` (built from src).

---

## Wireless (`Dockerfile.wifi`)

APT: `aircrack-ng`, `reaver`, `pixiewps`, `hcxdumptool`, `hcxtools`,
`tshark`, `tcpdump`, `iw`, `wireless-tools`, `rfkill`, `wpasupplicant`,
`usbutils`, `kmod`.

---

## Pivot (`Dockerfile.pivot`)

APT: `microsocks`, `sshuttle`, `openvpn`, `wireguard-tools`, `openssh-server`,
`iptables`, `nftables`, `iputils-ping`.

Go (pinned): `chisel v1.11.5`.

---

## Reproducibility

Every pinned reference is exposed as a Dockerfile build-arg. Override at
build time:

```bash
docker build -f Dockerfile.web \
  --build-arg SECLISTS_REF=2025.3 \
  --build-arg TESTSSL_REF=v3.2.2 \
  -t ghostwire-web:custom .
```

Dependabot opens weekly PRs for `docker` and `github-actions` ecosystems.
