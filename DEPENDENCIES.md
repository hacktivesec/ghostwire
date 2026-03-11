# ghostwire – Dependencies

This file summarizes the main dependencies across all ghostwire images.

---

## System packages (APT)

Base image: `ubuntu:24.04`

Core system & tooling:

* `ca-certificates`, `tzdata`, `curl`, `wget`, `git`, `jq`, `sudo`
* `nano`, `less`, `bash-completion`
* `python3`, `python3-pip`, `python3-venv`
* `ripgrep`, `fd-find`, `fzf`, `whois`, `tree`, `rsync`, `bat`
* `proxychains4`, `openssh-client`
* `unzip`, `zip`, `procps`, `tini`, `tar`

Web:

* `gobuster`, `nikto`, `sqlmap`, `whatweb`, `wafw00f`, `wfuzz`

Network / infrastructure:

* `nmap`, `masscan`, `dnsutils`, `iputils-ping`, `traceroute`
* `netcat-openbsd`, `socat`, `tcpdump`, `iproute2`, `openssl`
* `tshark`, `tcpflow`, `ngrep`
* `sshuttle`, `openvpn`, `wireguard-tools`
* `ike-scan`, `onesixtyone`, `snmp`, `patator`

Active Directory / authentication:

* `samba-common-bin`, `krb5-user`, `ldap-utils`, `smbclient`
* `python3-impacket`

Cracking:

* `hashcat`, `ocl-icd-libopencl1`, `pocl-opencl-icd`, `clinfo`
* `john`, `hydra`

Wireless:

* `aircrack-ng`, `reaver`, `pixiewps`
* `hcxdumptool`, `hcxtools`
* `iw`, `wireless-tools`, `rfkill`, `wpasupplicant`

Steganography / forensics:

* `steghide`, `libimage-exiftool-perl`, `binwalk`, `foremost`

Mobile:

* `apktool`, `adb`, `aapt`
* `radare2`
* `ideviceinstaller`, `ifuse`, `libimobiledevice-utils`

---

## Python (main venv `/opt/ghost-venv`)

HTTP / networking:

* `httpx[socks]`, `httpx-ntlm`, `requests`, `requests-ntlm`, `requests-toolbelt`, `PySocks`

AD / network:

* `ldapdomaindump`, `bloodhound`, `smbmap`, `sslyze==6.2.0`
* `impacket`, `certipy-ad`, `pypykatz`, `mitm6`

Cloud:

* `boto3`, `azure-identity`, `azure-mgmt-*`
* `scoutsuite`

Web:

* `arjun`, `commix`

Mobile:

* `frida-tools`, `objection`, `androguard`, `apkid`, `mobsfscan`

Forensics:

* `volatility3`

---

## Python (NetExec venv `/opt/nxc-venv`)

* `NetExec` (from pip or `git+https://github.com/Pennyw0rth/NetExec`)

---

## Ruby (gems)

* `evil-winrm`
* `wpscan` (also exposed via the wrapper command `wp`)

---

## Go tools (installed into `/usr/local/bin`)

* `ffuf`, `nuclei`, `jaeles`, `amass`, `subfinder`
* `httpx`, `dnsx`, `katana`, `waybackurls`, `anew`, `unfurl`
* `s3scanner`, `kerbrute`, `gitleaks`
* `chisel`, `gospider`, `gf`, `qsreplace`
* `ipatool`

---

## External tools cloned / downloaded

* `bulk_extractor` — compiled from source in builder stage
* `enum4linux` / `enum4linux-ng` — cloned
* `joomscan` — cloned (OWASP)
* `SecretFinder` — cloned
* `Responder` — cloned
* `XSStrike` — cloned
* `testssl.sh` — cloned
* `MobSF` — cloned
* `Pacu` — cloned
* `Coercer` — cloned

Optional (via build args):

* `PowerSploit` (`ENABLE_POWERSPLOIT=1`)
* `Empire` (`ENABLE_EMPIRE=1`)
* `CloudMapper` (`ENABLE_CLOUDMAPPER=1`)
* `MobSF` (`ENABLE_MOBSF=1`)

Downloaded binaries:

* `jadx` v1.5.0
* `Trivy` (official install script)
* `AWS CLI v2` (official installer)
* `Azure CLI` (Microsoft repo)
* `GCP CLI` (Google SDK)
* `linPEAS` (latest release)
* `pspy` (latest release)
* `IPATool` v2.2.0 (built from source)

---

## SecLists

* `https://github.com/danielmiessler/SecLists`
* Installed to `/opt/seclists`, exposed as `$SECLISTS`
