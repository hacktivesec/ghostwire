# ghostwire – Dependencies

This file summarizes the main dependencies used in `Dockerfile.total`.

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
* `iw`, `wireless-tools`, `usbutils`, `kmod`

Web:

* `gobuster`
* `nikto`
* `sqlmap`
* `whatweb`
* `wafw00f`

Network / infrastructure:

* `nmap`
* `dnsutils`
* `iputils-ping`
* `traceroute`
* `netcat-openbsd`
* `socat`
* `tcpdump`
* `iproute2`
* `openssl`

Active Directory / authentication:

* `samba-common-bin`
* `krb5-user`
* `ldap-utils`
* `smbclient`
* `python3-impacket`

Cracking:

* `hashcat`
* `ocl-icd-libopencl1`
* `pocl-opencl-icd`
* `clinfo`
* `john`
* `hydra`

Extra network / service tools:

* `snmp`
* `ike-scan`
* `patator`

Wireless:

* `aircrack-ng`
* `reaver`

Steganography / forensics:

* `steghide`
* `libimage-exiftool-perl`
* `binwalk`
* `foremost`

Mobile:

* `apktool`

WPScan dependencies:

* `libcurl4-openssl-dev`
* `libcurl4`

Perl / joomscan:

* `perl`
* `libwww-perl`
* `liblwp-protocol-https-perl`

Java / jadx:

* `default-jre-headless`
* `unzip` (already installed earlier)

Temporary build tools (removed later):

* `python3-dev`
* `build-essential`
* `golang-go`
* `libpcap0.8-dev`
* `pkg-config`
* `ruby-full`

---

## Python (main venv `/opt/ghost-venv`)

HTTP libraries / utilities:

* `httpx[socks]`
* `httpx-ntlm`
* `requests`
* `requests-ntlm`
* `requests-toolbelt`
* `PySocks`

Templating / crypto / parsing:

* `jinja2`
* `markupsafe`
* `cryptography`
* `cffi`
* `pyopenssl`
* `colorama`
* `beautifulsoup4`
* `defusedxml`
* `pyparsing`

Databases:

* `psycopg[binary]`
* `mysql-connector-python`

Active Directory / network tooling:

* `ldapdomaindump`
* `bloodhound`
* `smbmap`
* `sslyze==6.2.0`

Forensics / post-ex / other tools:

* `pypykatz`
* `arjun`
* `commix`
* `volatility3`
* `objection`
* `frida-tools`

SecretFinder:

* repo: `https://github.com/m4ll0k/SecretFinder`
* requirements pulled from the project’s `requirements.txt`

---

## Python (NetExec venv `/opt/nxc-venv`)

* `NetExec` installed from:

  * `git+https://github.com/Pennyw0rth/NetExec`

---

## Ruby (gems)

* `evil-winrm`
* `wpscan` (also exposed via the wrapper command `wp`)

---

## Go tools (installed into `/usr/local/bin`)

Installed using `go install`:

* `github.com/ffuf/ffuf/v2`
* `github.com/projectdiscovery/nuclei/v3/cmd/nuclei`
* `github.com/jaeles-project/jaeles`
* `github.com/owasp-amass/amass/v4/...`
* `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`
* `github.com/projectdiscovery/httpx/cmd/httpx`
* `github.com/projectdiscovery/dnsx/cmd/dnsx`
* `github.com/projectdiscovery/katana/cmd/katana`
* `github.com/tomnomnom/waybackurls`
* `github.com/tomnomnom/anew`
* `github.com/tomnomnom/unfurl`
* `github.com/sa7mon/s3scanner`
* `github.com/ropnop/kerbrute`
* `github.com/zricethezav/gitleaks/v8`

The `golang-go` toolchain is removed after installation.

---

## External tools cloned / downloaded

**bulk_extractor build stage:**

* `bulk_extractor` from
  `https://github.com/simsong/bulk_extractor`
  compiled in the `bulkbuilder` stage and copied into `/usr/local/`.

Cloned into `/opt`:

* `enum4linux` – `https://github.com/portcullislabs/enum4linux`
* `joomscan` – `https://github.com/OWASP/joomscan`
* `SecretFinder` – `https://github.com/m4ll0k/SecretFinder`

Optional (via build args):

* `PowerSploit` – `https://github.com/PowerShellMafia/PowerSploit`
* `Empire` – `https://github.com/BC-SECURITY/Empire`
* `cloudmapper` – `https://github.com/duo-labs/cloudmapper`
* `MobSF` – `https://github.com/MobSF/Mobile-Security-Framework-MobSF`

**Jadx:**

* from release zip:
  `https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip`
* installed to `/opt/jadx`, with wrappers `jadx` and `jadx-gui` in `/usr/local/bin`.

**Trivy:**

* installed via official script:
  `https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh`

**AWS CLI v2:**

* official installer:

  * `https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip` (amd64)
  * `https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip` (arm64)

**linPEAS:**

* `linpeas.sh` from
  `https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh`

**SecLists:**

* `https://github.com/danielmiessler/SecLists`
  checked out into `/opt/seclists`

---

## Optional feature flags

Enable via build args:

* `ENABLE_POWERSPLOIT=1` → clones `PowerSploit` into `/opt/PowerSploit`
* `ENABLE_EMPIRE=1` → clones `Empire` into `/opt/empire`
* `ENABLE_CLOUDMAPPER=1` → clones `cloudmapper` into `/opt/cloudmapper`
* `ENABLE_MOBSF=1` → clones `MobSF` into `/opt/mobsf`

