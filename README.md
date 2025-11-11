
<p align="center">
  <img src="https://github.com/hacktivesec/ghostwire/blob/main/Ghostwire.png" alt="Ghostwire" width="50%">
</p>

<h1 align="center">ghostwire</h1>

<p align="center">
  A lean, no-nonsense <b>web / network / AD</b> toolkit that runs anywhere Docker runs.<br>
  Bring your targets, scope, and a SOCKS pivot — ghostwire handles the rest.
</p>

<p align="center">
  <a href="#"><img alt="Ubuntu 24.04" src="https://img.shields.io/badge/base-Ubuntu%2024.04-EB5E28?logo=ubuntu&logoColor=white"></a>
  <a href="#"><img alt="Docker + Compose" src="https://img.shields.io/badge/packaging-Docker%20%2B%20Compose-2496ED?logo=docker&logoColor=white"></a>
  <a href="#"><img alt="Non-root default" src="https://img.shields.io/badge/user-ghost%20(non--root)-6C757D"></a>
  <a href="#"><img alt="SecLists" src="https://img.shields.io/badge/wordlists-SecLists-0E7C86"></a>
</p>

---

## Table of contents
- [What’s inside](#whats-inside)
- [Requirements](#requirements)
- [Repo layout](#repo-layout)
- [Docker Compose (recommended)](#docker-compose-recommended)
- [Merged Compose quickstart (PowerShell)](#merged-compose-quickstart-powershell)
- [Docker CLI alternative](#docker-cli-alternative)
- [Quickstarts](#quickstarts)
- [Using the SOCKS pivot](#using-the-socks-pivot)
- [Common flows (consent / lab)](#common-flows-consent--lab)
- [Files in/out](#files-inout)
- [Self-test](#quick-self-test)
- [Updating](#updating)
- [Troubleshooting](#troubleshooting)
- [Intended use](#intended-use)
- [Credits](#credits)
- [Changelog (high-level)](#changelog-high-level)

---

## 🔎 What’s inside

### Core CLI
- **Web:** `gobuster`, `nikto`, `sqlmap`, `wfuzz`, `whatweb`, `wafw00f`, `joomscan`, `wpscan` (`wp` wrapper)
- **Network:** `nmap`, `masscan`, `dnsutils`, `iputils-ping`, `traceroute`, `netcat-openbsd`, `socat`, `tcpdump`, `iproute2`, `openssl`, classic **enum4linux**
- **AD / Auth:** `python3-impacket` *(module entrypoints exposed as CLIs)*, `krb5-user`, `ldap-utils`, `smbclient`, `ldapdomaindump`, `bloodhound` *(venv; `bloodhound-python` alias)*, `smbmap`
- **Cracking:** `hashcat` *(CPU OpenCL via POCL)*, `john`, `hydra`
- **Wordlists:** **SecLists** at `/opt/seclists` → `$SECLISTS`

### Extras
- **Network & service:** `snmp`, `ike-scan`, `patator`
- **Wireless** *(needs `NET_RAW`/`NET_ADMIN` caps)*: `aircrack-ng`, `reaver`
- **Stego & forensics:** `steghide`, `exiftool`, `binwalk`, `foremost`, **bulk_extractor** *(built from source)*
- **Mobile / reverse:** `apktool`, **jadx** (CLI + GUI), **MobSF** *(cloned only)*
- **Cloud & containers:** **Trivy**, **AWS CLI v2**
- **AD/Windows post-ex** *(cloned only):* **PowerSploit**, **Empire**
- **Python (venv):** `pypykatz`, `arjun`, `commix`, `volatility3`, `objection`, `frida-tools`, **NetExec** (`nxc`, plus `crackmapexec` shim)
- **Go recon stack** *(installed, then Go removed):* `ffuf`, `nuclei`, `jaeles`, `amass`, `subfinder`, `httpx`, `dnsx`, `katana`, `waybackurls`, `anew`, `unfurl`, `s3scanner`, `kerbrute`, `gitleaks`

### Helpers
`px` (SOCKS5 wrapper), `pxcurl`, `pxwget` · `savehere` · `out` · `update-seclists` · `session-log`  
`gw-wifi-capture`, `gw-usb-capture`, `gw-ssh-agent-check`, `gw-gpu-check`  
Impacket wrappers: `psexec`, `wmiexec`, `secretsdump`, `ntlmrelayx`, `atexec`, `ticketer`, `GetUserSPNs`, `GetNPUsers`, `addcomputer`, `smbserver`

---

## ⚙️ Requirements
- Docker **and** Docker Compose v2
- For **SOCKS:** reachable SOCKS5 (default `127.0.0.1:1080`)
- For **GPU:** vendor drivers on host + container runtime (`--gpus all` for NVIDIA)

---

## 🧰 Repo layout
- `Dockerfile.total` → single **multi-stage** Dockerfile (stages: `web`, `wifi`, `net`, `mobile`, `ad`, `total`)
- `docker-compose.yml` → recommended way to build/run per stage with `build.target`
- `docker-compose.merged.yml` → convenience to build/run **all** stages/services at once

---

## 🧩 Docker Compose (recommended)

Create **`docker-compose.yml`** at the repo root:

```yaml
version: "3.9"

x-common: &common
  build:
    context: .
    dockerfile: Dockerfile.total
    # Optional feature flags:
    # args:
    #   ENABLE_POWERSPLOIT: "1"
    #   ENABLE_EMPIRE: "1"
    #   ENABLE_CLOUDMAPPER: "1"
    #   ENABLE_MOBSF: "1"
  environment:
    # On Linux use 127.0.0.1; on Docker Desktop use host.docker.internal
    SOCKS5_HOST: ${SOCKS5_HOST:-host.docker.internal}
    SOCKS5_PORT: ${SOCKS5_PORT:-1080}
  volumes:
    - ./:/work
    - ./artifacts:/shared
  # Linux-only, optional:
  # network_mode: "host"
  restart: unless-stopped
  env_file: [.env]

services:
  web:
    <<: *common
    build: { target: web }
    container_name: ghostwire-web

  wifi:
    <<: *common
    build: { target: wifi }
    container_name: ghostwire-wifi
    cap_add: [ "NET_RAW", "NET_ADMIN" ]

  net:
    <<: *common
    build: { target: net }
    container_name: ghostwire-net

  mobile:
    <<: *common
    build: { target: mobile }
    container_name: ghostwire-mobile

  ad:
    <<: *common
    build: { target: ad }
    container_name: ghostwire-ad

  total:
    <<: *common
    build: { target: total }
    container_name: ghostwire
    # GPU (optional)
    # gpus: "all"
````

Optional **`.env`**:

```dotenv
SOCKS5_HOST=host.docker.internal   # Linux: 127.0.0.1
SOCKS5_PORT=1080
```

### Compose commands

```bash
# Build all stages
docker compose build

# Start one
docker compose up -d total    # or web|wifi|net|mobile|ad

# Shell
docker compose exec total bash

# Logs
docker compose logs -f total

# Stop & remove
docker compose down -v
```

> **Linux host networking:** add `network_mode: "host"` to services that need it (Linux only).

---

## 🧩 Merged Compose (PowerShell quickstart)

Using the included **`docker-compose.merged.yml`**:

```powershell
# Build every service
docker compose -f .\docker-compose.merged.yml build

# Start everything
docker compose -f .\docker-compose.merged.yml up -d web wifi net mobile ad total

# Shell (pick one)
docker compose -f .\docker-compose.merged.yml exec ad bash
docker compose -f .\docker-compose.merged.yml exec web bash
docker compose -f .\docker-compose.merged.yml exec wifi bash
docker compose -f .\docker-compose.merged.yml exec net bash
docker compose -f .\docker-compose.merged.yml exec mobile bash
docker compose -f .\docker-compose.merged.yml exec total bash

# Quick presence check (AD)
docker compose -f .\docker-compose.merged.yml run --rm ad bash -lc ^
  "set -e; for c in psexec secretsdump wmiexec ntlmrelayx atexec ticketer GetUserSPNs GetNPUsers addcomputer smbserver ldapdomaindump bloodhound smbmap evil-winrm nxc; do command -v `"$c`" >/dev/null || { echo missing: $c; exit 1; }; done; echo OK:ad"

# Stop & clean
docker compose -f .\docker-compose.merged.yml down -v
```

---

## 📦 Docker CLI (alternative)

```bash
# build a base tag
docker build -t ghostwire:dev -f Dockerfile.total .

# build stages
docker build -t ghostwire:web    -f Dockerfile.total --target web .
docker build -t ghostwire:wifi   -f Dockerfile.total --target wifi .
docker build -t ghostwire:net    -f Dockerfile.total --target net .
docker build -t ghostwire:mobile -f Dockerfile.total --target mobile .
docker build -t ghostwire:ad     -f Dockerfile.total --target ad .
docker build -t ghostwire:total  -f Dockerfile.total --target total .

# run (Linux host with local SOCKS)
mkdir -p artifacts
docker run --rm -it --network host \
  -e SOCKS5_HOST=127.0.0.1 -e SOCKS5_PORT=1080 \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  --name ghostwire \
  ghostwire:dev
```

---

## 🚀 Quickstarts

### A) Compose + local SOCKS (Linux)

```bash
mkdir -p artifacts
# optional (Linux only): add network_mode: "host" under 'total'
docker compose up -d total
docker compose exec total bash
```

### B) Docker Desktop (Mac/Windows)

```bash
mkdir -p artifacts
# .env should set SOCKS5_HOST=host.docker.internal
docker compose up -d total
docker compose exec total bash
```

### C) WiFi capture & USB (Linux)

```bash
docker compose up -d wifi
docker compose exec wifi bash
# inside:
sudo -n tcpdump -D || true
gw-wifi-capture wlan0 /shared/wifi.pcap
gw-usb-capture  usbmon0 /shared/usb.pcap
```

### D) GPU cracking (Linux / WSL2)

```yaml
# add under the 'total' service (Compose):
gpus: "all"
```

```bash
docker compose up -d total
docker compose exec total bash -lc 'gw-gpu-check && hashcat -I'
```

---

## 🧦 Using the SOCKS pivot

**One-off via wrapper**

```bash
px curl -I https://example.com
px gobuster dir -u https://example.com \
  -w "$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt" \
  -x php,js,html -o /shared/gobuster.txt
px sqlmap -u "https://example.com/?id=1" --batch
px nmap -sT -Pn -n example.com
```

**Environment-wide**

```bash
export ALL_PROXY="socks5h://${SOCKS5_HOST}:${SOCKS5_PORT}"
export HTTP_PROXY="$ALL_PROXY" HTTPS_PROXY="$ALL_PROXY" NO_PROXY="127.0.0.1,localhost"
```

> Raw SYN/UDP scans & packet capture do **not** traverse SOCKS.

---

## 🧰 Common flows (consent / lab)

**Subdomains → probe → scan → nuclei**

```bash
subfinder -silent -d example.com | anew /shared/subs.txt
httpx -silent -status-code -title -follow -l /shared/subs.txt -o /shared/httpx.txt
masscan -p1-65535,U:1-65535 --rate 5000 -iL /shared/subs.txt -oL /shared/masscan.txt || true
nuclei -l /shared/httpx.txt -o /shared/nuclei.txt
```

**Fuzz (dirs/params)**

```bash
ffuf -u https://example.com/FUZZ -w "$SECLISTS/Discovery/Web-Content/common.txt" -o /shared/ffuf.json
wfuzz -u https://example.com/page?FUZZ=1 -w "$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt"
arjun -u https://example.com/page -oT /shared/arjun_params.txt
```

**WordPress / CMS**

```bash
wp --url https://example.com --enumerate vp,vt,u
joomscan --url https://example.com
```

**Active Directory (authenticated discovery)**

```bash
nxc smb 10.0.0.0/24 -u user -p '***' --shares
ldapdomaindump ldap://10.0.0.10 -u 'lab.local\user' -p '***' -o /shared/ad
python3 -m impacket.examples.secretsdump lab.local/user:'***'@10.0.0.10 -outputfile /shared/secrets
```

**Windows post-ex (remote shell)**

```bash
evil-winrm -i 10.0.0.5 -u 'user' -p '***'
```

**Binary & mobile**

```bash
binwalk -e firmware.bin -C /shared/fw
apktool d app.apk -o /shared/app
jadx -d /shared/jadx app.apk
```

**Forensics**

```bash
foremost -i disk.img -o /shared/foremost
bulk_extractor -o /shared/be_out disk.img
exiftool sample.jpg
```

**Code & secrets scanning**

```bash
trivy fs --severity MEDIUM,HIGH,CRITICAL .
gitleaks detect -s . -r /shared/gitleaks.json
```

---

## 📁 Files in/out

* Work in **`/work`** (bind-mounted from your current folder)
* Export artifacts to **`/shared`** (bind-mounted e.g. to `./artifacts`)

```bash
savehere report.txt
out /bin/uname -a
```

---

## 🧪 Quick self-test (inside the container)

```bash
whoami && pwd
[ -w /work ] && echo "/work ok" || echo "NO /work"
[ -w /shared ] && echo "/shared ok" || echo "NO /shared"
curl -I https://example.com || true

# presence / versions (selection)
nmap --version
masscan --version
gobuster -h | head -n 2
wfuzz --version
whatweb --version
wafw00f --version
sqlmap --version | head -n 1
hashcat --version
hydra -h | head -n 1
ffuf -V
nuclei -version
nxc --version || true
wp --version || true
pypykatz --version || true
volatility3 --help | head -n 1
```

---

## 🔧 Build args, env & volumes

* **Build args:** `BASE_IMAGE=ubuntu:24.04`, `SECLISTS_SHA=HEAD`, feature flags `ENABLE_POWERSPLOIT`, `ENABLE_EMPIRE`, `ENABLE_CLOUDMAPPER`, `ENABLE_MOBSF`
* **Environment:** `SOCKS5_HOST` (default `127.0.0.1`), `SOCKS5_PORT` (default `1080`), `SECLISTS=/opt/seclists`, `ARTIFACTS=/shared`
* **Volumes:** `VOLUME ["/shared", "/work"]`
* **Healthcheck:** verifies `nmap`, `hashcat`, `python3` reachability

---

## 🔄 Updating

* **SecLists:** `update-seclists`
* **APT tools:**

  ```bash
  sudo apt-get update && sudo apt-get install --only-upgrade \
    gobuster nikto sqlmap wfuzz whatweb wafw00f \
    nmap masscan hashcat john hydra python3-impacket
  ```
* **Python tools:** rebuild the image to keep the venvs consistent.

---

## 🆘 Troubleshooting

* **“container name already in use”** — pick a new name (e.g., `--name ghostwire2`) or remove the old: `docker rm -f ghostwire`
* **Windows path issues** — prefer `--mount` or forward slashes in `-v` paths
* **No GPU devices** — ensure host drivers + `nvidia-container-toolkit` (Linux) or WSL2 GPU support (Windows), then run with `--gpus all`
* **SOCKS not reachable** — on Docker Desktop, use `host.docker.internal` for the host IP

---

## ✅ Intended use

**Red team / pentest / DFIR / training only — on systems you own or have explicit written permission to test.**
You are responsible for complying with laws, contracts, and your Rules of Engagement.

---

## 🙏 Credits

This image repackages superb work from many OSS projects (see individual repos/licenses).
OCI labels are included in the image metadata.

---

## 📝 Changelog (high-level)

* Added: Compose recipe with per-stage services and build targets
* Added: **Merged Compose** quickstart (PowerShell)
* Added: network/service (`snmp`, `ike-scan`, `patator`)
* Added: wireless (`aircrack-ng`, `reaver`)
* Added: stego/forensics (`steghide`, `exiftool`, `binwalk`, `foremost`, `bulk_extractor`)
* Added: mobile/reverse (`apktool`, `jadx`), CMS (`joomscan`, `wpscan`)
* Added: Python venv tools (`pypykatz`, `arjun`, `commix`, `volatility3`, `objection`, `frida-tools`, `NetExec`)
* Added: Go recon stack (`ffuf`, `nuclei`, `jaeles`, `amass`, `subfinder`, `httpx`, `dnsx`, `katana`, `waybackurls`, `anew`, `unfurl`, `s3scanner`, `kerbrute`, `gitleaks`)
* Added: `Trivy`, `AWS CLI v2`, impacket wrappers, `linpeas.sh`, helpers




