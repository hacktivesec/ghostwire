
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
- [What's inside](#whats-inside)
- [Requirements](#requirements)
- [Repo layout](#repo-layout)
- [Quick start](#quick-start)
- [Using the SOCKS pivot](#using-the-socks-pivot)
- [Common flows (consent / lab)](#common-flows-consent--lab)
- [Files in/out](#files-inout)
- [Self-test](#quick-self-test)
- [Updating](#updating)
- [Troubleshooting](#troubleshooting)
- [Intended use](#intended-use)
- [Credits](#credits)

---

## What's inside

### Per image

| Image | Tools |
|-------|-------|
| **web** | `ffuf`, `gobuster`, `nikto`, `sqlmap`, `wfuzz`, `whatweb`, `wafw00f`, `nuclei`, `xsstrike`, `testssl`, `arjun`, `commix`, `httpx`, `dnsx`, `katana`, `waybackurls`, `gospider` |
| **net** | `nmap`, `masscan`, `tcpdump`, `tshark`, `chisel`, `socat`, `hydra`, `openvpn`, `sshuttle`, `wireguard`, `ike-scan`, `httpx`, `dnsx` |
| **ad** | `nxc`, `bloodhound-python`, `certipy`, `kerbrute`, `responder`, `coercer`, `impacket` wrappers, `hashcat`, `john`, `hydra`, `aws`, `az`, `gcloud`, `scoutsuite`, `pacu`, `enum4linux-ng` |
| **mobile** | `jadx`, `apktool`, `adb`, `frida-tools`, `objection`, `radare2`, `ipatool`, `mobsfscan`, `androguard` |
| **wifi** | `aircrack-ng`, `reaver`, `pixiewps`, `hcxdumptool`, `hcxtools`, `tshark`, `tcpdump` |

**All images:** SecLists at `$SECLISTS`, `proxychains4`, `px`/`pxcurl`/`pxwget` SOCKS wrappers

### Helpers
`px` (SOCKS5 wrapper) · `pxcurl` · `pxwget` · `savehere` · `out` · `session-log` · `update-seclists` · `gw-versions` · `smoke-test`
Impacket wrappers: `psexec`, `wmiexec`, `secretsdump`, `ntlmrelayx`, `atexec`, `ticketer`, `GetUserSPNs`, `GetNPUsers`, `addcomputer`, `smbserver`

---

## Requirements
- Docker **and** Docker Compose v2
- For **SOCKS:** reachable SOCKS5 proxy (default `127.0.0.1:1080`)


---

## Repo layout

```
Dockerfile.web            → web recon + vuln scanning
Dockerfile.net            → network recon + tunneling
Dockerfile.ad             → Active Directory + cloud
Dockerfile.mobile         → Android & iOS
Dockerfile.wifi           → wireless
docker-compose.yml        → recommended way to build/run
docker-compose.merged.yml → all services, tagged images
scripts/                  → shared helper scripts (COPY'd into images)
tests/smoke-test.sh       → per-variant tool presence check
Makefile                  → convenience targets
.github/workflows/        → CI: lint, build, smoke test
```

---

## Quick start

### Using Make (easiest)

```bash
make web            # build & start the web container
make shell          # drop into it
make test           # run smoke tests

# or pick a variant
make ad             # AD + cloud
make shell-ad       # shell into AD container
make test-web       # smoke test web image
```

### Using Compose

```bash
# build & start a variant
docker compose up -d web    # or net|wifi|mobile|ad
docker compose exec web bash
docker compose down
```

### Docker CLI

```bash
mkdir -p artifacts
docker build -t ghostwire:web -f Dockerfile.web .
docker run --rm -it --network host \
  -e SOCKS5_HOST=127.0.0.1 -e SOCKS5_PORT=1080 \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  --name ghostwire ghostwire:web
```

### Docker Desktop (Mac/Windows)

```bash
# .env: SOCKS5_HOST=host.docker.internal
docker compose up -d web
docker compose exec web bash
```

### WiFi capture (Linux, needs caps)

```bash
make wifi
docker compose exec wifi bash
wifi-mon wlan0 on
wifi-capture wlan0
```

---

## Using the SOCKS pivot

### Linking to a VPN jumpbox

If you run a VPN container (e.g. a SOCKS5 proxy on port `1080`), ghostwire can reach it over a shared Docker network:

```bash
# 1. Create the shared network (once)
docker network create vpn

# 2. Start your VPN container on that network
docker run -d --name vpn-jumpbox --network vpn \
  -p 127.0.0.1:1080:1080 your-vpn-image

# 3. Point ghostwire at it (in .env)
VPN_NETWORK=vpn
SOCKS5_HOST=vpn-jumpbox
SOCKS5_PORT=1080

# 4. Start ghostwire — containers join the vpn network automatically
docker compose up -d web
```

On Docker Desktop (Mac/Windows) without a shared network, use `SOCKS5_HOST=host.docker.internal` in `.env`.

### Using the proxy

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

## Common flows (consent / lab)

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

**Active Directory**

```bash
nxc smb 10.0.0.0/24 -u user -p '***' --shares
responder -I eth0 -dwPv
mitm6 -d lab.local
bloodhound-python -d lab.local -u user -p '***' -ns 10.0.0.10 -c All
certipy find -u user@lab.local -p '***' -dc-ip 10.0.0.10
```

**Cloud audit**

```bash
scoutsuite aws --access-keys-id <key> --secret-access-key <secret>
pacu
trivy fs --severity MEDIUM,HIGH,CRITICAL .
```

**Mobile**

```bash
jadx -d /shared/jadx app.apk
apktool d app.apk -o /shared/app
objection explore
frida-ps -U
```

**Forensics**

```bash
foremost -i disk.img -o /shared/foremost
bulk_extractor -o /shared/be_out disk.img
exiftool sample.jpg
```

---

## Files in/out

* Work in **`/work`** (bind-mounted from your repo root)
* Export artifacts to **`/shared`** (bind-mounted to `./artifacts`)

```bash
savehere report.txt
out nmap -sC -sV target
gw-versions /shared/versions.txt
```

---

## Quick self-test

```bash
# automated (inside the container)
smoke-test web    # or net|wifi|mobile|ad

# manual spot check
whoami && pwd
nmap --version
gw-versions
```

---

## Build args, env & volumes

* **Build args:** `BASE_IMAGE=ubuntu:24.04`
* **Environment:** `SOCKS5_HOST`, `SOCKS5_PORT`, `SECLISTS=/opt/seclists`, `ARTIFACTS=/shared`
* **Volumes:** `/shared` (artifacts), `/work` (workspace)
* **Healthcheck:** verifies core tools are reachable

---

## Updating

* **SecLists:** `update-seclists`
* **APT tools:** `sudo apt-get update && sudo apt-get upgrade`
* **Python/Go/Ruby tools:** rebuild the image

---

## Troubleshooting

* **"container name already in use"** — `docker rm -f ghostwire` or use `--name ghostwire2`
* **Windows path issues** — prefer `--mount` or forward slashes
* **SOCKS not reachable** — on Docker Desktop use `host.docker.internal`

---

## Intended use

**Red team / pentest / DFIR / training only — on systems you own or have explicit written permission to test.**
You are responsible for complying with laws, contracts, and your Rules of Engagement.

---

## Credits

This image repackages work from many OSS projects (see individual repos/licenses).
OCI labels are included in the image metadata.
