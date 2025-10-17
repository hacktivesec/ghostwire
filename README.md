![Ghostwire](https://github.com/hacktivesec/ghostwire/blob/main/Ghostwire.png "Ghostwire")

# ghostwire

A lean, no-nonsense **web / network / AD** toolkit that runs anywhere Docker runs.
Bring your targets, your scope, and your SOCKS pivot, ghostwire handles the rest.

<p align="left">
  <a href="#"><img alt="Ubuntu 24.04" src="https://img.shields.io/badge/base-Ubuntu%2024.04-EB5E28?logo=ubuntu&logoColor=white"></a>
  <a href="#"><img alt="Dockerized" src="https://img.shields.io/badge/packaging-Docker-2496ED?logo=docker&logoColor=white"></a>
  <a href="#"><img alt="Non-root default" src="https://img.shields.io/badge/user-ghost%20(non--root)-6C757D"></a>
  <a href="#"><img alt="SecLists" src="https://img.shields.io/badge/wordlists-SecLists-0E7C86"></a>
</p>

---

## 🔎 What’s inside

**Web:** `dirsearch`, `gobuster`, `nikto`, `sqlmap`, `wfuzz`, `whatweb`, `wafw00f`, `testssl`
**Network:** `nmap`, `masscan`, `netcat-openbsd`, `socat`, `tcpdump`, `traceroute`, `dnsutils`, `openssl`
**AD / Auth:** `python3-impacket` (module entrypoints), `ldap-utils`, `smbclient`, `ldapdomaindump`, `bloodhound-python` *(venv)*, `smbmap`
**Cracking:** `hashcat` *(CPU OpenCL via POCL)*, `john`, `hydra`
**Wordlists:** **SecLists** at `/opt/seclists` → `$SECLISTS`

**Helpers:**

* `px` run any command via **SOCKS5** (`socks5h` DNS on proxy)
* `savehere` copy files/dirs to `/shared` (host-mounted)
* `out` tee output to `/shared/<cmd>_<ts>.log`
* `update-seclists` fast-forward pull of SecLists
* Shell UX: retro two-line prompt, default user **ghost** (sudo enabled)

---

## ⚙️ Requirements

* Docker (Linux) or Docker Desktop (Windows/macOS)
* For **SOCKS** pivot: reachable SOCKS5 service (e.g. `127.0.0.1:1080` on a jump box)
* For **GPU**: vendor drivers + container runtime (see below)

---

## 🚀 Quickstart

### Build

**Linux / macOS**

```bash
docker build -t ghostwire-toolkit .
```

**Windows (PowerShell)**

```powershell
docker build -t ghostwire-toolkit .
```

### Run

#### A) Linux jumpbox with SOCKS on `127.0.0.1:1080` (recommended)

```bash
mkdir -p artifacts
docker run --rm -it --network host \
  -e SOCKS5_HOST=127.0.0.1 -e SOCKS5_PORT=1080 \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  --name ghostwire \
  ghostwire-toolkit
```

#### B) Windows/macOS with Docker Desktop (no host network)

```powershell
New-Item -ItemType Directory -Force -Path .\artifacts | Out-Null
$work  = (Get-Location).Path
$share = Join-Path $work 'artifacts'
docker run --rm -it --name ghostwire `
  -e SOCKS5_HOST=host.docker.internal -e SOCKS5_PORT=1080 `
  --mount type=bind,source="$work",target=/work `
  --mount type=bind,source="$share",target=/shared `
  ghostwire-toolkit
```

#### C) Extra capabilities when needed (Linux)

**Raw sockets / capture**

```bash
docker run --rm -it \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  --name ghostwire \
  ghostwire-toolkit
```

**GPU acceleration (optional)**

```bash
# Install NVIDIA driver + nvidia-container-toolkit on the host
docker run --rm -it --gpus all \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  --name ghostwire \
  ghostwire-toolkit

# inside:
hashcat -I   # check OpenCL devices
```

> The image includes a generic OpenCL ICD loader; vendor libs come from the host.
> On Windows/macOS, GPU passthrough depends on Desktop support and host drivers.

---

## 🖥️ Getting a shell

```bash
# interactive bash (default) if container is already running:
docker exec -it ghostwire bash

# root shell:
docker exec -u 0 -it ghostwire bash
# or inside the container: sudo -s

# start a fresh container explicitly:
docker run --rm -it -v "$PWD:/work" -v "$PWD/artifacts:/shared" ghostwire-toolkit
```

---

## 🧦 Using the SOCKS pivot

**One-off via wrapper**

```bash
px curl -I https://example.com
px dirsearch -u https://example.com -w "$SECLISTS/Discovery/Web-Content/common.txt" -e php,js,html -o /shared/dirsearch.txt
px gobuster dir -u https://example.com -w "$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt" -x php,js,html -o /shared/gobuster.txt
px sqlmap -u "https://example.com/?id=1" --batch
# nmap over SOCKS is connect-only (proxychains-style):
px nmap -sT -Pn -n example.com
```

**Environment-wide**

```bash
export ALL_PROXY="socks5h://${SOCKS5_HOST}:${SOCKS5_PORT}"
export HTTP_PROXY="$ALL_PROXY" HTTPS_PROXY="$ALL_PROXY" NO_PROXY="127.0.0.1,localhost"
# socks5h ensures DNS resolves on the proxy
```

> Raw SYN/UDP scans and packet capture do not traverse SOCKS.
> Run those on the jump box (optionally with `--cap-add NET_RAW,NET_ADMIN`).

---

## 📁 Files in/out

* Work in **`/work`** (bind-mounted from your current host folder)
* Export artifacts to **`/shared`** → appears on host in `./artifacts`

```bash
savehere report.txt
out /bin/uname -a
```

---

## 🧪 Quick self-test (safe targets only)

```bash
# inside the container
whoami && pwd
[ -w /work ] && echo "/work: ok" || echo "/work: NO"
[ -w /shared ] && echo "/shared: ok" || echo "/shared: NO"
curl -I https://example.com

# versions / presence
nmap --version
masscan --version || true
gobuster -h | head -n 2
whatweb --version
wafw00f --version
testssl --help | head -n 1
sqlmap --version | head -n 1
wfuzz --version
hashcat --version
john --help | head -n 15
hydra -h | head -n 1
python3 -m impacket.smbserver -h | head -n 1
/opt/ghost-venv/bin/bloodhound-python -h | head -n 1
smbclient --version
smbmap -h | head -n 1
dirsearch --help | head -n 3

# optional: capture (requires NET_RAW/NET_ADMIN)
sudo -n tcpdump -D || echo "no capture caps (ok)"
sudo -n tcpdump -i lo -c 10 -w /shared/lo_test.pcap || true
ls -lh /shared/lo_test.pcap || true

# optional: GPU (requires --gpus all)
hashcat -I || true
```

---

## 🛠️ Quick task guide (consent-only / lab)

**Web recon (low-touch)**

```bash
whatweb https://example.com
wafw00f https://example.com
testssl --help | head -n 1   # review options; run per ROE
```

**Network (connect-only over proxy)**

```bash
px nmap -sT -Pn -n example.com
```

**Active Directory (lab / authorized)**

```bash
ldapsearch -x -H ldap://dc.lab.local -b "DC=lab,DC=local" -s base
ldapdomaindump ldap://10.0.0.10 -u 'lab.local\user' -p '***' -o /shared/ad-dump
/opt/ghost-venv/bin/bloodhound-python -d lab.local -u user -p '***' -ns 10.0.0.10 -c all -o /shared/bh
smbmap -H 10.0.0.20 -u user -p '***'
```

**Cracking (local files)**

```bash
hashcat -m 0 hashes.txt "$SECLISTS/Passwords/Common-Credentials/10k-most-common.txt" -o /shared/cracked.txt
john --wordlist="$SECLISTS/Passwords/Common-Credentials/10k-most-common.txt" hashes.txt
```

---

## 🔄 Updating

**Wordlists**

```bash
update-seclists
```

**APT tools**

```bash
sudo apt-get update && sudo apt-get install --only-upgrade \
  gobuster nikto sqlmap wfuzz whatweb wafw00f testssl.sh \
  nmap masscan hashcat john hydra python3-impacket
```

**Python tools in the venv**
Rebuild the image to keep versions consistent.

---

## 🧩 Troubleshooting

* **Windows `$PWD:/path` errors** Use `--mount` or `${PWD}.Path` (PowerShell).
* **`testssl.sh` not found** Binary name is `testssl` on Ubuntu.
* **Impacket CLIs** With apt, use module entrypoints (e.g., `python3 -m impacket.smbserver`).
* **`john --version`** Some builds lack it; use `john --help` or `john --list=all`.
* **`out` wrapper** Pass a full path as first arg (e.g., `out /bin/uname -a`).
* **CRLF line endings** If scripts were edited on Windows:

  ```bash
  sed -i 's/\r$//' /usr/local/bin/{px,savehere,update-seclists,dirsearch,out}
  ```

---

## 🧷 Bonus: container-to-container SOCKS on a user network

```powershell
# PowerShell
$JUMP = "jumphost"   # name of your running microsocks container
docker network inspect rednet > $null 2>&1; if ($LASTEXITCODE -ne 0) { docker network create rednet | Out-Null }
docker network connect rednet $JUMP 2>$null

New-Item -ItemType Directory -Force -Path .\artifacts | Out-Null
$work  = (Get-Location).Path; $share = Join-Path $work 'artifacts'

docker run --rm -it --network rednet `
  -e SOCKS5_HOST=$JUMP -e SOCKS5_PORT=1080 `
  --mount type=bind,source="$work",target=/work `
  --mount type=bind,source="$share",target=/shared" `
  --name ghostwire `
  ghostwire-toolkit:latest

# inside ghostwire:
px curl -I https://example.com
```

Docker’s embedded DNS resolves the `$JUMP` container name on the same user-defined network. Traffic stays behind NAT.

---
> **Status:** This project is in **continuous evolution** — we’re steadily **dockerizing** and **de-bloating** everything we can to keep it fast, portable, and practical for **red teamers** and **pentesters**. It’s designed to run cleanly on **servers** (VMs or Kubernetes) so you can **scale** jobs, keep **load off your host**, and **standardize** tooling across the team and environments.

### Why containers for offensive tooling?
- **Standardize**: same versions, same flags, same UX on every host.
- **Scale on servers**: run jobs in parallel on beefy nodes/K8s without polluting them.
- **Reduce host burden**: keep drivers and special libs on the server side; your laptop stays clean.
- **Reproducible**: pinned base + optional locks mean fewer “works on my machine” moments.

