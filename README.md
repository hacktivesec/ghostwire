<p align="center"><img src="https://github.com/hacktivesec/ghostwire/blob/main/Ghostwire.png" alt="Ghostwire" width="50%"></p>

# ghostwire

A lean, no-nonsense **web / network / AD** toolkit that runs anywhere Docker runs.
Bring your targets, your scope, and your SOCKS pivot—ghostwire handles the rest.

<p align="left">
  <a href="#"><img alt="Ubuntu 24.04" src="https://img.shields.io/badge/base-Ubuntu%2024.04-EB5E28?logo=ubuntu&logoColor=white"></a>
  <a href="#"><img alt="Dockerized" src="https://img.shields.io/badge/packaging-Docker-2496ED?logo=docker&logoColor=white"></a>
  <a href="#"><img alt="Non-root default" src="https://img.shields.io/badge/user-ghost%20(non--root)-6C757D"></a>
  <a href="#"><img alt="SecLists" src="https://img.shields.io/badge/wordlists-SecLists-0E7C86"></a>
</p>

---

## 🔎 What’s inside

### Core CLI

* **Web**: `dirsearch` *(venv wrapper)*, `gobuster`, `nikto`, `sqlmap`, `wfuzz`, `whatweb`, `wafw00f`, `testssl`
* **Network**: `nmap`, `masscan`, `dnsutils`, `iputils-ping`, `traceroute`, `netcat-openbsd`, `socat`, `tcpdump`, `iproute2`, `openssl`
* **AD / Auth**: `python3-impacket` *(module entrypoints + convenience symlinks)*, `krb5-user`, `ldap-utils`, `smbclient`, `ldapdomaindump`, `bloodhound-python` *(venv)*, `smbmap`
* **Cracking**: `hashcat` *(CPU OpenCL via POCL)*, `john`, `hydra`
* **Wordlists**: **SecLists** at `/opt/seclists` → `$SECLISTS`

### Extras (added)

* **Network & service**: `snmp`, `onesixtyone`, `ike-scan`, `patator`, `medusa`, classic `enum4linux`
* **Wireless** *(requires NET_RAW/NET_ADMIN caps from host)*: `aircrack-ng`, `reaver`, `bully`
* **Stego & forensics**: `steghide`, `exiftool`, `binwalk`, `foremost`, **bulk_extractor** *(built from source)*
* **Web CMS**: `joomscan`, `wpscan` (`wp` wrapper)
* **Mobile / reverse**: `apktool`, **jadx** (CLI + GUI), **MobSF** *(cloned only)*
* **Cloud & containers**: **Trivy**, **AWS CLI v2**, **ScoutSuite** (pinned `5.14.0`), `anchore-cli`, **CloudMapper** *(cloned only)*
* **AD/Windows post-ex** *(cloned only)*: **PowerSploit**, **Empire**
* **Python tools (venv)**: `pypykatz`, `arjun`, `commix`, `volatility3`, `objection`, `frida-tools`, **NetExec** (`nxc`, also symlink `crackmapexec`)
* **Go recon stack** (installed, then Go toolchain removed): `ffuf`, `nuclei`, `jaeles`, `amass`, `subfinder`, `httpx`, `naabu`, `dnsx`, `tlsx`, `katana`, `waybackurls`, `anew`, `unfurl`, `s3scanner`, `kerbrute`, `gitleaks` (v8)
  *(best-effort for `clair-scanner` / `clairctl`, may vary by arch)*
* **Convenience**: `linpeas.sh`, impacket symlinks (`psexec.py`, `secretsdump.py`, `wmiexec.py`, `ntlmrelayx.py`, etc.)

### Helpers

* `px` run any command via **SOCKS5** (`socks5h` DNS on proxy) · `pxcurl` / `pxwget`
* `savehere` copy files/dirs to `/shared` (host-mounted)
* `out` tee output to `/shared/<cmd>_<ts>.log`
* `update-seclists` refresh SecLists from upstream
* `session-log` start bash with history persisted to `/shared/history/…`
* `gw-wifi-capture` / `gw-usb-capture` capture helpers (see *Capabilities*)
* `gw-ssh-agent-check`, `gw-gpu-check`
* UX: two-line prompt, default user **ghost** (passwordless `sudo`)

---

## ⚙️ Requirements

* Docker on Linux/macOS/Windows (Desktop)
* For **SOCKS** pivot: reachable SOCKS5 (e.g. `127.0.0.1:1080`)
* For **GPU**: vendor drivers on host + container runtime hooks (e.g. `--gpus all` for NVIDIA)

---

## 🚀 Quickstart

### Build

```bash
docker build -t ghostwire-toolkit .
```

### Run

#### A) Linux jump box with local SOCKS (recommended)

```bash
mkdir -p artifacts
docker run --rm -it --network host \
  -e SOCKS5_HOST=127.0.0.1 -e SOCKS5_PORT=1080 \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  --name ghostwire \
  ghostwire-toolkit
```

#### B) Docker Desktop (Windows/macOS)

```powershell
New-Item -ItemType Directory -Force -Path .\artifacts | Out-Null
docker run --rm -it --name ghostwire `
  -e SOCKS5_HOST=host.docker.internal -e SOCKS5_PORT=1080 `
  --mount type=bind,source="$PWD",target=/work `
  --mount type=bind,source="$PWD\artifacts",target=/shared `
  ghostwire-toolkit
```

#### C) Extra capabilities (Linux)

* **Raw sockets / capture** *(for tcpdump/aircrack-ng etc.)*

  ```bash
  docker run --rm -it \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
    ghostwire-toolkit
  ```

* **GPU** *(optional)*

  ```bash
  # host: install driver + nvidia-container-toolkit
  docker run --rm -it --gpus all \
    -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
    ghostwire-toolkit
  # inside:
  hashcat -I
  ```

> The image ships a generic OpenCL ICD; vendor libs come from the host.

---

## 🧦 Using the SOCKS pivot

**One-off via wrapper**

```bash
px curl -I https://example.com
px dirsearch -u https://example.com -w "$SECLISTS/Discovery/Web-Content/common.txt" -e php,js,html -o /shared/dirsearch.txt
px gobuster dir -u https://example.com -w "$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt" -x php,js,html -o /shared/gobuster.txt
px sqlmap -u "https://example.com/?id=1" --batch
# connect-scan over SOCKS (proxychains style)
px nmap -sT -Pn -n example.com
```

**Environment-wide**

```bash
export ALL_PROXY="socks5h://${SOCKS5_HOST}:${SOCKS5_PORT}"
export HTTP_PROXY="$ALL_PROXY" HTTPS_PROXY="$ALL_PROXY" NO_PROXY="127.0.0.1,localhost"
```

> Raw SYN/UDP scans & packet capture do not traverse SOCKS—run on the jump box with proper caps.

---

## 🧰 Common flows (consent / lab)

> Basic examples.

* **Subdomains → probe → scan → nuclei**

  ```bash
  subfinder -silent -d example.com | anew /shared/subs.txt
  httpx -silent -status-code -title -follow -l /shared/subs.txt -o /shared/httpx.txt
  naabu -list /shared/subs.txt -o /shared/ports.txt
  nuclei -l /shared/httpx.txt -o /shared/nuclei.txt
  ```

* **Fuzz (dirs/params)**

  ```bash
  ffuf -u https://example.com/FUZZ -w "$SECLISTS/Discovery/Web-Content/common.txt" -o /shared/ffuf.json
  arjun -u https://example.com/page -oT /shared/arjun_params.txt
  ```

* **WordPress / CMS reconnaissance**

  ```bash
  wp --url https://example.com --enumerate vp,vt,u
  joomscan --url https://example.com
  ```

* **Active Directory (authenticated discovery)**

  ```bash
  nxc smb 10.0.0.0/24 -u user -p '***' --shares
  ldapdomaindump ldap://10.0.0.10 -u 'lab.local\user' -p '***' -o /shared/ad
  python3 -m impacket.secretsdump lab.local/user:'***'@10.0.0.10 -outputfile /shared/secrets
  ```

* **Windows post-ex (remote shell)**

  ```bash
  evil-winrm -i 10.0.0.5 -u 'user' -p '***'
  ```

* **Binary & mobile analysis (local files)**

  ```bash
  binwalk -e firmware.bin -C /shared/fw
  apktool d app.apk -o /shared/app
  jadx -d /shared/jadx app.apk
  ```

* **Forensics (local images)**

  ```bash
  foremost -i disk.img -o /shared/foremost
  bulk_extractor -o /shared/be_out disk.img
  exiftool sample.jpg
  ```

* **Cloud & code scanning**

  ```bash
  trivy fs --exit-code 0 --severity MEDIUM,HIGH,CRITICAL .
  gitleaks detect -s . -r /shared/gitleaks.json
  trufflehog filesystem --directory . --json > /shared/trufflehog.json
  scout aws --report-dir /shared/scout  # requires credentials in env/volume
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

## 🧪 Quick self-test

```bash
whoami && pwd
[ -w /work ] && echo "/work: ok" || echo "/work: NO"
[ -w /shared ] && echo "/shared: ok" || echo "/shared: NO"
curl -I https://example.com

# presence / versions (partial)
nmap --version
gobuster -h | head -n 2
whatweb --version
wafw00f --version
sqlmap --version | head -n 1
hashcat --version
hydra -h | head -n 1
dirsearch --help | head -n 3
ffuf -V
nuclei -version
nxc --version || true
wp --version || true
```

---

## 🧦 Capabilities & hardware helpers

* **Capture** (needs `--cap-add NET_RAW --cap-add NET_ADMIN`)

  ```bash
  sudo -n tcpdump -D || true
  gw-wifi-capture wlan0 /shared/wifi.pcap
  gw-usb-capture usbmon0 /shared/usb.pcap
  ```

* **GPU** (if `--gpus all`)

  ```bash
  gw-gpu-check
  hashcat -I
  ```

---

## 🔧 Build args, env & volumes

* **Build args**

  * `BASE_IMAGE` *(default `ubuntu:24.04`)*
  * `SECLISTS_SHA`, `DIRSEARCH_SHA` *(pin revisions or leave `HEAD`)*
* **Environment**

  * `SOCKS5_HOST` *(default `127.0.0.1`)*, `SOCKS5_PORT` *(default `1080`)*
  * `SECLISTS=/opt/seclists`, `DIRSEARCH_DIR=/opt/dirsearch`, `ARTIFACTS=/shared`
* **Volumes**

  * `VOLUME ["/shared", "/work"]`
* **Healthcheck** ensures `nmap`, `hashcat`, `python3`, and `dirsearch` are reachable.

---

## 🔄 Updating

* **SecLists**

  ```bash
  update-seclists
  ```
* **APT tools**

  ```bash
  sudo apt-get update && sudo apt-get install --only-upgrade \
    gobuster nikto sqlmap wfuzz whatweb wafw00f testssl.sh \
    nmap masscan hashcat john hydra python3-impacket
  ```
* **Python tools**
  Rebuild the image to keep the venv consistent.

---

## 🧷 Container-to-container SOCKS (user network)

```powershell
# PowerShell
$JUMP = "jumphost" # your SOCKS container name
docker network create rednet 2>$null | Out-Null
docker network connect rednet $JUMP 2>$null

docker run --rm -it --network rednet `
  -e SOCKS5_HOST=$JUMP -e SOCKS5_PORT=1080 `
  --mount type=bind,source="$PWD",target=/work `
  --mount type=bind,source="$PWD\artifacts",target=/shared `
  --name ghostwire `
  ghostwire-toolkit:latest

# inside ghostwire:
px curl -I https://example.com
```

---

## ✅ Intended use

**Red teaming / pentest / DFIR / training only—on systems you own or have explicit written permission to test.**
You are responsible for complying with laws, contracts, and your Rules of Engagement.

---

## 🙏 Credits

This image combines stellar open-source work from many projects (see individual repos/licenses).
`org.opencontainers.image.*` labels are included in the image metadata.

---

## 📝 Changelog (high-level)

* Added: network/service (`snmp`, `onesixtyone`, `ike-scan`, `patator`, `medusa`)
* Added: wireless (`aircrack-ng`, `reaver`, `bully`)
* Added: stego/forensics (`steghide`, `exiftool`, `binwalk`, `foremost`, `bulk_extractor`)
* Added: mobile/reverse (`apktool`, `jadx`), CMS (`joomscan`, `wpscan`)
* Added: post-ex & cloud stacks (PowerSploit, Empire, CloudMapper, MobSF clones)
* Added: Python venv tools (`pypykatz`, `arjun`, `commix`, `ScoutSuite`, `anchorecli`, `volatility3`, `objection`, `frida-tools`, `NetExec`)
* Added: Go recon stack (`ffuf`, `nuclei`, `amass`, `subfinder`, `httpx`, `naabu`, `dnsx`, `tlsx`, `katana`, `waybackurls`, `anew`, `unfurl`, `s3scanner`, `kerbrute`, `gitleaks`, `trufflehog`)
* Added: `Trivy`, `AWS CLI v2`, impacket symlinks, `linpeas.sh`, helpers

---

### Dev notes (optional)

* **Publish to GHCR**

  ```bash
  IMAGE=ghcr.io/<org-or-user>/ghostwire:latest
  docker buildx build --platform linux/amd64 -t "$IMAGE" --push .
  ```

* **Makefile idea** (handy)

  ```makefile
  build: ; docker build -t ghostwire-toolkit .
  run:   ; docker run --rm -it -v $(PWD):/work -v $(PWD)/artifacts:/shared --name ghostwire ghostwire-toolkit
  ```

---

## Known nits (Dockerfile)

* Duplicate wrapper generation for `dirsearch` appears twice; keeping one is enough.
* The `USER ghost (per uso …)` line (see above) must be `USER ghost`.

---



