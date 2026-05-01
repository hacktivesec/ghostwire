<p align="center">
  <img src="Ghostwire.png" alt="Ghostwire" width="50%">
</p>

<h1 align="center">ghostwire</h1>

<p align="center">
  A lean <b>web · network · AD · mobile · wifi · pivot</b> toolkit that runs anywhere Docker runs.<br>
  Pull a variant, drop into a shell, run <code>gw recon target.com</code>.
</p>

<p align="center">
  <a href="#"><img alt="Ubuntu 24.04" src="https://img.shields.io/badge/base-Ubuntu%2024.04-EB5E28?logo=ubuntu&logoColor=white"></a>
  <a href="#"><img alt="amd64+arm64" src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64-1F6FEB"></a>
  <a href="#"><img alt="Cosign signed" src="https://img.shields.io/badge/cosign-keyless%20OIDC-brightgreen"></a>
  <a href="#"><img alt="SLSA L2" src="https://img.shields.io/badge/SLSA-L2%20provenance-A872E2"></a>
  <a href="#"><img alt="Non-root" src="https://img.shields.io/badge/user-ghost%20(non--root)-6C757D"></a>
  <a href="LICENSE"><img alt="CC0" src="https://img.shields.io/badge/license-CC0-0A0A0A"></a>
</p>

---

## Why ghostwire

| | ghostwire | Kali / Parrot Docker | BlackArch | Custom Dockerfile |
|---|---|---|---|---|
| First-run time | **30 s** (pull from GHCR) | 5–20 min build | 30 min+ | hours |
| Image size | 5 specialised, ~2 GB each | 1 mega image, 5–8 GB | 6+ GB | varies |
| arm64 | **yes** | partial | partial | DIY |
| Pinned deps | **every git clone, every Go module** | apt rolling | rolling | DIY |
| Signed images | **cosign keyless OIDC** | no | no | DIY |
| SBOM + SLSA provenance | **yes** | no | no | DIY |
| Non-root by default | **yes** (ghost UID 1001) | no | no | DIY |
| SOCKS-pivot first-class | **yes** (`px`, pivot variant) | no | no | DIY |
| Engagement workflow | **`gw new client`** | none | none | DIY |
| Reporting | **`gw report` → markdown** | none | none | DIY |

If you want one container that just works on a fresh laptop, signed and reproducible — pick ghostwire. If you want a desktop OS in a container, pick Kali.

---

## Variants

| Image | Tools |
|-------|-------|
| **base** | `python3-venv`, `proxychains4`, `px`/`pxcurl`/`pxwget`, `gw` orchestrator, `ghost` user, `tini` |
| **web** | `ffuf`, `gobuster`, `nikto`, `sqlmap`, `wfuzz`, `whatweb`, `wafw00f`, `nuclei`, `xsstrike`, `testssl`, `arjun`, `commix`, `httpx`, `dnsx`, `katana`, `subfinder`, `waybackurls`, `gospider`, `gf`, `anew`, `assetfinder`, `jaeles` |
| **net** | `nmap`, `masscan`, `tcpdump`, `tshark`, `tcpflow`, `ngrep`, `chisel`, `socat`, `hydra`, `openvpn`, `sshuttle`, `wireguard-tools`, `ike-scan`, `onesixtyone`, `httpx`, `dnsx`, `subfinder` |
| **ad** | `nxc`, `bloodhound-python`, `certipy`, `kerbrute`, `responder`, `mitm6`, `coercer`, `impacket` wrappers, `enum4linux-ng`, `hashcat`, `john`, `hydra`, `aws`, `az`, `gcloud`, `scoutsuite`, `pacu`, `bulk_extractor` |
| **mobile** | `jadx`, `apktool`, `adb`, `frida-tools`, `objection`, `radare2`, `ipatool`, `mobsfscan`, `androguard`, `apkid`, `quark-engine`, `MobSF`, `yara` |
| **wifi** | `aircrack-ng`, `reaver`, `pixiewps`, `hcxdumptool`, `hcxtools`, `tshark`, `tcpdump`, `iw`, `wpasupplicant` |
| **pivot** | `microsocks`, `chisel`, `sshuttle`, `openvpn`, `wireguard-tools`, `openssh-server`, `iptables`, `nftables` |

All variants ship: SecLists at `$SECLISTS` (web/net/ad), `gw` orchestrator, `px`/`pxcurl`/`pxwget` SOCKS5 wrappers, `savehere`/`out`/`session-log`/`gw-versions`/`update-seclists`, non-root `ghost` user, healthcheck.

---

## Quick start (pull, don't build)

```bash
docker pull ghcr.io/wnoelll/ghostwire-web:latest
docker run --rm -it --network host \
  -e SOCKS5_HOST=127.0.0.1 -e SOCKS5_PORT=1080 \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  ghcr.io/wnoelll/ghostwire-web:latest
```

Or with compose (default = pull from GHCR):

```bash
docker compose up -d web
docker compose exec web bash
```

### Verify the image (cosign)

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/wnoelll/ghostwire/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/wnoelll/ghostwire-web:latest
```

---

## The `gw` orchestrator

`gw` is a single command that runs the common flows for you and stores output in
a tidy engagement directory under `/shared/<client>/<UTC-date>/`.

```bash
# Inside any variant container:

gw new acme                       # /shared/acme/2026-05-01_103045/{recon,scans,...}
gw recon acme.com                 # subfinder | httpx | nuclei pipeline
gw web https://app.acme.com       # whatweb + wafw00f + nuclei + nikto + gobuster
gw fuzz "https://acme.com/FUZZ"   # ffuf with directory-list-2.3-medium
gw ad 10.0.0.10 alice 'P@ss'      # nxc + kerbrute + bloodhound + certipy
gw mobile app.apk                 # jadx + apkid + apktool + mobsfscan
gw wifi wlan0                     # airodump capture
gw report                         # consolidate everything into markdown
gw ls                             # show all engagements
cdgw                              # cd into the active one
```

Output goes into `/shared/<client>/<date>/{recon,scans,creds,loot,reports,logs}`.
Set `ENGAGEMENT_DIR` to override the active engagement; otherwise `gw new`/`gw use`
persists it to `~/.config/ghostwire/active`.

`gw help` for the full list.

---

## SOCKS pivot (the whole point)

### Run the pivot variant as your jumpbox

```bash
docker run -d --name pivot --network vpn \
  -p 127.0.0.1:1080:1080 -p 8080:8080 \
  ghcr.io/wnoelll/ghostwire-pivot:latest \
  gw-socks5 1080
```

### Or use chisel reverse SOCKS

```bash
# This side (operator):
docker run --rm -it -p 8080:8080 ghcr.io/wnoelll/ghostwire-pivot:latest \
  gw-chisel-server 8080

# Compromised box:
chisel client your-host:8080 R:1080:socks
```

### Use the pivot from any other variant

```bash
docker run --rm -it --network vpn \
  -e SOCKS5_HOST=pivot -e SOCKS5_PORT=1080 \
  -v "$PWD:/work" -v "$PWD/artifacts:/shared" \
  ghcr.io/wnoelll/ghostwire-web:latest

# Then:
px curl -I https://internal.target
px gw recon internal.target
```

> Raw SYN/UDP scans and packet capture do **not** traverse SOCKS5 — they're L3.

---

## Files in / out

* `/work` — your repo or workspace, bind-mounted r/w
* `/shared` — artifacts dir, mapped to `./artifacts/` on the host
* `/shared/<client>/<UTC-date>/` — created by `gw new`

```bash
savehere report.txt                  # copy to /shared
out nmap -sC -sV target              # tee output to /shared/nmap_<ts>.log
gw-versions /shared/versions.txt     # tool manifest
```

---

## Build locally (don't pull from GHCR)

```bash
make base          # build shared base first (one time)
make build-all     # build base + every variant locally
make test-all      # smoke-test every variant
make web           # build & start one variant
make shell-ad      # shell into ad container
make prune         # remove all images and clean buildx cache
```

Local images are tagged `ghostwire-<variant>:dev`. Compose picks them up when
`GHOSTWIRE_IMAGE_TAG=local`.

---

## CI / supply chain

Every push to `main` and every `v*` tag rebuilds and publishes:

- **GHCR**: `ghcr.io/wnoelll/ghostwire-{base,web,net,ad,mobile,wifi,pivot}`
- **Architectures**: `linux/amd64` and `linux/arm64`
- **Cosign**: keyless OIDC signature on every digest
- **SLSA**: build-provenance attestation
- **SBOM**: syft SPDX, attached as image attestation
- **Trivy scan**: HIGH/CRITICAL surfaced (non-blocking)

Verify any tag with `cosign verify` (recipe in [SECURITY.md](SECURITY.md)).

---

## Common flows (consent / lab only)

```bash
# Subdomains → probe → fuzz
gw recon example.com
gw fuzz "https://example.com/FUZZ"

# Active Directory
gw ad 10.0.0.10 alice 'P@ss'

# Cloud audit
scoutsuite aws --access-keys-id <k> --secret-access-key <s>
pacu

# Mobile
gw mobile app.apk

# Forensics
bulk_extractor -o /shared/be_out disk.img
```

---

## Updating

* **SecLists**: `update-seclists` (in-container) — refreshes to current upstream
* **Container itself**: `docker pull ghcr.io/wnoelll/ghostwire-<variant>:latest`
* **Pin tracking**: dependabot opens weekly PRs for action and Docker FROM bumps

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `container name already in use` | `docker rm -f ghostwire-<variant>` or use `--name` |
| Windows path mounts fail | use forward slashes or `--mount` |
| SOCKS unreachable on Docker Desktop | set `SOCKS5_HOST=host.docker.internal` |
| arm64 build fails on a tool | open an issue with the variant + Dockerfile line |
| Healthcheck red | `docker logs <container>` and `smoke-test <variant>` |

---

## Intended use

**Red team / pentest / DFIR / training only — on systems you own or have explicit
written permission to test.** You are responsible for laws, contracts, and your
Rules of Engagement. See [SECURITY.md](SECURITY.md).

---

## Credits

ghostwire repackages work from many OSS projects. Each tool's licence applies in
the image where it ships; OCI labels capture provenance. Pinned tool versions
are listed in `Dockerfile.<variant>` and in this repo's `CHANGELOG.md`.
