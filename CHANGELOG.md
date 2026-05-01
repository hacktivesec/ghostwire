# Changelog

All notable changes to this project are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-05-01

### Added
- `Dockerfile.base` — shared layer (apt core, python venv, ghost user, scripts).
  All variants now `FROM ghostwire-base`, eliminating ~5×500MB of duplication.
- `Dockerfile.pivot` — SOCKS5 / chisel / WireGuard / OpenVPN / sshuttle jumpbox.
  Closes the SOCKS-pivot-first design loop.
- `gw` orchestrator (`scripts/gw`) with subcommands:
  `new`, `use`, `cd`, `ls`, `recon`, `web`, `fuzz`, `ad`, `mobile`, `wifi`,
  `report`, `versions`, `help`.
- Engagement-aware `/shared/<client>/<UTC-date>/{recon,scans,creds,loot,reports,logs}`
  layout, persisted to `~/.config/ghostwire/active`. `cdgw` jumps in.
- Multi-arch (amd64 + arm64) builds via buildx + QEMU.
- GHCR publishing of all 7 images (`ghcr.io/hacktivesec/ghostwire-{base,web,net,ad,mobile,wifi,pivot}`).
- Cosign keyless OIDC signing on every published image.
- SLSA build provenance attestations.
- syft SBOM generation per image.
- `subfinder`, `anew`, `assetfinder` added to `web` variant.
- `microsocks` for the `pivot` variant.
- `SECURITY.md` with disclosure policy and verification recipe.
- `CHANGELOG.md` (this file).
- Beefier `smoke-test.sh`: SOCKS reachability, SecLists integrity, dry-run probes.

### Changed
- Pinned every previously-floating dependency to a tag or commit:
  `gf` (commit), `jaeles` `v0.17.1`, `SecLists` `2026.1`, `XSStrike` (commit),
  `testssl.sh` `v3.2.3`, `NetExec` `v1.5.1`, `enum4linux-ng` `v1.3.10`,
  `Responder` (commit), `Pacu` `v1.7.0`, `coercer` `2.4.3`, `MobSF` `v4.4.6`,
  `bulk_extractor` `v2.1.1`.
- `docker-compose.yml`: pull from GHCR by default; build only when
  `GHOSTWIRE_IMAGE_TAG=local`. `.env` no longer required to bring services up.
- GCP CLI install now arch-aware (was hardcoded x86_64).
- Dropped `env_file: [.env]` from compose (made optional via env defaults).
- README rewritten with "why ghostwire" section, GHCR pull quickstart,
  cosign verify recipe, and `gw` orchestrator examples.

### Security
- `.env` now gitignored. `.env.example` is the committed template.
- Non-root `ghost` user pinned to UID/GID 1001 (was unset, system-assigned).
- Healthchecks tightened per variant.

### Fixed
- `docker-buildx` plugin pulled in CI (was implicit, broken on minimal runners).
- `dpkg-architecture` checks for arm64 across AWS / GCP / installer steps.
