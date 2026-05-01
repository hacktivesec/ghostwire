# Security policy

## Reporting

If you find a security issue **in ghostwire itself** (e.g. a build that pulls a
compromised dependency, a privilege escalation in the image, a leaking
container default), report it privately:

- **GitHub Security Advisories**: https://github.com/hacktivesec/ghostwire/security/advisories/new
- **Email** (alternative): see `git log --format='%ae' | sort -u | head -1`

Please include:
- Affected variant(s) and image digest
- Reproduction (Dockerfile excerpt, command, expected vs. actual)
- Suggested fix if you have one

I aim to acknowledge within 72 hours and ship a fix or mitigation within
14 days for high-severity issues.

## Scope

In scope:
- Container hardening (root creep, missing dropped caps, exposed sockets)
- Dependency supply-chain (poisoned upstream, missing signature verification)
- Build process (CI secret exposure, missing pin, unsafe `latest` reference)
- `gw` orchestrator (command injection, path traversal in engagement dirs)

Out of scope:
- Vulnerabilities in third-party tools shipped (report upstream — the relevant
  repo is in the `git clone` step or pip install)
- Misuse against systems you don't own
- Trivy/Grype findings on the base Ubuntu image where no fix is yet available

## Verification

All published images are signed (cosign keyless OIDC) and have SLSA build
provenance attached. Verify before pulling into production:

```sh
cosign verify \
  --certificate-identity-regexp 'https://github.com/hacktivesec/ghostwire/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/hacktivesec/ghostwire-web:latest
```

## Intended use

ghostwire is for authorised security testing: red team, pentest, DFIR, CTF,
training, and self-owned-lab work. You are responsible for laws, contracts,
and Rules of Engagement.
