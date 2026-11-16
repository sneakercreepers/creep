# Security Policy

`creep` reads untrusted code and talks to language models, so we expect it to be a target. Thank you for helping keep it safe.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:
[Report a vulnerability](https://github.com/sneakercreepers/creep/security/advisories/new)

Please include the version, the configuration (`creep config explain`, with secrets removed), steps to reproduce and the impact you expect.

## What we commit to

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Initial assessment | 7 days |
| Fix released — critical | ≤ 7 days |
| Fix released — high | ≤ 30 days |
| Fix released — medium/low | Next minor release |

We publish a GitHub Security Advisory and request a CVE for confirmed vulnerabilities, and credit reporters who want it.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor | ✅ |
| Previous minor | ✅ security fixes only |
| Older | ❌ |

Before v1.0, only the latest minor release is supported.

## Verifying a release

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml) from a `v*` tag, only in the `release` environment (maintainer approval) and only when the tagged commit is on `main` or a `release/*` branch. No signing key exists: the workflow signs with its short-lived GitHub OIDC identity (Sigstore keyless).

Each release has:

- `checksums.txt`: the SHA-256 of every archive and SBOM.
- `checksums.txt.sigstore.json`: the cosign bundle (signature, certificate, transparency-log entry) for `checksums.txt`.
- A build provenance attestation (`actions/attest-build-provenance`) for every file listed in `checksums.txt`.
- `<archive>.sbom.json`: an SPDX SBOM per archive.

The workflow runs these commands against its own output and publishes the release only when they pass. For release `vX.Y.Z`, with cosign v3+ and the GitHub CLI:

```sh
cosign verify-blob \
  --certificate-identity 'https://github.com/sneakercreepers/creep/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
gh attestation verify creep_X.Y.Z_linux_amd64.tar.gz \
  --repo sneakercreepers/creep \
  --signer-workflow sneakercreepers/creep/.github/workflows/release.yml
```

A certificate or attestation naming any other workflow, ref or repository means the file was not built by our release workflow: do not run it, and report it as above.

## Threat model

[docs/threat-model.md](docs/threat-model.md) lists what creep protects, its trust boundaries, the attackers it expects (malicious repository, malicious model, network attacker, malicious recipe, local user, malicious contributor) and the control and test behind each mitigation. A report that breaks one of those mitigations is in scope.

## In scope

- Secrets or code leaving the machine despite redaction or `local-only` mode
- Prompt injection that changes the planner's decisions or causes command execution
- Sandbox escape or network egress from the sandbox
- Tool canary bypass in the command contract
- Supply-chain issues in our releases (signatures, provenance, SBOM)

## Out of scope

- Vulnerabilities `creep` fails to detect in *your* code — open a *False negative* issue instead
- Findings in third-party scanners (semgrep, osv-scanner, gitleaks) — report them upstream
