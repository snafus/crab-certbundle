# CRAB Roadmap

**Certificate Root Anchor Builder** — planned milestones and status.

Items marked ✅ are shipped in the current release. Items marked 🔲 are planned.

---

## ✅ 0.1.0 — Initial Release (2026-04-12)

Core trust-directory pipeline, complete and tested.

### Pipeline

- ✅ `CertificateInfo` model — full X.509 attribute extraction (subject, issuer,
  fingerprints, key usage, EKU, CDP, AIA, BasicConstraints, validity)
- ✅ PEM bundle parsing (single file and concatenated bundle)
- ✅ Subject-hash computation: pyOpenSSL → `openssl` subprocess → pure-Python
  BER-walk fallback
- ✅ Policy engine: CA flag, pathLen, expiry, EKU, include/exclude rules,
  IGTF policy-tag filtering
- ✅ Atomic directory replacement (staging + rename; symlink-guard)
- ✅ IGTF metadata passthrough (`.info`, `.signing_policy`, `.namespaces`, `.crl_url`)
- ✅ CRL fetch, DER→PEM, atomic write, freshness/expiry validation
- ✅ Post-build directory validation with structured `ValidationIssue` results
- ✅ Diff mode (added / removed / renewed / unchanged)
- ✅ Source load report

### Source Loaders

- ✅ `igtf` — local directory, local tarball, HTTP URL; path-traversal protection
- ✅ `local` — single PEM, bundle file, directory (glob, optional recursive)
- ✅ `http` — download with retry/backoff; scheme validation (http/https only)

### CLI (`crab` / `crabctl`)

- ✅ `build [PROFILE…]` — `--dry-run`, `--report`, `--no-crls`
- ✅ `validate [TARGET…]` — `--no-hash-check`, `--no-openssl`, `--json`; exit codes 0/1/2
- ✅ `diff PROFILE` — `--json`
- ✅ `list [TARGET]` — `--source`, `--expired`, `--json`
- ✅ `fetch-crls [PROFILE…]` — `--dry-run`
- ✅ `show-config`
- ✅ `CRAB_CONFIG` environment variable

### Packaging and Operations

- ✅ pip-installable package (`setup.cfg`, `pyproject.toml`)
- ✅ Python 3.6.8 – 3.12 compatibility (Rocky 8/9, Ubuntu 22.04/24.04)
- ✅ `systemd` service + daily timer (04:00, 30-min jitter, `Persistent=true`)
- ✅ Dockerfile (Rocky Linux 8 base)
- ✅ Example configs: minimal, full, SRCNet
- ✅ `docs/ARCHITECTURE.md`
- ✅ `README.md`, `CHANGELOG.md`
- ✅ 183 tests, all passing (pytest)

---

## 🔲 0.2.0 — Packaging and Distribution

*Goal: make CRAB installable from standard package managers used in research
computing environments.*

- 🔲 Add `crab` as an alias entry point alongside `crabctl`
- 🔲 PyPI release (`crabctl` package name)
- 🔲 RPM spec file for Rocky/RHEL 8 and 9 (COPR or direct)
- 🔲 Debian/Ubuntu `.deb` package (for Ubuntu 22.04 LTS)
- 🔲 JSON Schema for `crab.yaml` config (machine-readable validation, editor
  auto-complete)
- 🔲 `crab --version` reports commit SHA when installed from source
- 🔲 Tox matrix extended to Python 3.13

---

## 🔲 0.3.0 — Operational Observability

*Goal: make CRAB suitable for unattended production operation with monitoring
hooks.*

- 🔲 Prometheus/OpenMetrics text-file exporter — cert counts, expiry days,
  CRL age, last-build timestamp; written to a configurable path after each build
- 🔲 Structured JSON logging mode (`--log-format json`) for integration with
  log aggregators (Loki, Splunk, ECS)
- 🔲 `crab status` command — machine-readable summary of current output
  directories (cert count, oldest/newest expiry, CRL freshness)
- 🔲 Exit code 3 — "build succeeded but warnings present" (currently merged
  into exit 0); opt-in via `--strict-warnings`
- 🔲 Nagios/Icinga-compatible `check_crab` wrapper script

---

## 🔲 0.4.0 — Trust Policy Enhancements

*Goal: cover the remaining trust-vetting rules used in WLCG and EGI production.*

- 🔲 Namespace validation — enforce IGTF `.namespaces` permitted-subject rules
  at validation time
- 🔲 OCSP staple check — optionally verify OCSP status for CA certificates
  with AIA OCSP URLs
- 🔲 Pinned-fingerprint enforcement — config option to hard-require a specific
  fingerprint for a named subject; alerts on replacement
- 🔲 Policy `warn:` rules (report without rejecting) in addition to existing
  `include:`/`exclude:`
- 🔲 `exclude_sources:` per profile (complement to `sources:`)

---

## 🔲 0.5.0 — CRAB-PKI: Self-Signed CA and Host Certificate Generation

*Goal: allow CRAB to bootstrap and operate a minimal internal or test PKI
suitable for research infrastructure nodes — data-transfer endpoints (XRootD,
dCache), internal grid services, and RI lab environments. This is intentionally
narrower than a general-purpose PKI tool (step-ca, cfssl, HashiCorp Vault PKI);
the target is "RI sysadmin who needs a working test CA in ten minutes, not a
CA policy document".*

**Why include this in CRAB?**  
CRAB already owns the trust-directory side of the equation. Closing the loop —
so operators can generate the CA they then distribute via CRAB — removes the
dependency on external tools for common RI bootstrapping workflows. It also
keeps the test suite self-contained (no more borrowing CA fixtures from
`cryptography` in conftest; use `crab ca init` instead).

**Scope of 0.5.0:**

- 🔲 `crab ca init [--name NAME] [--days N] [--out DIR]`
  — generates a self-signed root CA (RSA-4096 or Ed25519); writes
  `ca-cert.pem`, `ca-key.pem` (mode 0600) into `DIR`
- 🔲 `crab ca show [CA_DIR]`
  — pretty-print CA certificate details; JSON mode
- 🔲 `crab cert issue --ca CA_DIR --cn HOSTNAME [--san …] [--days N]`
  — issues a TLS server certificate signed by the local CA; writes
  `HOSTNAME-cert.pem` and `HOSTNAME-key.pem`
- 🔲 `crab cert revoke --ca CA_DIR CERT`
  — revokes a certificate and regenerates the local CRL
- 🔲 `crab cert list --ca CA_DIR`
  — list issued certificates and their status
- 🔲 Auto-add generated CA to a named CRAB profile's source list (`--add-to-profile`)
- 🔲 Serial number database (`serial.db`, JSON lines) for issued certificates
- 🔲 Key storage: PEM files only; no PKCS#11 or HSM in this milestone
- 🔲 Certificate profiles: `server`, `client`, `grid-host` (adds
  `gridFTP`/`XRootD` EKU OIDs used by some RI middleware)

**Out of scope for 0.5.0 (may revisit later):**

- Intermediate/subordinate CAs
- ACME protocol support
- Web UI or REST API
- PKCS#11 / HSM key storage
- CMP or EST enrollment protocols

---

## 🔲 Future / Under Consideration

- HTTP source: `If-Modified-Since` conditional GET to reduce bandwidth on
  scheduled refreshes
- `crab diff --ci` mode: exits non-zero and prints a compact summary for use
  in CI pipelines that gate on trust-anchor drift
- Multi-arch container image (amd64, arm64) published to a registry
- Ansible role for deploying CRAB + systemd timer
- Integration tests against a live IGTF mirror (opt-in, marked `@pytest.mark.network`)
- Windows support (for hybrid RI environments running dCache on Windows nodes)

---

*This roadmap reflects current priorities and is subject to change based on
community feedback. Contributions welcome — see `CONTRIBUTING.md` (planned for
0.2.0).*
