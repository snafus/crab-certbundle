# CRAB Roadmap

**Certificate Root Anchor Builder** — planned milestones and status.

Items marked ✅ are shipped. Items marked 🔲 are planned.

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
- ✅ `system` — OS trust store auto-detection (EL, Debian/Ubuntu, Alpine, macOS)

### Output Formats

- ✅ `capath` — OpenSSL-compatible hashed directory
- ✅ `bundle` — concatenated PEM file with optional annotations
- ✅ `pkcs12` — PKCS#12 `.p12` file with optional password encryption

### CLI (`crabctl`)

- ✅ `build [PROFILE…]` — `--dry-run`, `--report`, `--no-crls`
- ✅ `validate [TARGET…]` — `--no-hash-check`, `--no-openssl`; exit codes 0/1/2
- ✅ `diff PROFILE`
- ✅ `list [TARGET]` — `--source`, `--expired`
- ✅ `fetch-crls [PROFILE…]` — `--dry-run`
- ✅ `show-config`
- ✅ `CRAB_CONFIG` environment variable
- ✅ `${VAR}` / `${VAR:-default}` env-var interpolation in config string values

### Packaging and Operations

- ✅ pip-installable package (`crabctl`); Python module `crab`
- ✅ Python 3.6.8 – 3.12 compatibility (Rocky 8/9, Ubuntu 22.04/24.04)
- ✅ `systemd` service + daily timer (04:00, 30-min jitter, `Persistent=true`)
- ✅ Dockerfile (Rocky Linux 8 base)
- ✅ RPM spec (`crab-certbundle`) for EL8 and EL9
- ✅ Example configs: minimal, full, SRCNet
- ✅ `docs/ARCHITECTURE.md`
- ✅ `README.md`, `CHANGELOG.md`

---

## ✅ 0.2.0 — Hardening and CRAB-PKI (2026-04-12)

### Bug fixes

- ✅ `file_mode`/`dir_mode` string parsing — accepts bare integers and
  `"0o644"`-style octal strings
- ✅ `diff` exit code inconsistency — JSON mode now exits 1 when changes
  are present, matching text mode
- ✅ Silent parse errors in `_load_certs_from_directory` — replaced
  `except Exception: pass` with `logger.warning(...)`
- ✅ `description:` key silently ignored in profiles — read, stored, and
  displayed in `show-config` output

### Architecture

- ✅ Move `build_source` and source registry to `crab/sources/__init__.py`
- ✅ Ternary `PolicyOutcome` (ACCEPT / WARN / REJECT) — replaces `accepted: bool`;
  `accepted` is now a property; no call-site changes required
- ✅ Integrate `CRLManager.validate_crls` into the validation pipeline —
  `crabctl validate` reports stale/missing CRLs for profiles with `include_crls: true`

### CRAB-PKI — test CA and certificate generation

- ✅ `crabctl ca init [CA_DIR]` — self-signed root CA; RSA-2048/4096,
  ECDSA P-256/P-384, or Ed25519; key written mode 0600
- ✅ `crabctl ca show [CA_DIR]`
- ✅ `crabctl cert issue --ca CA_DIR --cn NAME [--san …] [--profile PROFILE]
  [--key-type TYPE] [--days N] [--cdp-url URL]`
- ✅ `crabctl cert revoke --ca CA_DIR CERT [--reason REASON]` — updates serial
  DB and regenerates CRL atomically
- ✅ `crabctl cert list --ca CA_DIR [--revoked]`
- ✅ Certificate profiles: `server`, `client`, `grid-host`
- ✅ `keyEncipherment` correctly absent from ECDSA and Ed25519 certs
- ✅ P-384 CA signs with SHA-384; P-256 and RSA CAs sign with SHA-256
- ✅ Serial database (`serial.db`, JSON-lines, `fcntl`-locked)
- ✅ `--add-to-profile` prints the `crab.yaml` snippet for source registration

### Config and tooling

- ✅ JSON Schema for `crab.yaml` (editor autocompletion via `yaml-language-server`)
- ✅ Debian/Ubuntu `.deb` package (Ubuntu 22.04 LTS and 24.04 LTS)
- ✅ `crabctl --version` reports commit SHA when installed from source
- ✅ Tox matrix extended to Python 3.12 and 3.13
- ✅ `CONTRIBUTING.md`

---

## ✅ 0.3.0 — Operational Observability and PKI Enhancements (2026-04-17)

### Observability

- ✅ Structured JSON logging — `--log-format json` global flag and
  `logging.format: json` config key; one JSON object per line
- ✅ `crabctl status` — cert count, expired/expiring-soon, earliest expiry,
  CRL freshness, last-built time; exits 1 when degraded
- ✅ Exit code 3 — `--strict-warnings` on `build` and `refresh`; exits 3 on
  policy WARN outcomes or CRL fetch failures
- ✅ Parallel CRL fetching — `ThreadPoolExecutor`-backed; configurable
  `crl.max_workers` (default 8)
- ✅ `--output-format text|json` — global flag replacing per-command `--json`;
  applies to all commands uniformly

### Policy

- ✅ `warn:` rules in policy — certs matching warn rules pass through but
  are flagged WARN and counted toward `--strict-warnings` exit code 3
- ✅ Policy evaluation order documented: non-CA → expired → include →
  exclude → warn → default ACCEPT

### CRL cache-control

- ✅ `min_remaining_hours` — warn if a CRL's nextUpdate is imminent (default 4h)
- ✅ `refetch_before_expiry_hours` — skip re-fetch if a CRL still has sufficient
  life remaining (default 0; set to e.g. 12 for weekly-CRL CAs)
- ✅ `CRLUpdateResult.skipped` — count of CRLs skipped as still-fresh

### CRAB-PKI enhancements

- ✅ `crabctl ca intermediate [CA_DIR] --parent PARENT` — intermediate CA signed
  by a parent; validates parent BasicConstraints; supports N-level hierarchies
- ✅ `ca-chain.pem` — written to intermediate CA directories; contains this CA's
  certificate plus all ancestor intermediates (root excluded)
- ✅ `{cn}-fullchain.pem` — written alongside leaf certs issued by an intermediate
  CA; contains leaf + intermediates, root excluded (Let's Encrypt convention)
- ✅ `--path-length` on `ca intermediate` — constrains depth below this CA

### Docker Compose PKI support

- ✅ `scripts/compose-pki.sh` — generic shell script for managing a CRAB PKI
  hierarchy for Compose services; `init`, `issue`, `revoke`, `status`, `clean`
- ✅ `docker/Dockerfile.pki` — init-container image extending the production
  image; all `CRAB_*` vars configurable at runtime
- ✅ `examples/docker-compose.pki.yml` — Compose overlay demonstrating the
  init-container pattern with `condition: service_completed_successfully`

---

## 🔲 0.4.0 — Trust Policy Enhancements

*Goal: cover remaining trust-vetting rules used in WLCG and EGI production.*

- 🔲 **Namespace validation** — enforce IGTF `.namespaces` permitted-subject
  rules at validation time; report violations as `ValidationIssue` entries
- 🔲 **Pinned-fingerprint enforcement** — config option to hard-require a
  specific fingerprint for a named subject; alerts on replacement (cert swap
  without fingerprint update fails the build or emits WARN)
- 🔲 **`exclude_sources:` per profile** — complement to `sources:`; needs a
  design note on semantics when the same cert appears in both an included and
  excluded source (per-source exclusion vs. per-cert-after-merge)
- 🔲 **OCSP staple check** — optionally verify OCSP status for CA certificates
  with AIA OCSP URLs; `cryptography` provides OCSP request building but not a
  full client — evaluate dependency surface before implementing

---

## 🔲 Future / Under Consideration

| Item | Notes |
|---|---|
| **Prometheus/OpenMetrics exporter** | Text-file exporter written after each build: cert counts, expiry days, CRL age, last-build timestamp; no extra runtime dependency |
| **`check_crab` Nagios/Icinga wrapper** | Thin shell script over `crabctl --output-format json status`; exit codes compatible with Nagios plugin API |
| **PyPI release** | Deferred until API surface is stable and package name confirmed |
| **Output format registry** | Replace hardcoded `if output_format ==` chain in `output.py` with a dict dispatcher; enables external packages to contribute output formats |
| **Source plugin system** | Entry-point-based registration so external packages can contribute source types (builds on `sources/__init__.py` registry) |
| **`crab diff --ci` mode** | Non-zero exit + compact one-line summary for CI pipelines gating on trust-anchor drift |
| **Multi-arch container image** | amd64 + arm64, published to a registry |
| **Ansible role** | Deploy CRAB + systemd timer |
| **Integration tests against live IGTF mirror** | Opt-in, `@pytest.mark.network` |
| **CRL parsing via `cryptography`** | Replace `openssl crl -text` subprocess + regex with native `load_der_x509_crl` / `load_pem_x509_crl` |
| **Config schema versioning** | Formal backwards-compat guarantee and upgrade path when `version:` increments |
| **Windows support** | For hybrid RI environments running dCache on Windows nodes |

---

*This roadmap reflects current priorities and is subject to change based on
community feedback. Contributions welcome — see `CONTRIBUTING.md`.*
