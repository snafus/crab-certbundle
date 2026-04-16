# CRAB Roadmap

**Certificate Root Anchor Builder** — planned milestones and status.

Items marked ✅ are shipped. Items marked 🔲 are planned. Items marked ⚠️ are
known defects that must be fixed before the next milestone completes.

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
- ✅ `validate [TARGET…]` — `--no-hash-check`, `--no-openssl`, `--json`; exit codes 0/1/2
- ✅ `diff PROFILE` — `--json`
- ✅ `list [TARGET]` — `--source`, `--expired`, `--json`
- ✅ `fetch-crls [PROFILE…]` — `--dry-run`
- ✅ `show-config`
- ✅ `CRAB_CONFIG` environment variable
- ✅ `${VAR}` / `${VAR:-default}` env-var interpolation in config string values

### Packaging and Operations

- ✅ pip-installable package (`crabctl` on PyPI); Python module `crab`
- ✅ Python 3.6.8 – 3.12 compatibility (Rocky 8/9, Ubuntu 22.04/24.04)
- ✅ `systemd` service + daily timer (04:00, 30-min jitter, `Persistent=true`)
- ✅ Dockerfile (Rocky Linux 8 base)
- ✅ RPM spec (`crab-certbundle`) for EL8 and EL9
- ✅ Example configs: minimal, full, SRCNet
- ✅ `docs/ARCHITECTURE.md`
- ✅ `README.md`, `CHANGELOG.md`
- ✅ 508 tests (501 unit + 7 integration), all passing

---

## 🔲 0.2.0 — Pre-release Hardening and Distribution

*Goal: close known defects, tighten the public API surface, add CRAB-PKI for
test certificate generation, and publish to PyPI.  Changes after this point
must be backwards-compatible or version-bumped.*

### Bug fixes

- ✅ **`file_mode`/`dir_mode` string parsing** — `ProfileConfig` now accepts
  both bare integers and `"0o644"`-style octal strings via `int(v, 0)`.
- ✅ **`diff` exit code inconsistency** — JSON mode now exits 1 when changes
  are present, matching text mode.
- ✅ **Silent parse errors in `_load_certs_from_directory`** — replaced
  `except Exception: pass` with `logger.warning(...)`.
- ✅ **`description:` key silently ignored in profiles** — read, stored, and
  displayed in `show-config` output.

### Architecture

- ✅ **Move `build_source` and source registry to `crab/sources/__init__.py`**
  — `SOURCE_REGISTRY` dict is the single authoritative mapping; `config.py`
  retains a thin re-export wrapper for backwards compatibility.
- ✅ **Ternary `PolicyOutcome` (ACCEPT / WARN / REJECT)** — replaces the
  `accepted: bool` field; `accepted` is now a property returning
  `outcome != REJECT`; no call-site changes required.
- ✅ **Integrate `CRLManager.validate_crls` into the validation pipeline** —
  `crabctl validate` now reports stale/missing CRLs for profiles with
  `include_crls: true`.

### CRAB-PKI — test CA and certificate generation

*Allows operators to bootstrap a minimal internal PKI for lab and CI
environments without external tooling.  Intentionally narrower than
step-ca/cfssl; the target is "working test CA in ten minutes".*

- ✅ `crabctl ca init [CA_DIR]` — self-signed root CA; RSA-2048/4096,
  ECDSA P-256/P-384, or Ed25519; key written mode 0600
- ✅ `crabctl ca show [CA_DIR] [--json]`
- ✅ `crabctl cert issue --ca CA_DIR --cn NAME [--san …] [--profile PROFILE]
  [--key-type TYPE] [--days N] [--cdp-url URL]`
- ✅ `crabctl cert revoke --ca CA_DIR CERT [--reason REASON]` — updates serial
  DB and regenerates CRL atomically
- ✅ `crabctl cert list --ca CA_DIR [--json] [--revoked]`
- ✅ Certificate profiles: `server` (serverAuth), `client` (clientAuth),
  `grid-host` (serverAuth + clientAuth for XRootD/dCache/gfal2)
- ✅ `keyEncipherment` correctly absent from ECDSA and Ed25519 certs
- ✅ P-384 CA signs with SHA-384; P-256 and RSA CAs sign with SHA-256
- ✅ Serial database (`serial.db`, JSON-lines, `fcntl`-locked)
- ✅ `--add-to-profile` prints the `crab.yaml` snippet for source registration
- ✅ 78 unit tests + 14 integration tests (including full CA→build→validate
  round-trip via `openssl verify -CApath`)

### Config and tooling

- ✅ JSON Schema for `crab.yaml` (editor autocompletion via
  `yaml-language-server`)

### Packaging and distribution (remaining)

- ✅ Debian/Ubuntu `.deb` package (Ubuntu 22.04 LTS and 24.04 LTS)
- ✅ `crabctl --version` reports commit SHA when installed from source
- ✅ Tox matrix extended to Python 3.12 and 3.13
- ✅ `CONTRIBUTING.md`

---

## 🔲 0.3.0 — Operational Observability

*Goal: make CRAB suitable for unattended production operation with monitoring
hooks.*

> **Prerequisite:** `CRLManager.validate_crls` must be integrated into the
> pipeline (0.2.0) before `crabctl status` can report CRL freshness, and
> `PolicyOutcome` must be ternary before exit code 3 is meaningful.

- ✅ **Structured JSON logging** — `--log-format json` global flag and
  `logging.format: json` config key; `JsonFormatter` emits one JSON object
  per line (timestamp, level, logger, message, exception).
- ✅ **`crabctl status`** — machine-readable health summary: cert count,
  expired/expiring-soon, earliest expiry, CRL count and freshness,
  last-built time; `--json` for machine consumption; exits 1 when degraded.
- ✅ **Exit code 3** — `--strict-warnings` on `build` and `refresh`; exits 3
  when build succeeds but policy WARN outcomes or CRL fetch failures are
  present.
- ✅ **Parallel CRL fetching** — `ThreadPoolExecutor`-backed fetch loop in
  `CRLManager.update_crls`; configurable `crl.max_workers` (default 8);
  persistent `requests.Session` shared across workers for connection reuse.

---

## 🔲 0.4.0 — Trust Policy Enhancements

*Goal: cover the remaining trust-vetting rules used in WLCG and EGI production.*

- 🔲 **Policy `warn:` rules** — report without rejecting; surfaces via exit
  code 3 and Prometheus `crab_policy_warnings_total` counter (requires
  `PolicyOutcome` from 0.2.0)
- 🔲 Namespace validation — enforce IGTF `.namespaces` permitted-subject rules
  at validation time
- 🔲 Pinned-fingerprint enforcement — config option to hard-require a specific
  fingerprint for a named subject; alerts on replacement
- 🔲 OCSP staple check — optionally verify OCSP status for CA certificates
  with AIA OCSP URLs; evaluate dependency surface (`cryptography` provides
  OCSP request building but not a full client)
- 🔲 **`exclude_sources:` per profile** — complement to `sources:`; note: must
  define precise semantics for the case where the same cert appears in both an
  included and an excluded source (per-source vs. per-cert-after-merge); needs
  a design note before implementation

---

## ⚠️ 0.5.0 — CRAB-PKI: Self-Signed CA and Host Certificate Generation

*Goal: allow CRAB to bootstrap and operate a minimal internal or test PKI
suitable for research infrastructure nodes — data-transfer endpoints (XRootD,
dCache), internal grid services, and RI lab environments. This is intentionally
narrower than a general-purpose PKI tool (step-ca, cfssl, HashiCorp Vault PKI);
the target is "RI sysadmin who needs a working test CA in ten minutes, not a
CA policy document".*

**Why include this in CRAB?**
CRAB already owns the trust-directory side of the equation. Closing the loop —
so operators can generate the CA they then distribute via CRAB — removes the
dependency on external tools for common RI bootstrapping workflows.

**Prerequisites from earlier milestones:**
- `_write_file` must support per-file mode overrides so key files can be
  written 0600 regardless of profile `file_mode` (add in 0.2.0 or 0.5.0 prep).
- Serial number database (`serial.db`, JSON lines) introduces mutable on-disk
  state outside the output directory — needs explicit design for locking and
  atomic writes before implementation begins.

**Scope of 0.5.0:**

- ✅ `crabctl ca init [CA_DIR] [--name NAME] [--org ORG] [--days N] [--key-type TYPE] [--force]`
  — generates a self-signed root CA (RSA-2048/4096 or Ed25519); writes
  `ca-cert.pem`, `ca-key.pem` (mode 0600) into `CA_DIR`
- ✅ `crabctl ca show [CA_DIR] [--json]` — pretty-print CA certificate details; JSON mode
- ✅ `crabctl cert issue --ca CA_DIR --cn HOSTNAME [--san …] [--days N] [--profile PROFILE] [--cdp-url URL]`
  — issues a TLS server certificate signed by the local CA; writes
  `HOSTNAME-cert.pem` and `HOSTNAME-key.pem` (mode 0600)
- ✅ `crabctl cert revoke --ca CA_DIR CERT [--reason REASON]`
  — revokes a certificate and regenerates the local CRL
- ✅ `crabctl cert list --ca CA_DIR [--json] [--revoked]` — list issued certificates and their status
- ✅ `--add-to-profile PROFILE` on `ca init` — prints the crab.yaml snippet
  to register the CA as a local source in the named profile
- ✅ Serial number database (`serial.db`, JSON lines) for issued certificates;
  `fcntl.flock` for process-safety on Linux/macOS
- ✅ Key storage: PEM (PKCS#8 format, supports RSA and Ed25519); no PKCS#11 or HSM
- ✅ Certificate profiles: `server` (serverAuth), `client` (clientAuth),
  `grid-host` (serverAuth + clientAuth for XRootD/dCache/gfal2)
- ✅ CRL Distribution Point URL embeddable per cert (`--cdp-url`)

**Out of scope for 0.5.0 (may revisit later):**

- Intermediate/subordinate CAs
- ACME protocol support
- Web UI or REST API
- PKCS#11 / HSM key storage
- CMP or EST enrollment protocols

---

## 🔲 Future / Under Consideration

- Prometheus/OpenMetrics text-file exporter — cert counts, expiry days,
  CRL age, last-build timestamp; written to a configurable path after each build
- Nagios/Icinga-compatible `check_crab` wrapper script
- PyPI release (`crabctl` package name) — deferred from 0.2.0; publish
  once the public API surface is stable and the package name is confirmed
- Output format registry — replace the hardcoded `if output_format ==` chain in
  `output.py` with a dict-based dispatcher; enables external packages to
  contribute output formats without modifying core
- Source plugin system — entry-point-based registration so external packages
  can contribute source types (builds on the `sources/__init__.py` registry
  introduced in 0.2.0)
- `crab diff --ci` mode — exits non-zero and prints a compact summary for use
  in CI pipelines that gate on trust-anchor drift
- Multi-arch container image (amd64, arm64) published to a registry
- Ansible role for deploying CRAB + systemd timer
- Integration tests against a live IGTF mirror (opt-in, `@pytest.mark.network`)
- CRL parsing via `cryptography` library — replace the fragile
  `openssl crl -text` subprocess + regex in `crl.py` with native
  `x509.load_der_x509_crl` / `load_pem_x509_crl`
- Config schema versioning and migration policy — formal statement of
  backwards-compatibility guarantees and upgrade path when `version:` increments
- Windows support (for hybrid RI environments running dCache on Windows nodes)

---

*This roadmap reflects current priorities and is subject to change based on
community feedback. Contributions welcome — see `CONTRIBUTING.md` (planned for
0.2.0).*
