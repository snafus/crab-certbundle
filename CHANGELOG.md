# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Nothing yet.

---

## [0.1.0] — 2026-04-12

Initial public release.

### Added

**Core pipeline**
- `certbundle.cert` — `CertificateInfo` data model with full X.509 attribute
  extraction (subject, issuer, fingerprints, key usage, EKU, CDP, AIA,
  BasicConstraints, validity); bundle parsing via PEM regex unwrapping.
- `certbundle.rehash` — OpenSSL subject-hash computation with three-tier
  fallback: pyOpenSSL (C library, guaranteed correct) → subprocess
  `openssl x509 -hash` → pure-Python SHA-1 / DER-walk fallback; shared
  `CERT_HASH_FILE_RE` / `CRL_HASH_FILE_RE` regex constants.
- `certbundle.policy` — `PolicyEngine` with structural (CA flag, pathLen),
  validity, EKU, include/exclude rule support; per-rule AND semantics,
  across-rules OR semantics; INFO-level rejection summary.
- `certbundle.output` — `OutputProfile`, `build_output` with atomic staging
  + rename; IGTF metadata passthrough; configurable file/dir permissions;
  symlink-target safety guard.
- `certbundle.crl` — `CRLManager` with CDP + IGTF `.info` URL discovery;
  DER→PEM conversion; atomic temp-file write; issuer-hash format validation;
  freshness and expiry checks.
- `certbundle.validation` — `validate_directory`; hash filename consistency
  check; expired cert warnings; optional `openssl verify` smoke test.
- `certbundle.reporting` — `diff_cert_sets`; `render_diff_text` /
  `render_diff_json`; `render_inventory` (text + JSON); source load report.
- `certbundle.config` — YAML config loading and validation; source factory;
  `ConfigError` with actionable messages.

**Source loaders**
- `certbundle.sources.igtf` — local directory, local tarball, HTTP URL;
  `.info` / `.signing_policy` / `.namespaces` / `.crl_url` passthrough;
  IGTF policy-tag filtering; tarball path-traversal protection.
- `certbundle.sources.local` — single PEM file, bundle file, directory with
  glob patterns; optional recursive walk.
- `certbundle.sources.http` — HTTP/HTTPS download with retry and backoff;
  scheme validation (rejects `file://`, `ftp://`, etc.); size cap.

**CLI** (`crabctl` entry point)
- `build [PROFILE...]` — build profiles; `--dry-run`, `--report`, `--no-crls`
- `validate [TARGET...]` — validate CApath dirs; `--no-hash-check`,
  `--no-openssl`, `--json`; exit codes 0/1/2
- `diff PROFILE` — in-memory diff before committing a build; `--json`
- `list [TARGET]` — inventory by profile, source, or raw directory;
  `--source`, `--expired`, `--json`
- `fetch-crls [PROFILE...]` — refresh CRLs; `--dry-run`
- `show-config` — dump resolved config (useful for debugging)

**Packaging and operations**
- `setup.cfg` + `setup.py` + `pyproject.toml` for pip-installable package
- `tox.ini` targeting Python 3.6–3.11
- `Dockerfile` (Rocky Linux 8 base for EL-compatible testing)
- `systemd/certbundle.service` + `certbundle.timer` (daily 04:00, 30 min jitter)
- Example configs: `config-full.yaml`, `config-minimal.yaml`, `config-srcnet.yaml`
- `docs/ARCHITECTURE.md` covering pipeline, hash strategy, atomic swap,
  policy model, IGTF integration, Python 3.6 compatibility, security notes

**Tests** — 160+ tests across 8 test modules
- `test_cert` — PEM parsing, model attributes, edge cases
- `test_config` — YAML loading, validation, error paths
- `test_crl` — CRLInfo, CRLManager dry-run, security (hash injection, TLS),
  URL source logic, date parsing
- `test_cli` — full CLI via Click test runner; all commands; JSON output;
  dry-run; exit codes; env var config
- `test_output` — directory building, deduplication, atomic swap,
  permissions
- `test_policy` — accept/reject paths; include/exclude rules; EKU; IGTF
  policy tag; filter list
- `test_rehash` — hash computation, caching, collision handling, DER walk
- `test_reporting` — diff computation, text/JSON rendering, inventory
- `test_sources` — IGTF dir/tarball, local dir/file/bundle, info parsing
- `test_validation` — directory health checks, expired cert warnings

### Security

- HTTP downloads restricted to `http://` and `https://` schemes only;
  `file://`, `ftp://`, `gopher://`, etc. are rejected.
- Tarball extraction uses `os.path.basename()` to prevent path-traversal
  attacks from malicious archive member names.
- Atomic swap (`_atomic_swap`) rejects symlinks as `output_dir` to prevent
  TOCTOU replacement of unintended targets.
- CRL issuer hashes validated against `[0-9a-f]{8}` before use in filesystem
  paths.
- CRL files written via `tempfile.mkstemp()` + `os.replace()` rather than
  open-by-name, preventing TOCTOU races on the temp file.
- `verify_tls: false` emits a WARNING log to discourage unintended use.

### Compatibility

- Python 3.6.8+ (Rocky Linux 8 / EL8 system Python)
- Python 3.9 (Rocky Linux 9 / EL9 system Python)
- Python 3.10+ (Ubuntu 22.04 / 24.04)
- `cryptography >= 2.8` (EL8 ships ≥ 3.x)
- No dependency on `dataclasses`, walrus operator, `tomllib`, or any 3.7+
  stdlib feature

---

[Unreleased]: https://github.com/snafus/crab-certbundle/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/snafus/crab-certbundle/releases/tag/v0.1.0
