# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.3.0] — 2026-04-16

### Added

- **`crabctl status`** — new command that reads profile output directories
  without network access and reports: cert count, expired/expiring-soon
  counts, earliest expiry (with subject), CRL file count, CRL freshness
  warnings (via `CRLManager.validate_crls`), and last-built time (directory
  mtime). `--json` flag emits a machine-readable list. Exits 0 when all
  profiles are healthy, 1 when any are degraded or missing.
- **`--log-format json`** — new global CLI flag (and `logging.format: json`
  config key) enabling structured JSON logging. Each log record is emitted as
  a single-line JSON object with fields `timestamp` (ISO-8601 UTC with ms),
  `level`, `logger`, `message`, and `exception` (when present). CLI flag
  takes priority over config; the `text` format is unchanged. Invalid format
  values are rejected by config validation.
- **`--strict-warnings`** on `build` and `refresh` — exits 3 when the build
  succeeds but policy `WARN` outcomes or CRL fetch failures are present.
  Errors still exit 1 (takes priority). Exit code 3 is the hook for future
  `warn:` policy rules (0.4.0) and Prometheus alerting.
- **Parallel CRL fetching** — `CRLManager.update_crls` now uses a
  `ThreadPoolExecutor` (configurable `crl.max_workers`, default 8) with a
  shared `requests.Session` for connection pooling. A `threading.Lock`
  guards result accumulation. Dry-run path remains serial.
- `PolicyEngine.count_warnings(cert_infos)` — counts certs that would
  receive a `WARN` outcome without modifying filter results; used by
  `--strict-warnings`.
- `crab/logfmt.py` — `JsonFormatter` and `make_formatter(fmt, with_time)`
  factory extracted as a standalone module.
- `crab/status.py` — `ProfileStatus`, `collect_status()`,
  `render_status_text()` extracted as a standalone module.
- `runner` and `cli_env` pytest fixtures promoted to root `conftest.py`
  (previously only in `test_cli.py`).
- Integration tests for CRL fetching (`TestFetchCRLsIntegration`, 6 tests):
  dry-run, live fetch, PEM format verification, parallel (4 CAs), missing
  CDP URL, server-down soft failure.

### Changed

- `_build_profile` now returns `(errors, warned)` tuple instead of a bare
  `int`; callers (`build`, `refresh`) updated accordingly.
- `crl.max_workers` added to JSON Schema `crl_config` definition.
- `logging.format` added to JSON Schema `logging_config` definition.
- ROADMAP: `crab status` corrected to `crabctl status` throughout; Prometheus
  and Nagios items moved to Future section.

---

## [0.1.0] — 2026-04-13

Initial public release.

### Added

**Core pipeline**
- `crab.cert` — `CertificateInfo` data model with full X.509 attribute
  extraction (subject, issuer, fingerprints, key usage, EKU, CDP, AIA,
  BasicConstraints, validity); bundle parsing via PEM regex unwrapping.
- `crab.rehash` — OpenSSL subject-hash computation with three-tier
  fallback: pyOpenSSL (C library, guaranteed correct) → subprocess
  `openssl x509 -hash` → pure-Python SHA-1 / DER-walk fallback; shared
  `CERT_HASH_FILE_RE` / `CRL_HASH_FILE_RE` regex constants.
- `crab.policy` — `PolicyEngine` with structural (CA flag, pathLen),
  validity, EKU, include/exclude rule support; per-rule AND semantics,
  across-rules OR semantics; INFO-level rejection summary.
- `crab.output` — `OutputProfile`, `build_output` with atomic staging
  + rename; IGTF metadata passthrough; configurable file/dir permissions;
  symlink-target safety guard.
- `crab.crl` — `CRLManager` with CDP + IGTF `.info` URL discovery;
  DER→PEM conversion; atomic temp-file write; issuer-hash format validation;
  freshness and expiry checks.
- `crab.validation` — `validate_directory`; hash filename consistency
  check; expired cert warnings; optional `openssl verify` smoke test.
- `crab.reporting` — `diff_cert_sets`; `render_diff_text` /
  `render_diff_json`; `render_inventory` (text + JSON); source load report.
- `crab.config` — YAML config loading and validation; source factory;
  `ConfigError` with actionable messages.

**Source loaders**
- `crab.sources.igtf` — local directory, local tarball, HTTP URL;
  `.info` / `.signing_policy` / `.namespaces` / `.crl_url` passthrough;
  IGTF policy-tag filtering; tarball path-traversal protection.
- `crab.sources.local` — single PEM file, bundle file, directory with
  glob patterns; optional recursive walk.
- `crab.sources.http` — HTTP/HTTPS download with retry and backoff;
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
- `systemd/crab.service` + `crab.timer` (daily 04:00, 30 min jitter)
- Example configs: `config-full.yaml`, `config-minimal.yaml`, `config-srcnet.yaml`
- `docs/ARCHITECTURE.md` covering pipeline, hash strategy, atomic swap,
  policy model, IGTF integration, Python 3.6 compatibility, security notes

**Tests** — 312 tests across 11 test modules; 88 % line coverage
- `test_cert` — PEM parsing, model attributes, EKU predicates, equality
- `test_cli` — full CLI via Click test runner; all commands; JSON output;
  dry-run; exit codes; env var config; source error handling
- `test_config` — YAML loading, validation, error paths
- `test_crl` — CRLInfo, CRLManager dry-run, security (hash injection, TLS),
  `.r0` overwrite regression, URL source logic, date parsing
- `test_http` — URL scheme validation, download retry/backoff, size limits
- `test_igtf` — directory, tarball, and HTTP URL loading; `.info` / extra-file
  passthrough; policy filtering; path-traversal protection; unreadable-file
  handling
- `test_output` — directory building, deduplication, atomic swap, permissions
- `test_policy` — accept/reject paths; include/exclude rules; EKU; IGTF
  policy tag; reject_not_yet_valid; reject_path_len_zero; filter list
- `test_rehash` — hash computation, caching, collision handling, DER walk;
  pure-Python fallback; multi-byte DER length encodings; `rehash_directory`
  external tool fallback; pyOpenSSL strategy paths
- `test_reporting` — diff computation, text/JSON rendering, inventory
- `test_sources` — IGTF dir/tarball, local dir/file/bundle, info parsing
- `test_validation` — directory health checks; hash-filename mismatch; expired
  cert warnings; multi-cert file; unrecognised files; openssl graceful skip

### Fixed

- `CRLManager._write_crl` accumulated stale `.rN` files when a separate
  `crl_path` was configured; now always writes to `.r0` via `os.replace()`.
- `crabctl validate --json` accepted the flag but always printed plain text;
  JSON accumulation and output are now correctly conditional on the flag.
- `OutputProfile` `file_mode` / `dir_mode` string-parsing branch used
  `int("0o644", 8)` which raises `ValueError`; simplified to `int(value)`.
- `ValidationIssue` used a bare `assert` for level validation, silently
  bypassed under `python -O`; replaced with explicit `raise ValueError`.
- `systemd/crab.service` `ExecStart` path was `/usr/local/bin/crabctl`
  but the RPM installs to `/usr/bin/crabctl`.
- RPM spec: EL8 system pip (9.0.3) does not support `--prefer-binary`; added
  pip self-upgrade step in `%install` before vendoring.
- RPM spec: `%{_unitdir}` undefined on EL9 without `systemd-rpm-macros`;
  added `BuildRequires: systemd-rpm-macros` and fallback `%global`.

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

[Unreleased]: https://github.com/snafus/crab-crab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/snafus/crab-crab/releases/tag/v0.1.0
