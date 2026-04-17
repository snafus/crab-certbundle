# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.4.0] — 2026-04-17

### Added

- **`crabctl cert renew`** — revoke-and-reissue workflow that reads all
  parameters (CN, SANs, profile, CDP URL, validity period) from the existing
  certificate and issues a replacement in-place.  `--days` overrides the
  validity period; `--reuse-key` skips key rotation; `--force` bypasses the
  "still valid" confirmation prompt.  Writes to the same filenames so consuming
  configurations need only a service reload.
- **`crabctl cert sign --csr`** — CSR-based issuance where the private key
  never enters CRAB.  Reads a PEM PKCS#10 CSR, verifies the self-signature,
  merges any `--san` additions, and issues a certificate using CA policy.
  No key file is written.  `--cn` overrides the CSR subject CN when absent
  or when the operator needs a canonical name.

### Fixed

- **`renew_cert` revoke-before-issue ordering** (high) — previous code called
  `revoke_cert()` before `_issue_cert_with_key()`.  A disk-full, permission, or
  any other I/O error during issuance left the old certificate permanently
  revoked with no replacement; any retry then hit "Certificate is already
  revoked".  Fixed: the new cert is issued first; the old serial is marked
  revoked (by fingerprint, inline) only after the new cert file is safely
  written.
- **`cert_renew` CLI naive/aware datetime mismatch** (forward-compat) —
  `cryptography >= 42` returns a timezone-aware UTC datetime from
  `cert.not_valid_after`; `datetime.utcnow()` always returns naive.  Mixing
  the two raises `TypeError` on any Python + cryptography >= 42 combination.
  Fixed: `not_valid_after` is normalised to naive UTC by stripping `tzinfo`
  when present before any arithmetic or comparison.
- **`crabctl validate` crashes with `NotADirectoryError` on bundle/pkcs12
  output paths** — three related problems: (1) profiles with `include_crls:
  true` and a non-directory `output_path` caused `_load_certs_from_directory`
  to be called on a file, crashing; (2) running validate with no arguments
  silently attempted to validate bundle files as CApath dirs; (3) passing a
  `.pem` file explicitly gave the unhelpful "not a known profile or directory"
  message.  All three fixed; bundle/pkcs12 profiles are now skipped with an
  explanatory message.  Use `crabctl list` to inspect bundle files.

---

## [0.3.0] — 2026-04-17

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
- **`warn:` rules in policy** — a new `warn:` list in the policy config
  accepts the same rule syntax as `include:` / `exclude:`.  Matching certs
  pass through to the output directory but are counted as WARN outcomes and
  trigger exit code 3 when `--strict-warnings` is active.  Evaluation order:
  non-CA → expired → include → exclude → warn → default ACCEPT.
- **CRL cache-control** — two new `crl:` config keys:
  `min_remaining_hours` (warn when a cached CRL's nextUpdate is imminent,
  default 4 h) and `refetch_before_expiry_hours` (skip re-fetch when a CRL
  still has sufficient life remaining, default 0 — set to e.g. 12 for
  weekly-CRL CAs).  `CRLUpdateResult` gains a `skipped` counter.
- **`crabctl ca intermediate`** — issue an intermediate CA signed by a
  parent CA; validates parent BasicConstraints (`cA: true`, non-zero
  pathLenConstraint); supports N-level hierarchies.  `--path-length` caps
  the depth below this CA.  Writes `ca-chain.pem` (this CA + ancestor
  intermediates, root excluded) alongside the new CA cert.
- **`{cn}-fullchain.pem`** — written automatically alongside leaf certs
  issued by an intermediate CA; contains leaf + all intermediate certs,
  root excluded (follows the Let's Encrypt / TLS convention expected by
  most TLS stacks).
- **Docker Compose PKI support**:
  - `scripts/compose-pki.sh` — generic shell script (`init`, `issue`,
    `revoke`, `status`, `clean`) that drives `crabctl` commands using
    `CRAB_*` environment variables; service-specific extra SANs via
    `CRAB_SAN_<SERVICE>` indirect expansion.
  - `docker/Dockerfile.pki` — init-container image extending the production
    image; all `CRAB_*` vars configurable at runtime via Docker env; runs
    `compose-pki.sh init` by default then exits.
  - `examples/docker-compose.pki.yml` — Compose overlay demonstrating the
    init-container pattern (`restart: "no"`, `condition:
    service_completed_successfully`) with a shared `pki-data` named volume.

### Changed

- `_build_profile` now returns `(errors, warned)` tuple instead of a bare
  `int`; callers (`build`, `refresh`) updated accordingly.
- `--output-format text|json` global flag replaces all per-command `--json`
  flags.  The flag must precede the subcommand name.  All commands emit
  structured JSON when `--output-format json` is active.
- `crl.max_workers` added to JSON Schema `crl_config` definition.
- `logging.format` added to JSON Schema `logging_config` definition.
- ROADMAP: `crab status` corrected to `crabctl status` throughout; Prometheus
  and Nagios items moved to Future section.

---

## [0.2.0] — 2026-04-12

### Added

**CRAB-PKI — test CA and certificate generation**

- **`crabctl ca init [CA_DIR]`** — initialise a self-signed root CA.
  Key type selectable: `rsa2048`, `rsa4096`, `ecdsa-p256`, `ecdsa-p384`,
  `ed25519`.  Key written mode 0600.  Creates `ca-cert.pem`, `ca-key.pem`,
  and an empty `serial.db`.
- **`crabctl ca show [CA_DIR]`** — display CA subject, key type, validity,
  fingerprint, and serial-database statistics.
- **`crabctl cert issue`** — issue a leaf certificate from a CA.  Options:
  `--ca`, `--cn`, `--san` (repeatable), `--profile` (`server`, `client`,
  `grid-host`), `--key-type`, `--days`, `--cdp-url`.
  `--add-to-profile` prints the `crab.yaml` source snippet.
- **`crabctl cert revoke`** — revoke a certificate and regenerate the CRL.
  Appends a revocation record to `serial.db` and atomically rewrites
  `ca.crl`.  `--reason` accepts all RFC 5280 reason codes.
- **`crabctl cert list`** — list serial-database records.  `--revoked` shows
  only revoked entries.
- **Certificate profiles**: `server` (serverAuth EKU, DNS SANs),
  `client` (clientAuth EKU), `grid-host` (serverAuth + clientAuth, CN
  auto-added as DNS SAN).
- `keyEncipherment` key usage correctly absent from ECDSA and Ed25519 certs;
  P-384 CAs sign with SHA-384; all others sign with SHA-256.
- Serial database (`serial.db`) — JSON-lines format; `fcntl`-locked for
  concurrent-write safety; stores fingerprint, profile, issued/expires
  timestamps, cert path, revocation state.
- `crab/pki.py` — new module exposing `init_ca`, `issue_cert`, `show_ca_info`,
  `revoke_cert`, `list_issued`, `generate_crl`.

**Config and tooling**

- JSON Schema for `crab.yaml` — enables editor autocompletion via
  `yaml-language-server` (`# yaml-language-server: $schema=…` header).
- `crabctl --version` reports the short commit SHA when installed from a
  git checkout (falls back to "unknown" for sdist/wheel installs).
- Tox matrix extended to Python 3.12 and 3.13.
- Debian/Ubuntu `.deb` package (Ubuntu 22.04 LTS and 24.04 LTS).
- `CONTRIBUTING.md` — development setup, test matrix, coding conventions.

### Fixed

- `file_mode` / `dir_mode` config keys now accept bare integer literals
  (e.g. `0644`) and `"0o644"`-style octal strings in addition to decimal
  strings.
- `crabctl diff` exited 0 in JSON mode regardless of whether changes were
  present; now exits 1 when additions, removals, or renewals are detected
  (matching text mode behaviour).
- Silent parse errors in `_load_certs_from_directory` — bare
  `except Exception: pass` replaced with `logger.warning(…)` so corrupt
  or unreadable PEM files surface at log level WARNING instead of being
  silently skipped.
- `description:` key in profiles was silently ignored; now stored and
  displayed in `crabctl show-config` output.

### Architecture

- Source registry and `build_source` factory moved to
  `crab/sources/__init__.py`; individual source modules unchanged.
- `PolicyOutcome` changed from a boolean to a ternary enum
  (`ACCEPT` / `WARN` / `REJECT`); `accepted` is now a property for
  backwards compatibility; no call-site changes required.
- `CRLManager.validate_crls` integrated into the `crabctl validate`
  pipeline — stale or missing CRLs for profiles with `include_crls: true`
  now appear as `ValidationIssue` entries.

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

[Unreleased]: https://github.com/snafus/crab-crab/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/snafus/crab-crab/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/snafus/crab-crab/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/snafus/crab-crab/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/snafus/crab-crab/releases/tag/v0.1.0
