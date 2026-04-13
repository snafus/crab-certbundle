# certbundle

**OpenSSL-style CA certificate directory builder for research infrastructure**

`certbundle` generates and updates hashed CApath directories suitable for
XRootD, dCache clients, curl/OpenSSL consumers, and similar data-movement
middleware used in research computing environments such as SRCNet, WLCG, and
EGI.

It combines:
- **IGTF trust anchors** (classic, IOTA, MICS, SLCS policies)
- **Public CA roots** (system bundle, custom directories)
- **Optional CRLs** fetched from CDP extensions or IGTF `.info` files

into one or more named output profiles, each an OpenSSL-compatible CApath
directory that can be used directly by any software reading
`/etc/grid-security/certificates` or a similar path.

---

## Features

- Atomic directory replacement — output is staged and renamed; consumers
  never see a partially-written directory
- Idempotent rebuilds — running twice produces the same output
- Policy engine — include/exclude by subject regex, fingerprint, source, IGTF
  policy tag, EKU; reject expired or non-CA certificates
- Subject-hash computation via pyOpenSSL → subprocess openssl → Python fallback
- IGTF `.info` / `.signing_policy` / `.namespaces` file passthrough
- CRL fetch, store, and freshness validation
- Diff mode — show what would change before committing a rebuild
- Dry-run mode
- JSON output for all list/diff/validate commands
- Python 3.6.8+ compatible (EL7, Rocky 8, RHEL8 system Python)
- No dependency on OSG, VOMS, or grid middleware packages

---

## Platform and Python compatibility

| Platform | Python | Status |
|---|---|---|
| Rocky Linux 8 / RHEL 8 / CentOS Stream 8 | 3.6.8 (system) | **Supported** |
| Rocky Linux 9 / RHEL 9 / AlmaLinux 9 | 3.9 (system) | **Supported** |
| Ubuntu 22.04 LTS | 3.10 | **Supported** |
| Ubuntu 24.04 LTS | 3.12 | **Supported** |
| Any Linux, Python 3.6.8 – 3.12 | any | **Supported** |

No features from Python 3.7+ are used (no `dataclasses`, no walrus operator,
no `tomllib`, no `dict[str,str]` generic syntax).

## Requirements

- Python 3.6.8+
- `cryptography >= 2.8`
- `PyYAML >= 5.1`
- `click >= 7.0`
- `requests >= 2.20`
- `openssl` binary on PATH (for `openssl rehash`; optional but strongly recommended)
- Optional: `pyOpenSSL >= 19.0` for guaranteed-correct subject hash computation

---

## Installation

```bash
# From source (recommended for EL/Rocky systems)
pip3 install .

# With optional pyOpenSSL for accurate hash computation
pip3 install ".[openssl]"

# Development install
pip3 install -e ".[dev]"
```

---

## Quick start

1. Create a config file (see `examples/`):

```bash
cp examples/config-minimal.yaml /etc/certbundle/config.yaml
# Edit to set your source paths and output_path
```

2. Build the output directory:

```bash
certbundle --config /etc/certbundle/config.yaml build
```

3. Validate the result:

```bash
certbundle --config /etc/certbundle/config.yaml validate
```

---

## CLI reference

```
certbundle [--config FILE] [--verbose] [--quiet] COMMAND [ARGS]

Commands:
  build         Build one or more output profiles.
  validate      Validate one or more CApath directories.
  diff          Show changes between current output and a fresh build.
  list          List certificates in a source, profile, or directory.
  fetch-crls    Fetch or refresh CRLs for a profile.
  show-config   Dump the resolved configuration.
```

### build

```bash
# Build all profiles
certbundle build

# Build specific profiles
certbundle build grid server-auth

# Preview without writing
certbundle build --dry-run

# Print source/policy report
certbundle build --report
```

### validate

```bash
# Validate all profiles defined in config
certbundle validate

# Validate a specific profile
certbundle validate grid

# Validate an arbitrary directory
certbundle validate /etc/grid-security/certificates

# Output JSON
certbundle validate --json grid
```

### diff

```bash
# See what 'certbundle build grid' would change
certbundle diff grid

# Compare two directories directly
certbundle diff /etc/grid-security/certificates --old-dir /backup/certs

# JSON output
certbundle diff --json grid
```

### list

```bash
# List all certificates in a profile (after policy filtering)
certbundle list grid

# List from a specific source (before policy)
certbundle list --source igtf-classic

# List from a raw directory
certbundle list /etc/grid-security/certificates

# Show only expired
certbundle list --expired grid

# JSON
certbundle list --json grid | jq '.[].subject'
```

### fetch-crls

```bash
# Fetch CRLs for all profiles with include_crls: true
certbundle fetch-crls

# Fetch for a specific profile
certbundle fetch-crls grid

# Dry run — show URLs without downloading
certbundle fetch-crls --dry-run
```

---

## Configuration

See `examples/config-full.yaml` for a fully annotated reference configuration.

Key concepts:

**Sources** define where certificates come from:

```yaml
sources:
  igtf-classic:
    type: igtf
    path: /etc/grid-security/certificates   # local extracted directory
    policies: [classic, iota]               # IGTF policy filter

  system-roots:
    type: local
    path: /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
```

**Profiles** define output directories and apply policy:

```yaml
profiles:
  grid:
    sources: [igtf-classic]
    output_path: /etc/grid-security/certificates
    atomic: true
    rehash: auto
    include_crls: true
    policy:
      reject_expired: true
      require_ca_flag: true
      exclude:
        - subject_regex: "CN=Some Deprecated CA.*"
```

---

## Scheduled refresh

### systemd timer

```bash
cp systemd/certbundle.service systemd/certbundle.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now certbundle.timer
```

### cron

```cron
0 4 * * *  root  certbundle --config /etc/certbundle/config.yaml build 2>&1 | logger -t certbundle
```

See `systemd/README.md` for full installation instructions.

---

## Testing

```bash
# Run tests (requires pytest and cryptography)
pytest -v

# With coverage
pytest --cov=certbundle --cov-report=term-missing

# In a Rocky 8 container
docker build -t certbundle-test .
docker run --rm certbundle-test pytest -v
```

---

## Security notes

- **URL scheme enforcement**: only `http://` and `https://` URLs are accepted
  for downloads. `file://`, `ftp://`, etc. are rejected.
- **Tarball safety**: IGTF tarball members are extracted using
  `os.path.basename()` — malicious archive paths (e.g. `../../etc/cron.d/`)
  are stripped before any file is written.
- **Atomic output**: the staging→output rename means consumers (XRootD, etc.)
  never see a partially-written directory. `output_path` must be a real
  directory, not a symlink.
- **CRL writes**: temp files are created with `tempfile.mkstemp()` and renamed
  atomically; issuer hashes are validated as `[0-9a-f]{8}` before any path
  is constructed.
- **TLS verification**: `verify_tls: false` is supported for air-gapped
  environments but emits a prominent WARNING. Never disable in production.

---

## Architecture

See `docs/ARCHITECTURE.md` for a detailed description of the pipeline stages,
hash computation strategy, atomic swap mechanism, policy model, and IGTF
integration.

---

## Design principles

- **Independent**: no dependency on OSG, VOMS, or grid middleware
- **Generic**: designed for any research infrastructure, not just WLCG
- **Modular**: each concern (parsing, policy, output, CRL, validation) is a
  separate module with a clean interface
- **Deterministic**: same inputs always produce the same output
- **Safe**: atomic writes, validation, dry-run mode, security-hardened I/O

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of changes.

---

## License

Apache 2.0
