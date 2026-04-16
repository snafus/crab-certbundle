# crab

**OpenSSL-style CA certificate directory builder for research infrastructure**

`crab` generates and updates hashed CApath directories suitable for
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
- Python 3.6.8+ compatible (Rocky 8 / EL8, Rocky 9 / EL9)
- No dependency on OSG, VOMS, or grid middleware packages
- **Built-in test CA** — `crabctl ca` / `crabctl cert` for generating
  self-signed CAs and host certificates for lab and CI environments

---

## Platform and Python compatibility

| Platform | Python | Status |
|---|---|---|
| Rocky Linux 8 / RHEL 8 / CentOS Stream 8 | 3.6.8 (system) | **Supported** |
| Rocky Linux 9 / RHEL 9 / AlmaLinux 9 | 3.9 (system) | **Supported** |
| Ubuntu 22.04 LTS | 3.10 | **Supported** |
| Ubuntu 24.04 LTS | 3.12 | **Supported** |
| Any Linux, Python 3.6.8 – 3.13 | any | **Supported** |

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

### RPM (Rocky Linux 8 / 9, RHEL, AlmaLinux)

```bash
# Build the .rpm (requires rpmbuild, python3-pip, gcc, openssl-devel, libffi-devel)
mkdir -p rpmbuild/SOURCES
git archive --format=tar.gz --prefix=crab-certbundle-0.3.0/ HEAD \
    > rpmbuild/SOURCES/crab-certbundle-0.3.0.tar.gz
rpmbuild -ba packaging/rpm/crab-certbundle.spec \
    --define "_topdir $(pwd)/rpmbuild" \
    --define "_sourcedir $(pwd)/rpmbuild/SOURCES"
# Install
sudo rpm -ivh rpmbuild/RPMS/x86_64/crab-certbundle-*.rpm
```

### Debian/Ubuntu (22.04 LTS, 24.04 LTS)

```bash
# Install build dependencies
sudo apt-get install -y dpkg-dev debhelper python3-pip gcc libssl-dev libffi-dev

# Build the .deb
bash packaging/deb/build-deb.sh
# → debbuild/crab-certbundle_0.3.0-1_amd64.deb

# Install
sudo dpkg -i debbuild/crab-certbundle_*_amd64.deb
```

### From source (any platform)

```bash
# From source
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
cp examples/config-minimal.yaml /etc/crab/config.yaml
# Edit to set your source paths and output_path
```

2. Build the output directory:

```bash
crabctl --config /etc/crab/config.yaml build
```

3. Validate the result:

```bash
crabctl --config /etc/crab/config.yaml validate
```

---

## CLI reference

```
crabctl [--config FILE] [--verbose] [--quiet] [--log-format text|json] COMMAND [ARGS]

Commands:
  build         Build one or more output profiles.
  refresh       Fetch CRLs then rebuild (equivalent to fetch-crls + build).
  validate      Validate one or more CApath directories.
  diff          Show changes between current output and a fresh build.
  list          List certificates in a source, profile, or directory.
  fetch-crls    Fetch or refresh CRLs for a profile.
  status        Report cert counts, expiry, and CRL freshness without network I/O.
  show-config   Dump the resolved configuration.
```

`--log-format json` emits one JSON object per log line with fields
`timestamp` (ISO-8601 UTC with ms), `level`, `logger`, `message`, and
`exception` (when present). Useful for forwarding to log aggregators.
The format can also be set globally via `logging.format: json` in
`crab.yaml`; the CLI flag takes priority.

### build

```bash
# Build all profiles
crabctl build

# Build specific profiles
crabctl build grid server-auth

# Preview without writing
crabctl build --dry-run

# Print source/policy report
crabctl build --report

# Exit 3 if any policy warnings or CRL fetch failures occur
crabctl build --strict-warnings
```

`--strict-warnings` is intended for CI and monitoring hooks. Exit codes:
0 = success, 1 = errors, 3 = success with warnings (policy `WARN` outcomes
or CRL fetch failures). Exit 1 takes priority over exit 3.

### validate

```bash
# Validate all profiles defined in config
crabctl validate

# Validate a specific profile
crabctl validate grid

# Validate an arbitrary directory
crabctl validate /etc/grid-security/certificates

# Output JSON
crabctl validate --json grid
```

### diff

```bash
# See what 'crabctl build grid' would change
crabctl diff grid

# Compare two directories directly
crabctl diff /etc/grid-security/certificates --old-dir /backup/certs

# JSON output
crabctl diff --json grid
```

### list

```bash
# List all certificates in a profile (after policy filtering)
crabctl list grid

# List from a specific source (before policy)
crabctl list --source igtf-classic

# List from a raw directory
crabctl list /etc/grid-security/certificates

# Show only expired
crabctl list --expired grid

# JSON
crabctl list --json grid | jq '.[].subject'
```

### fetch-crls

```bash
# Fetch CRLs for all profiles with include_crls: true
crabctl fetch-crls

# Fetch for a specific profile
crabctl fetch-crls grid

# Dry run — show URLs without downloading
crabctl fetch-crls --dry-run
```

### refresh

Convenience command: fetch CRLs then rebuild all affected profiles in one
step. Equivalent to running `fetch-crls` followed by `build`.

```bash
crabctl refresh
crabctl refresh grid
crabctl refresh --dry-run
crabctl refresh --strict-warnings   # exit 3 on warnings
```

### status

Read output directories without any network access and report cert counts,
expiry information, CRL freshness, and last-built time. Useful for monitoring
and dashboards.

```bash
# Status of all profiles
crabctl status

# Machine-readable JSON output
crabctl status --json
```

Exit codes: 0 = all profiles healthy, 1 = any profile degraded or missing.

A profile is **healthy** when its output directory exists, contains at least
one certificate, no certificates are expired, and no CRL staleness warnings
are present.

---

## Configuration

See `examples/config-full.yaml` for a fully annotated reference configuration.

A JSON Schema is bundled at `crab/schema/crab.yaml.json` and enables
editor autocompletion and inline validation in VS Code (with the
[YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml))
and any editor that supports `yaml-language-server`. Add this comment to
the top of your config file to activate it:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/ska-telescope/ska-src-cert-bundle/main/crab/schema/crab.yaml.json
version: 1
…
```

Or point directly at your installed copy:

```yaml
# yaml-language-server: $schema=/path/to/site-packages/crab/schema/crab.yaml.json
```

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

---

## CRAB-PKI: local test CA and certificate generation

CRAB includes a lightweight CA for bootstrapping lab and CI environments —
useful for XRootD/dCache test nodes, internal grid services, and any
situation where you need a working PKI in minutes rather than days.

> **For testing only.** For production PKI use step-ca, cfssl, or
> HashiCorp Vault PKI. CRAB-PKI stores private keys as unencrypted PEM
> files on disk.

### Quick start

```bash
# 1. Create a self-signed root CA
crabctl ca init ./my-ca --name "Lab Test CA" --org "ACME Lab"

# 2. Issue a server certificate (CN auto-added as DNS SAN)
crabctl cert issue --ca ./my-ca --cn host.example.com

# 3. Issue a wildcard certificate
crabctl cert issue --ca ./my-ca --cn "*.example.com" \
    --san DNS:example.com

# 4. Issue with extra SANs including an IP address
crabctl cert issue --ca ./my-ca --cn host.example.com \
    --san DNS:host.internal --san IP:10.0.0.1 --days 90

# 5. Issue a grid-host cert (serverAuth + clientAuth EKU)
crabctl cert issue --ca ./my-ca --cn xrootd.example.com \
    --profile grid-host

# 6. Issue a client cert
crabctl cert issue --ca ./my-ca --cn alice \
    --profile client --san EMAIL:alice@example.com

# 7. Show CA details
crabctl ca show ./my-ca
crabctl ca show ./my-ca --json

# 8. List issued certificates
crabctl cert list --ca ./my-ca

# 9. Revoke a certificate (regenerates CRL automatically)
crabctl cert revoke --ca ./my-ca \
    ./my-ca/issued/host.example.com-cert.pem \
    --reason keyCompromise

# 10. Show only revoked certificates
crabctl cert list --ca ./my-ca --revoked
```

### CA directory layout

```
my-ca/
  ca-cert.pem     Self-signed root CA certificate (mode 0644)
  ca-key.pem      CA private key                  (mode 0600)
  serial.db       Issued certificate log (JSON-lines)
  crl.pem         Current CRL (written after first revocation)
  issued/
    host.example.com-cert.pem
    host.example.com-key.pem   (mode 0600)
```

### `crabctl ca init`

```
crabctl ca init [CA_DIR] [OPTIONS]

  CA_DIR      Directory to create (default: ./ca)

Options:
  --name TEXT       Common Name for the CA  [default: CRAB Test CA]
  --org TEXT        Organisation name
  --days INTEGER    Validity period in days  [default: 3650]
  --key-type TEXT   rsa2048 | rsa4096 | ecdsa-p256 | ecdsa-p384 | ed25519
                    [default: rsa2048]
  --force           Overwrite an existing CA
  --add-to-profile  Print the crab.yaml snippet for adding this CA
                    as a local source in the named profile
```

### `crabctl ca show`

```
crabctl ca show [CA_DIR] [--json]
```

Displays subject, key type, validity dates, fingerprint, issued/revoked
counts, and whether a CRL is present.

### `crabctl cert issue`

```
crabctl cert issue --ca CA_DIR [OPTIONS]

  --cn TEXT        Common Name  [required]
  --san TEXT       Subject Alternative Name (repeatable)
                   Prefix: DNS: | IP: | EMAIL:
                   Unprefixed values are auto-detected (IP vs DNS)
  --days INTEGER   Validity in days  [default: 365]
  --profile TEXT   server | client | grid-host  [default: server]
  --key-type TEXT  rsa2048 | rsa4096 | ecdsa-p256 | ecdsa-p384 | ed25519
                   [default: rsa2048]
  --out DIR        Output directory  [default: <ca-dir>/issued/]
  --cdp-url URL    CRL Distribution Point URL to embed in the cert
```

**Profile summary:**

| Profile | Key Usage | Extended Key Usage |
|---|---|---|
| `server` | `digitalSignature`, `keyEncipherment` | `serverAuth` |
| `client` | `digitalSignature` | `clientAuth` |
| `grid-host` | `digitalSignature`, `keyEncipherment` | `serverAuth`, `clientAuth` |

`keyEncipherment` is omitted for Ed25519 keys (not applicable to that
algorithm).

**Key algorithm reference:**

| `--key-type` | Algorithm | Security | Notes |
|---|---|---|---|
| `rsa2048` | RSA-2048 | ~112-bit | IGTF minimum; broad compatibility |
| `rsa4096` | RSA-4096 | ~140-bit | Conservative choice; slower generation |
| `ecdsa-p256` | ECDSA P-256 | ~128-bit | Recommended for new certs; universal TLS support |
| `ecdsa-p384` | ECDSA P-384 | ~192-bit | NIST Suite B; used in some RI/federal contexts |
| `ed25519` | Ed25519 | ~128-bit | Fastest; not yet in IGTF baseline |

P-256 is the recommended default for test infrastructure. RSA-2048 is kept as
the default for maximum compatibility with older IGTF middleware.

**SAN auto-detection:**

- If `--cn` contains a dot (e.g. `host.example.com`), it is automatically
  added as a `DNS:` SAN. You do not need to repeat it with `--san`.
- Wildcard CNs (e.g. `*.example.com`) are written as `DNS:*.example.com`
  in the SAN extension. A wildcard does not cover the apex domain
  (`example.com`) — add that separately with `--san DNS:example.com`.
- CNs without a dot (e.g. bare hostnames or usernames) are not
  auto-added; supply at least one `--san` in that case.

**Wildcard example:**

```bash
# Covers *.example.com AND example.com
crabctl cert issue --ca ./my-ca \
    --cn "*.example.com" \
    --san DNS:example.com
```

### `crabctl cert revoke`

```
crabctl cert revoke --ca CA_DIR CERT [--reason REASON]

  CERT    Path to a PEM certificate previously issued by this CA

  --reason  unspecified | keyCompromise | affiliationChanged |
            superseded | cessationOfOperation
            [default: unspecified]
```

The CA's CRL is regenerated atomically after every revocation. The CRL
is written to `<ca-dir>/crl.pem`.

### `crabctl cert list`

```
crabctl cert list --ca CA_DIR [--json] [--revoked]
```

Lists all certificates in the serial database. `--revoked` filters to
revoked certs only. `--json` emits the raw serial-database records.

### Adding your test CA to a crab profile

After creating a CA, add it as a `local` source in your `crab.yaml` so
that any software consuming the CRAB output directory will trust
certificates issued by it:

```yaml
sources:
  my-test-ca:
    type: local
    path: /path/to/my-ca/ca-cert.pem   # the CA certificate only

profiles:
  grid:
    sources:
      - igtf-classic
      - my-test-ca          # include alongside IGTF anchors
    output_path: /etc/grid-security/certificates
    policy:
      require_ca_flag: true
      reject_expired: true
```

`crabctl ca init --add-to-profile PROFILE` prints the exact snippet to
paste for a given profile name.

---

## Scheduled refresh

### systemd timer

```bash
cp systemd/crab.service systemd/crab.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now crab.timer
```

### cron

```cron
0 4 * * *  root  crabctl --config /etc/crab/config.yaml build 2>&1 | logger -t crabctl
```

See `systemd/README.md` for full installation instructions.

---

## Testing

```bash
# Run tests (requires pytest and cryptography)
pytest -v

# With coverage
pytest --cov=crab --cov-report=term-missing

# In a Rocky 8 container
docker build -t crab-test .
docker run --rm crab-test pytest -v

# Build and smoke-test the .deb on Ubuntu 22.04
docker run --rm -v "$(pwd)":/src ubuntu:22.04 bash -c "
    apt-get update -q &&
    apt-get install -y -q dpkg-dev debhelper python3-pip gcc libssl-dev libffi-dev &&
    cd /src &&
    bash packaging/deb/build-deb.sh &&
    dpkg -I debbuild/crab-certbundle_*_amd64.deb"
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
