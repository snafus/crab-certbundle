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

into one or more named output profiles. Each profile can produce:
- an OpenSSL-compatible **CApath directory** (`/etc/grid-security/certificates`)
- a flat **PEM bundle** file (for curl, Python requests, etc.)
- a **PKCS#12 truststore** (for Java, .NET, Tomcat)

---

## Features

- Atomic directory replacement — output is staged and renamed; consumers
  never see a partially-written directory
- Idempotent rebuilds — running twice produces the same output
- Policy engine — include/exclude/warn by subject regex, fingerprint, source,
  IGTF policy tag, EKU; reject expired or non-CA certificates
- Subject-hash computation via pyOpenSSL → subprocess openssl → Python fallback
- IGTF `.info` / `.signing_policy` / `.namespaces` file passthrough
- CRL fetch, store, and freshness validation with tunable staleness thresholds
- Diff mode — show what would change before committing a rebuild
- Dry-run mode
- `--output-format json` global flag for machine-readable output on all commands
- `--log-format json` global flag for structured log forwarding
- Python 3.6.8+ compatible (Rocky 8 / EL8, Rocky 9 / EL9)
- No dependency on OSG, VOMS, or grid middleware packages
- **Built-in test CA** — `crabctl ca` / `crabctl cert` for generating root and
  intermediate CAs and host certificates for lab and CI environments

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

1. Create a config file:

```bash
crabctl init-config -o /etc/crab/config.yaml
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
crabctl [--config FILE] [--verbose] [--quiet] [--output-format text|json] [--log-format text|json] COMMAND [ARGS]

Commands:
  build         Build one or more output profiles.
  refresh       Fetch CRLs then rebuild (equivalent to fetch-crls + build).
  validate      Validate one or more CApath directories.
  diff          Show changes between current output and a fresh build.
  list          List certificates in a source, profile, or directory.
  fetch-crls    Fetch or refresh CRLs for a profile.
  status        Report cert counts, expiry, and CRL freshness without network I/O.
  show-config   Dump the resolved configuration.
  init-config   Write a template crab.yaml to stdout or a file.
  ca            CA management sub-commands (init, intermediate, show).
  cert          Certificate sub-commands (issue, revoke, list, renew, sign).
  pki           Declarative PKI hierarchy sub-commands (build, init-config).
```

`--output-format json` switches all command output to machine-readable JSON.
This is a **global** flag and must appear before the subcommand name:

```bash
crabctl --output-format json validate grid
crabctl --output-format json status
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
crabctl --output-format json validate grid
```

### diff

```bash
# See what 'crabctl build grid' would change
crabctl diff grid

# Compare two directories directly
crabctl diff /etc/grid-security/certificates --old-dir /backup/certs

# JSON output
crabctl --output-format json diff grid
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
crabctl --output-format json list grid | jq '.[].subject'
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
crabctl --output-format json status
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
      warn:
        - subject_regex: "CN=ACME Lab.*"   # pass through but flag WARN
        - fingerprint: "AA:BB:CC:…"        # warn by fingerprint
```

**Policy evaluation order**: non-CA check → expired check → explicit
`include` list → explicit `exclude` list → `warn` list → default INCLUDE.
A certificate matching `warn` is included in the output but counts toward
`--strict-warnings` exit code 3.

**Output formats** — set `output_format:` in a profile (default `capath`):

| Format | Output | Use with |
|---|---|---|
| `capath` | Hashed directory — one file per cert, named `<hash>.0` | XRootD, dCache, gfal2, `SSL_CERT_DIR`, `curl --capath` |
| `bundle` | Single concatenated PEM file | `curl --cacert`, Python `requests`, anything reading a flat CA bundle |
| `pkcs12` | Binary PKCS#12 truststore (CA certs only, no private key) | Java (`-Djavax.net.ssl.trustStore`), .NET, Tomcat |

```yaml
profiles:
  # OpenSSL hashed directory (default)
  grid:
    output_format: capath          # can be omitted — this is the default
    output_path: /etc/grid-security/certificates
    rehash: auto                   # auto | openssl | python | none
    include_crls: true
    include_igtf_meta: true        # write .info / .signing_policy files

  # Flat PEM bundle — same sources, different format
  bundle:
    output_format: bundle
    output_path: /etc/crab/ca-bundle.pem
    annotate_bundle: true          # prepend # Subject/Issuer/Expires comments
                                   # (ignored by all PEM consumers; human-readable only)

  # PKCS#12 truststore for Java / .NET
  truststore:
    output_format: pkcs12
    output_path: /etc/crab/truststore.p12
    pkcs12_password: ""            # omit or set "" for unencrypted
```

Notes:
- `include_crls` and `include_igtf_meta` only apply to `capath`; they are
  ignored for `bundle` and `pkcs12`.
- `crabctl validate` only supports `capath` profiles; `bundle` and `pkcs12`
  profiles are skipped with an explanatory message. Use `crabctl list` to
  inspect a bundle file.
- Multiple profiles can share the same sources and produce all three formats
  in one `crabctl build` run.

**CRL cache-control** keys (under a profile or global `crl_config`):

```yaml
crl_config:
  cache_dir: /var/cache/crab/crls
  max_age_hours: 168        # warn if nextUpdate is more than this far in the past
  min_remaining_hours: 4    # warn if fewer than N hours remain until nextUpdate
  refetch_before_expiry_hours: 0  # skip re-fetch if CRL still has > N hours left
                                  # (0 = always refetch; set to e.g. 12 for weekly CAs)
```

`min_remaining_hours` fires a warning without failing the build; useful
for catching CAs that publish 24-hour CRLs but are slow to update.
`refetch_before_expiry_hours` reduces network traffic for CAs that publish
CRLs valid for many days (e.g. IGTF Tier-1 CAs publish weekly CRLs).

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
crabctl ca init ./my-ca --name "Lab Root CA" --org "ACME Lab"

# 2. (Optional) Create an intermediate CA signed by the root
crabctl ca intermediate ./my-ca/issuing \
    --parent ./my-ca \
    --name "Lab Issuing CA" --org "ACME Lab"

# 3. Issue a server certificate (CN auto-added as DNS SAN)
#    Use --ca ./my-ca/issuing when you have an intermediate CA
crabctl cert issue --ca ./my-ca --cn host.example.com

# 4. Issue a wildcard certificate
crabctl cert issue --ca ./my-ca --cn "*.example.com" \
    --san DNS:example.com

# 5. Issue with extra SANs including an IP address
crabctl cert issue --ca ./my-ca --cn host.example.com \
    --san DNS:host.internal --san IP:10.0.0.1 --days 90

# 6. Issue a grid-host cert (serverAuth + clientAuth EKU)
crabctl cert issue --ca ./my-ca --cn xrootd.example.com \
    --profile grid-host

# 7. Issue a client cert
crabctl cert issue --ca ./my-ca --cn alice \
    --profile client --san EMAIL:alice@example.com

# 8. Show CA details
crabctl ca show ./my-ca
crabctl --output-format json ca show ./my-ca

# 9. List issued certificates
crabctl cert list --ca ./my-ca

# 10. Revoke a certificate (regenerates CRL automatically)
crabctl cert revoke --ca ./my-ca \
    ./my-ca/issued/host.example.com-cert.pem \
    --reason keyCompromise

# 11. Show only revoked certificates
crabctl cert list --ca ./my-ca --revoked

# 12. Renew a certificate (revoke old, issue replacement in-place)
crabctl cert renew --ca ./my-ca \
    ./my-ca/issued/host.example.com-cert.pem

# 13. Sign an externally-generated CSR (private key stays with the requester)
crabctl cert sign --ca ./my-ca --csr host.csr --profile server
```

### CA directory layout

```
my-ca/                          ← root CA
  ca-cert.pem     Self-signed root certificate       (mode 0644)
  ca-key.pem      CA private key                     (mode 0600)
  serial.db       Issued certificate log (JSON-lines)
  crl.pem         Current CRL (written after first revocation)
  issued/
    my-ca-issuing-cert.pem      (the intermediate, recorded here)

my-ca/issuing/                  ← intermediate CA (if created)
  ca-cert.pem     Intermediate CA certificate        (mode 0644)
  ca-key.pem      Intermediate CA private key        (mode 0600)
  ca-chain.pem    This cert + full parent chain (excludes root)
  serial.db       Issued certificate log
  crl.pem         CRL for this intermediate
  issued/
    host.example.com-cert.pem
    host.example.com-key.pem        (mode 0600)
    host.example.com-fullchain.pem  (leaf + intermediates, no root)
```

`ca-chain.pem` is present on intermediate CAs only. When a certificate is
issued from an intermediate CA, a `{cn}-fullchain.pem` file is written
alongside the leaf certificate. It contains the leaf plus all intermediate
certificates, but **not** the root (following the TLS convention used by
Let's Encrypt and most public CAs). Configure your TLS server to serve this
file; clients should already trust the root independently.

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

### `crabctl ca intermediate`

```
crabctl ca intermediate [CA_DIR] [OPTIONS]

  CA_DIR      Directory to create for the new intermediate CA (default: ./ca)

Options:
  --parent PATH     Parent CA directory to sign with  [required]
  --name TEXT       Common Name for the intermediate CA  [default: CRAB Intermediate CA]
  --org TEXT        Organisation name
  --days INTEGER    Validity period in days  [default: 1825]
  --key-type TEXT   rsa2048 | rsa4096 | ecdsa-p256 | ecdsa-p384 | ed25519
                    [default: rsa2048]
  --path-length N   Maximum CA depth below this intermediate (-1 = unconstrained)
                    [default: 0 — this CA may only issue leaf certs]
  --cdp-url URL     CRL Distribution Point URL to embed in issued certs
  --force           Overwrite an existing intermediate CA directory
```

The new intermediate's certificate is signed by the parent CA and recorded in
the parent's `serial.db`. A `ca-chain.pem` is written to the new directory
containing this CA's certificate followed by any ancestor intermediates
(the root is excluded, as it must be trusted independently).

### `crabctl ca show`

```
crabctl ca show [CA_DIR]
```

Displays subject, type (root or intermediate), issuer (for intermediates),
key type, path length constraint, validity dates, fingerprint, issued/revoked
counts, whether a CRL is present, and whether a chain file exists.

Use `crabctl --output-format json ca show CA_DIR` for machine-readable output.

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

When issuing from an intermediate CA (one that has a `ca-chain.pem`), a
`{cn}-fullchain.pem` file is written alongside the leaf. It contains the
leaf certificate followed by any intermediate certificates, with the root
excluded. Use this file as the TLS certificate chain served by your daemon.

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
crabctl cert list --ca CA_DIR [--revoked]
```

Lists all certificates in the serial database. `--revoked` filters to
revoked certs only. For machine-readable output use the global flag:

```bash
crabctl --output-format json cert list --ca ./my-ca
```

### `crabctl cert renew`

```
crabctl cert renew --ca CA_DIR CERT [OPTIONS]

  CERT           Path to the PEM certificate to renew

  --days N       Validity period for the replacement cert (default: same as original)
  --reuse-key    Reuse the existing private key instead of generating a new one
  --force        Skip the "still valid" confirmation prompt
```

Revokes the existing certificate (reason: `superseded`) and issues a
replacement with the same CN, SANs, profile, and CDP URL.  The new cert and
key are written to the same filenames so consuming configs need only a service
reload.  The issuance is atomic-safe: the old cert remains valid unless and
until the new one is successfully written.

```bash
# Renew with a new key (default)
crabctl cert renew --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem

# Renew with the same key (e.g. key is in an HSM config or already distributed)
crabctl cert renew --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem \
    --reuse-key

# Renew early without confirmation
crabctl cert renew --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem \
    --days 365 --force
```

### `crabctl cert sign`

```
crabctl cert sign --ca CA_DIR --csr CSR [OPTIONS]

  --ca CA_DIR        Issuing CA directory  [required]
  --csr CSR          Path to a PEM PKCS#10 CSR  [required]
  --profile PROFILE  Certificate profile: server, client, grid-host (default: server)
  --days N           Validity period in days (default: 365)
  --san SAN          Extra SAN to add (repeatable; prefix DNS:, IP:, EMAIL:)
  --cdp-url URL      CRL Distribution Point URL
  --cn TEXT          Override the CN from the CSR
  --out DIR          Output directory (default: <ca-dir>/issued/)
```

Issue a certificate from a PKCS#10 CSR.  The private key never enters CRAB —
only the public key embedded in the CSR is used, and no key file is written.
This is the recommended workflow when the service generates its own key (Go,
Rust, Java services), when the key is HSM-backed, or in multi-team setups
where the CA operator should not handle service private keys.

CRAB applies CA policy (profile, key usage, EKU) regardless of any extensions
requested in the CSR.

```bash
# Application generates a key and CSR
openssl req -newkey rsa:2048 -nodes -keyout svc-key.pem \
    -out svc.csr -subj "/CN=svc.example.com"

# CA operator signs it — no key file created on the CA side
crabctl cert sign --ca ./my-ca --csr svc.csr --profile server --days 365

# Add SANs that were not in the CSR
crabctl cert sign --ca ./my-ca --csr svc.csr \
    --san DNS:svc.internal --san IP:10.0.0.5
```

### `crabctl pki build` — declarative PKI hierarchy

Build an entire CA hierarchy — root, intermediates, and leaf certificates —
from a single `pki.yaml` file:

```
crabctl pki build [PKI_CONFIG]

  PKI_CONFIG     Path to a pki.yaml file (default: pki.yaml)

  --dry-run      Preview what would be created without writing any files
  --force-certs  Re-issue leaf certificates that already exist on disk.
                 CA directories are never regenerated regardless of this flag.
```

The build is **idempotent** — safe to re-run.  Existing CA directories are
always skipped (regenerating a CA would invalidate all previously issued
certificates).  Existing leaf cert files are skipped unless `--force-certs`
is given.  Hierarchy depth is unlimited.

```bash
# Generate a template
crabctl pki init-config -o pki.yaml

# Edit pki.yaml, then build the full hierarchy in one command
crabctl pki build pki.yaml

# Preview without touching the filesystem
crabctl pki build pki.yaml --dry-run

# Re-issue all leaf certs (e.g. after expiry) without touching CAs
crabctl pki build pki.yaml --force-certs
```

Example `pki.yaml`:

```yaml
version: 1

root:
  dir: ./pki/root-ca
  cn: "My Project Root CA"
  key_type: ecdsa-p256
  days: 3650

  intermediates:
    - dir: ./pki/issuing-ca
      cn: "My Project Issuing CA"
      key_type: ecdsa-p256
      days: 1825
      path_length: 0

      certs:
        - cn: host.example.com
          profile: server
          days: 365
          san:
            - DNS:host.example.com
            - DNS:host.internal

        - cn: alice
          profile: client
          days: 365
          san:
            - EMAIL:alice@example.com
```

### `crabctl init-config` — generate a crab.yaml template

```bash
crabctl init-config               # full annotated reference → stdout
crabctl init-config --minimal     # minimal working example → stdout
crabctl init-config -o crab.yaml  # write to file
crabctl init-config -o crab.yaml --force  # overwrite existing
```

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

Two unit files are provided: `crabctl.service` (a oneshot service that runs
the build) and `crabctl.timer` (fires daily at 04:00 with up to 30 minutes
of random jitter so cluster nodes don't all hit dl.igtf.net at once).

### RPM / deb package installs

The package installs the unit files automatically.  After placing your config
at `/etc/crab/config.yaml`, enable the timer:

```bash
# Create the config (if you haven't already)
crabctl init-config -o /etc/crab/config.yaml

# Enable and start the timer
systemctl enable --now crabctl.timer

# Run once immediately to verify
systemctl start crabctl.service
journalctl -u crabctl.service -f
```

### Manual / pipx installs

Copy the unit files from the source tree, then follow the same steps:

```bash
# Install unit files
install -m 644 systemd/crab.service /etc/systemd/system/crabctl.service
install -m 644 systemd/crab.timer   /etc/systemd/system/crabctl.timer

# Create required directories
install -d /etc/crab /var/lib/crab/staging /var/cache/crab /var/log/crab

# Create the config
crabctl init-config -o /etc/crab/config.yaml

# Enable
systemctl daemon-reload
systemctl enable --now crabctl.timer

# Verify
systemctl start crabctl.service
journalctl -u crabctl.service -f
```

### Checking status

```bash
systemctl status crabctl.timer          # next scheduled run
systemctl list-timers crabctl.timer     # last + next trigger times
journalctl -u crabctl.service --since "24 hours ago"
crabctl status                          # cert counts, expiry, CRL freshness
```

### Customising the schedule

Edit `/etc/systemd/system/crabctl.timer` (or use a drop-in):

```bash
systemctl edit crabctl.timer
```

```ini
[Timer]
OnCalendar=*-*-* 06:30:00   # change run time
RandomizedDelaySec=3600      # spread over 1 hour instead of 30 min
```

```bash
systemctl daemon-reload
systemctl restart crabctl.timer
```

### Hardening

The service unit runs as root by default (needed to write to
`/etc/grid-security/certificates`).  If your `output_path` is owned by
another user, set `User=` and `Group=` in the unit and adjust
`ReadWritePaths=` accordingly:

```bash
systemctl edit crabctl.service
```

```ini
[Service]
User=crab
Group=crab
ReadWritePaths=/srv/crab/output
ReadWritePaths=/var/cache/crab
```

### cron alternative

If you prefer cron over systemd timers:

```cron
# /etc/cron.d/crabctl
0 4 * * *  root  /usr/bin/crabctl --config /etc/crab/config.yaml build 2>&1 | logger -t crabctl
```

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
