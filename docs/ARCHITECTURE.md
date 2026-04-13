# certbundle — Architecture Notes

## Overview

`certbundle` builds OpenSSL-compatible CApath directories by combining IGTF
trust anchors with public CA roots.  The pipeline is designed to be
**modular**, **deterministic**, and **independently maintainable** — it does
not depend on OSG packaging, VOMS, or any grid middleware.

---

## Pipeline stages

```
Sources ──► Certificate set ──► Policy filter ──► Output renderer ──► CApath dir
                                                        │
                                                   CRL manager
                                                        │
                                                   Validator
                                                        │
                                                   Reporter
```

Each stage is a separate Python module with a well-defined interface.

---

## Module map

| Module | Responsibility |
|---|---|
| `certbundle.cert` | `CertificateInfo` data model; PEM/DER parsing |
| `certbundle.rehash` | OpenSSL subject-hash computation; `build_symlink_map` |
| `certbundle.sources.igtf` | Load IGTF tarballs / directories |
| `certbundle.sources.local` | Load local directories and bundle files |
| `certbundle.sources.http` | HTTP download with retry |
| `certbundle.policy` | Include/exclude rule engine |
| `certbundle.output` | Write CApath directories; atomic swap |
| `certbundle.crl` | Fetch, store, and validate CRLs |
| `certbundle.validation` | Post-build directory health checks |
| `certbundle.reporting` | Diff computation; text and JSON rendering |
| `certbundle.config` | YAML config loading and validation |
| `certbundle.cli` | Click-based command-line interface |

---

## Certificate identity and deduplication

Each certificate is identified by its **SHA-256 fingerprint** (the hash of
the DER-encoded certificate bytes).  Two `CertificateInfo` objects with the
same fingerprint are definitionally identical regardless of source or file
name.  The output renderer deduplicates by fingerprint before assigning hash
filenames.

A certificate *renewal* is detected in the diff engine when two certificates
share the same **subject DN** but have different fingerprints.

---

## Hash filename computation

OpenSSL CApath directories contain files named `<hash>.<n>` where:

- `<hash>` is a 32-bit unsigned integer formatted as 8 lowercase hex digits,
  computed from the **canonical** DER encoding of the certificate's subject name
- `<n>` is a collision counter starting at 0

The hash algorithm (OpenSSL 1.1+) is:
1. Canonicalise the subject name: convert all string values to UTF-8,
   lowercase, strip/collapse whitespace, re-encode as `UTF8String`.
2. SHA-1 hash the resulting DER.
3. Take the first 4 bytes as a little-endian `uint32`.
4. Clear the high bit: `value & 0x7FFFFFFF`.

`certbundle` computes this hash via three strategies in priority order:

1. **pyOpenSSL** (`cert.subject_name_hash()`) — calls the C library directly;
   guaranteed to match `openssl x509 -hash`.  Preferred when available.
2. **subprocess** (`openssl x509 -hash -noout`) — reliable when `openssl` is
   on the PATH; no Python dependency required.
3. **Pure Python fallback** — correct for well-formed certificates with UTF-8
   or ASCII-only subjects; may diverge for legacy TeletexString or BMPString.

After all files are written the tool optionally calls `openssl rehash` or
`c_rehash` on the output directory to (re)create symlinks, which is the
standard approach on Red Hat / EL-family systems.

---

## Policy model

A policy configuration block supports:

- **Structural filters**: `require_ca_flag`, `reject_path_len_zero`
- **Validity filters**: `reject_expired`, `reject_not_yet_valid`
- **EKU filters**: `server_auth_only`, `client_auth_only`
- **Include rules**: a cert must match *at least one* (OR semantics)
- **Exclude rules**: a cert is rejected if it matches *any* (OR semantics)
- Within a single rule: multiple keys are combined with AND semantics

Rule matchers: `subject_regex`, `fingerprint_sha256`, `fingerprint_sha1`,
`source` (source name), `igtf_policy`.

---

## Atomic output replacement

When `atomic: true` (the default), output is first built in a staging
directory, then the staging directory is atomically renamed into the target
path using `os.rename()`.  The old directory is kept as `.bak` during the
rename window and removed afterwards.  This prevents consumers from seeing a
partially-written output directory.

```
1. Write to  <output_path>.staging/
2. Rename    <output_path>       →  <output_path>.bak
3. Rename    <output_path>.staging  →  <output_path>
4. Remove    <output_path>.bak
```

On a single filesystem, steps 2 and 3 are atomic at the directory level.

---

## IGTF integration

IGTF trust anchors are distributed as `.tar.gz` bundles at:
`https://dl.igtf.net/distribution/igtf/current/accredited/`

Each bundle contains per-CA files:

| Extension | Content |
|---|---|
| `.pem` | DER-encoded certificate in PEM armour |
| `.info` | `key = value` metadata (alias, policy, CRL URL, status) |
| `.signing_policy` | Globus signing policy (subject namespace restrictions) |
| `.namespaces` | EUGridPMA namespace definitions |
| `.crl_url` | CRL distribution URL(s) |

`certbundle` parses `.info` files and stores all metadata on the
`CertificateInfo.igtf_info` dict, making it available to policy rules
(`igtf_policy` matcher) and output renderers (written as `.info` files
alongside the hashed certificate files).

---

## CRL management

CRL files follow the same naming convention as certificates but use `.r<n>`
suffixes:  `<issuer_hash>.r0`, `<issuer_hash>.r1`, etc.

CRL URLs are discovered from:
1. The certificate's CRL Distribution Points (CDP) extension
2. The IGTF `.info` file's `crlurl` key

Downloaded CRLs are converted from DER to PEM via `openssl crl` and stored
in the configured CRL directory (default: same as certificate output).

Freshness is evaluated against the CRL's `thisUpdate` field relative to a
configurable `max_age_hours` threshold (default 24 h).

---

## Trust separation

`certbundle` supports clean separation of trust stores through the profile
model:

| Profile | Sources | Typical consumer |
|---|---|---|
| `grid` | IGTF classic/IOTA only | XRootD, gfal2, dCache, globus-gsi |
| `server` | Public CA roots | curl, wget, Python requests |
| `combined` | IGTF + public roots | Hybrid tools, SRCNet data nodes |

Each profile writes to a distinct directory and can have independent policy,
CRL, and rehash settings.

---

## Python 3.6 compatibility

The package targets Python 3.6.8+ (EL7 / Rocky 8 system Python) and
deliberately avoids:

- `dataclasses` (3.7+)
- walrus operator `:=` (3.8+)
- `tomllib` (3.11+)
- f-string `=` debug specifier (3.8+)
- `typing.Literal`, `typing.Final` (3.8+)

All type annotations are expressed as `# type:` comments rather than inline
annotations where 3.6 support matters.

---

## Security considerations

- All HTTP downloads use TLS verification by default (`verify_tls: true`).
  Set `verify_tls: false` only for air-gapped / internal hosts where the
  intermediate CA is not in the system trust store.
- CRL files are written atomically (`.tmp` → rename).
- The tool does **not** perform OCSP checking; it relies solely on CRLs for
  revocation status.
- Self-signed certificates are not verified against any external root; the
  operator is responsible for ensuring the source URLs are authoritative.
- Output directories should be owned by root with mode 755; individual files
  at 644.  The systemd unit enforces this via `ProtectSystem=strict`.

---

## Extension points

The source loading interface (`CertificateSource.load()` → `SourceResult`) is
designed to be subclassed.  Potential future sources:

- `LDAPSource` — LDAP-published trust anchor repositories
- `VOSource` — VO-specific trust bundles fetched from VOMS Admin
- `HashiCorpVaultSource` — PKI secrets engine integration
- `RPMSource` — extract certs from a grid CA RPM package

Policy rules can be extended by adding new matchers in `policy.py`
(`_compile_rule`).
