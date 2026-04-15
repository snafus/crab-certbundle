"""
CRAB-PKI: minimal self-signed CA and host certificate generation.

Designed for testing and research-infrastructure bootstrapping.  For
production PKAs use purpose-built tools (step-ca, cfssl, Vault PKI).

CA directory layout
-------------------
::

    <ca-dir>/
      ca-cert.pem     Self-signed root CA certificate (mode 0644)
      ca-key.pem      CA private key                  (mode 0600)
      serial.db       Issued certificate log           (mode 0600, JSON-lines)
      crl.pem         Current CRL                      (mode 0644)
      issued/         Default location for issued certs
        <cn>-cert.pem
        <cn>-key.pem

Public API
----------
init_ca        Create a new self-signed root CA.
issue_cert     Issue a certificate signed by a CA.
revoke_cert    Revoke a certificate and regenerate the CRL.
generate_crl   Regenerate the CRL from the serial database.
show_ca_info   Return a dict of CA details.
list_issued    Return all serial-database records.
"""

import fcntl
import json
import logging
import os
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519_mod
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

CERT_PROFILES = ("server", "client", "grid-host")
KEY_TYPES = ("rsa2048", "rsa4096", "ed25519")

REVOKE_REASONS = (
    "unspecified",
    "keyCompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
)

_REASON_FLAGS = {
    "unspecified":         x509.ReasonFlags.unspecified,
    "keyCompromise":       x509.ReasonFlags.key_compromise,
    "affiliationChanged":  x509.ReasonFlags.affiliation_changed,
    "superseded":          x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
}

# Internal directory/file names
_CA_CERT_FILE  = "ca-cert.pem"
_CA_KEY_FILE   = "ca-key.pem"
_SERIAL_DB_FILE = "serial.db"
_CRL_FILE      = "crl.pem"
_ISSUED_DIR    = "issued"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PKIError(Exception):
    """Raised for PKI operation errors."""


# ---------------------------------------------------------------------------
# Internal helpers — keys
# ---------------------------------------------------------------------------

def _generate_key(key_type):
    if key_type == "rsa2048":
        return _rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa4096":
        return _rsa_mod.generate_private_key(public_exponent=65537, key_size=4096)
    if key_type == "ed25519":
        return _ed25519_mod.Ed25519PrivateKey.generate()
    raise PKIError(
        "Unknown key type {!r}. Valid types: {}".format(key_type, ", ".join(KEY_TYPES))
    )


def _is_ed25519(key):
    return isinstance(key, _ed25519_mod.Ed25519PrivateKey)


def _sign_hash(key):
    """Return the hash algorithm for signing, or None for Ed25519."""
    return None if _is_ed25519(key) else hashes.SHA256()


def _key_pem(key):
    # type: (...) -> bytes
    # PKCS8 format is required for Ed25519 keys (TraditionalOpenSSL only
    # supports RSA/DSA/EC).  It is equally well-supported by OpenSSL for
    # RSA keys, so we use it universally.
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _key_type_label(pub):
    # type: (...) -> str
    if isinstance(pub, _ed25519_mod.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, _rsa_mod.RSAPublicKey):
        return "RSA-{}".format(pub.key_size)
    return type(pub).__name__


# ---------------------------------------------------------------------------
# Internal helpers — certs
# ---------------------------------------------------------------------------

def _cert_fp(cert):
    # type: (x509.Certificate) -> str
    """Return the SHA-256 fingerprint as a colon-delimited hex string."""
    raw = cert.fingerprint(hashes.SHA256())
    return ":".join("{:02X}".format(b) for b in raw)


def _utcnow_naive():
    # type: () -> datetime
    """Return the current UTC time as a naive datetime (required by cryptography < 42)."""
    return datetime.utcnow()


def _format_dt(dt):
    # type: (datetime) -> str
    """Format a naive-or-aware datetime as an ISO-8601 UTC string."""
    if dt.tzinfo is not None:
        dt = dt.utctimetuple()
        return datetime(*dt[:6]).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_date(dt):
    # type: (datetime) -> str
    return dt.strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Internal helpers — file I/O
# ---------------------------------------------------------------------------

def _write_atomic(path, data, mode=0o644):
    # type: (str, bytes, int) -> None
    """Write *data* to *path* atomically via a temporary file + rename."""
    dirpath = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=dirpath)
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _safe_filename(cn):
    # type: (str) -> str
    """Sanitise a common name for use as a base filename."""
    return re.sub(r"[^\w\-.]", "_", cn)


# ---------------------------------------------------------------------------
# Serial database
# ---------------------------------------------------------------------------

class SerialDB:
    """
    JSON-lines issued-certificate database.

    Each line is one JSON object representing one issued certificate.
    Uses ``fcntl.flock`` for process-level locking (Linux/macOS only).

    Schema (per record)::

        serial            int    — monotonically increasing per-CA serial
        cn                str    — Common Name at issue time
        subject           str    — RFC 4514 subject DN
        fingerprint_sha256 str   — colon-hex SHA-256 fingerprint
        profile           str    — 'server' | 'client' | 'grid-host'
        issued_at         str    — ISO-8601 UTC
        expires_at        str    — ISO-8601 UTC
        cert_file         str    — path relative to CA directory
        revoked           bool
        revoked_at        str|null — ISO-8601 UTC when revoked
        revoke_reason     str|null
    """

    def __init__(self, path):
        # type: (str) -> None
        self._path = path

    # ------------------------------------------------------------------
    # Internal

    @staticmethod
    def _parse_lines(fh):
        # type: (...) -> List[dict]
        fh.seek(0)
        records = []
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records

    # ------------------------------------------------------------------
    # Public

    def records(self):
        # type: () -> List[dict]
        """Return all records (shared lock)."""
        if not os.path.exists(self._path):
            return []
        with open(self._path, "r") as fh:
            fcntl.flock(fh, fcntl.LOCK_SH)
            return self._parse_lines(fh)

    def next_serial(self):
        # type: () -> int
        """Return the next unused serial number."""
        recs = self.records()
        if not recs:
            return 1
        return max(r["serial"] for r in recs) + 1

    def append(self, record):
        # type: (dict) -> None
        """Append *record* to the database (exclusive lock, append-only)."""
        with open(self._path, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps(record) + "\n")

    def revoke(self, fingerprint_sha256, revoked_at, reason="unspecified"):
        # type: (str, str, str) -> int
        """
        Mark the certificate with *fingerprint_sha256* as revoked.

        Rewrites the database in place (exclusive lock).
        Returns the serial number of the revoked certificate.
        Raises :exc:`PKIError` if the cert is not found or already revoked.
        """
        if not os.path.exists(self._path):
            raise PKIError("Serial database not found: {}".format(self._path))

        with open(self._path, "r+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            records = self._parse_lines(fh)

            target = None
            for rec in records:
                if rec.get("fingerprint_sha256") == fingerprint_sha256:
                    target = rec
                    break

            if target is None:
                raise PKIError(
                    "Certificate with fingerprint {} not found in this CA's "
                    "serial database — was it issued by a different CA?".format(
                        fingerprint_sha256
                    )
                )
            if target.get("revoked"):
                raise PKIError(
                    "Certificate (serial {}) is already revoked".format(target["serial"])
                )

            target["revoked"] = True
            target["revoked_at"] = revoked_at
            target["revoke_reason"] = reason

            fh.seek(0)
            fh.truncate()
            for rec in records:
                fh.write(json.dumps(rec) + "\n")

            return target["serial"]


# ---------------------------------------------------------------------------
# CA directory accessor
# ---------------------------------------------------------------------------

class CADirectory:
    """Encapsulates a CRAB-PKI CA directory layout."""

    def __init__(self, path):
        # type: (str) -> None
        self.path = os.path.abspath(path)
        self.ca_cert_path = os.path.join(self.path, _CA_CERT_FILE)
        self.ca_key_path  = os.path.join(self.path, _CA_KEY_FILE)
        self.crl_path     = os.path.join(self.path, _CRL_FILE)
        self.issued_dir   = os.path.join(self.path, _ISSUED_DIR)
        self.serial_db    = SerialDB(os.path.join(self.path, _SERIAL_DB_FILE))

    def exists(self):
        # type: () -> bool
        return (
            os.path.isfile(self.ca_cert_path)
            and os.path.isfile(self.ca_key_path)
        )

    def load_cert(self):
        # type: () -> x509.Certificate
        with open(self.ca_cert_path, "rb") as fh:
            return x509.load_pem_x509_certificate(fh.read())

    def load_key(self):
        with open(self.ca_key_path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)


# ---------------------------------------------------------------------------
# CA initialisation
# ---------------------------------------------------------------------------

def init_ca(
    out_dir,                # type: str
    cn,                     # type: str
    org=None,               # type: Optional[str]
    days=3650,              # type: int
    key_type="rsa2048",     # type: str
    force=False,            # type: bool
):
    # type: (...) -> Tuple[str, str]
    """
    Create a new self-signed root CA in *out_dir*.

    Parameters
    ----------
    out_dir:  Directory to create (need not exist).
    cn:       Common Name of the CA, e.g. "My Test CA".
    org:      Optional Organisation name.
    days:     Validity period in days (default 3650 ≈ 10 years).
    key_type: One of ``rsa2048``, ``rsa4096``, ``ed25519``.
    force:    Overwrite an existing CA without raising.

    Returns
    -------
    (ca_cert_path, ca_key_path)

    Raises
    ------
    PKIError  if a CA already exists and *force* is False, or on I/O errors.
    """
    out_dir = os.path.abspath(out_dir)
    ca = CADirectory(out_dir)

    if ca.exists() and not force:
        raise PKIError(
            "A CA already exists in '{}'. "
            "Use --force to overwrite.".format(out_dir)
        )

    os.makedirs(out_dir, mode=0o755, exist_ok=True)
    os.makedirs(ca.issued_dir, mode=0o755, exist_ok=True)

    key = _generate_key(key_type)
    pub = key.public_key()

    # Build subject name
    attrs = []
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    subject = x509.Name(attrs)

    now = _utcnow_naive()
    not_after = now + timedelta(days=days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)                      # self-signed
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pub),
            critical=False,
        )
        .sign(key, _sign_hash(key))
    )

    _write_atomic(ca.ca_key_path,  _key_pem(key), mode=0o600)
    _write_atomic(ca.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM))

    logger.info(
        "CA initialised: %s  key=%s  valid until %s",
        subject.rfc4514_string(), key_type, _format_date(not_after),
    )
    return ca.ca_cert_path, ca.ca_key_path


# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------

def _parse_san(value):
    # type: (str) -> x509.GeneralName
    """
    Parse a SAN string into a :class:`x509.GeneralName`.

    Accepted forms:
      - ``DNS:host.example.com`` (explicit prefix)
      - ``IP:1.2.3.4`` or ``IP:::1``
      - ``EMAIL:user@example.com``
      - ``host.example.com`` (DNS assumed when unambiguous)
      - ``1.2.3.4`` (IPv4/IPv6 detected automatically)
    """
    import ipaddress

    upper = value.upper()
    if upper.startswith("DNS:"):
        return x509.DNSName(value[4:])
    if upper.startswith("IP:"):
        try:
            return x509.IPAddress(ipaddress.ip_address(value[3:]))
        except ValueError as exc:
            raise PKIError("Invalid IP SAN {!r}: {}".format(value, exc))
    if upper.startswith("EMAIL:"):
        return x509.RFC822Name(value[6:])

    # Auto-detect: try IP first, fall back to DNS
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def _key_usage_for_profile(profile, is_ed25519_key):
    # type: (str, bool) -> x509.KeyUsage
    """
    Return the KeyUsage extension for *profile*.

    Ed25519 keys do not support ``key_encipherment`` (RSA-specific
    operation), so that bit is always False for Ed25519.
    """
    if profile in ("server", "grid-host"):
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=not is_ed25519_key,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    if profile == "client":
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    raise PKIError("Unknown profile {!r}. Valid: {}".format(profile, ", ".join(CERT_PROFILES)))


def _eku_for_profile(profile):
    # type: (str) -> x509.ExtendedKeyUsage
    if profile == "server":
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    if profile == "client":
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    if profile == "grid-host":
        # Grid middleware (XRootD, dCache, gfal2) requires both serverAuth
        # and clientAuth.  Some older VOMS deployments look for clientAuth
        # specifically on data-transfer endpoints.
        return x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ])
    raise PKIError("Unknown profile {!r}. Valid: {}".format(profile, ", ".join(CERT_PROFILES)))


def issue_cert(
    ca_dir_path,            # type: str
    cn,                     # type: str
    sans=None,              # type: Optional[List[str]]
    days=365,               # type: int
    profile="server",       # type: str
    key_type="rsa2048",     # type: str
    out_dir=None,           # type: Optional[str]
    cdp_url=None,           # type: Optional[str]
):
    # type: (...) -> Tuple[str, str]
    """
    Issue a certificate signed by the CA in *ca_dir_path*.

    Parameters
    ----------
    ca_dir_path: Path to an existing CA directory (created by :func:`init_ca`).
    cn:          Common Name (hostname for server/grid-host, username for client).
    sans:        Additional Subject Alternative Names.  Each entry may be prefixed
                 with ``DNS:``, ``IP:``, or ``EMAIL:``.  The CN is automatically
                 added as a DNS SAN when it looks like a hostname.
    days:        Validity period in days.
    profile:     ``server``, ``client``, or ``grid-host``.
    key_type:    ``rsa2048``, ``rsa4096``, or ``ed25519``.
    out_dir:     Directory for the output files.  Defaults to ``<ca-dir>/issued/``.
    cdp_url:     Optional CRL Distribution Point URL to embed in the certificate.

    Returns
    -------
    (cert_path, key_path)
    """
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError(
            "No CA found in '{}'. Run 'crabctl ca init' first.".format(ca_dir_path)
        )

    if profile not in CERT_PROFILES:
        raise PKIError("Unknown profile {!r}. Valid: {}".format(profile, ", ".join(CERT_PROFILES)))

    ca_cert = ca.load_cert()
    ca_key  = ca.load_key()

    if out_dir is None:
        out_dir = ca.issued_dir
    os.makedirs(out_dir, mode=0o755, exist_ok=True)

    # Build SAN list.  The CN is prepended as a DNS SAN when it contains a
    # dot (hostname heuristic) and is not already present in explicit SANs.
    san_objects = []
    explicit_dns = set()

    for s in (sans or []):
        gn = _parse_san(s)
        san_objects.append(gn)
        if isinstance(gn, x509.DNSName):
            explicit_dns.add(gn.value)

    if "." in cn and cn not in explicit_dns:
        san_objects.insert(0, x509.DNSName(cn))

    if not san_objects:
        raise PKIError(
            "No Subject Alternative Names could be determined. "
            "Provide a hostname as --cn or supply --san values."
        )

    key = _generate_key(key_type)
    pub = key.public_key()
    is_ed = _is_ed25519(key)

    subject  = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    serial   = ca.serial_db.next_serial()
    now      = _utcnow_naive()
    not_after = now + timedelta(days=days)

    # Retrieve CA's SKI for AKI on the issued cert
    ca_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(pub)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .add_extension(_key_usage_for_profile(profile, is_ed), critical=True)
        .add_extension(_eku_for_profile(profile), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_objects), critical=False)
    )

    if cdp_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(cdp_url)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
            critical=False,
        )

    cert = builder.sign(ca_key, _sign_hash(ca_key))
    fp   = _cert_fp(cert)

    # Write output files
    safe_cn   = _safe_filename(cn)
    cert_path = os.path.join(out_dir, "{}-cert.pem".format(safe_cn))
    key_path  = os.path.join(out_dir, "{}-key.pem".format(safe_cn))

    _write_atomic(key_path,  _key_pem(key), mode=0o600)
    _write_atomic(cert_path, cert.public_bytes(serialization.Encoding.PEM))

    # Record in serial database
    ca.serial_db.append({
        "serial":             serial,
        "cn":                 cn,
        "subject":            cert.subject.rfc4514_string(),
        "fingerprint_sha256": fp,
        "profile":            profile,
        "issued_at":          _format_dt(now),
        "expires_at":         _format_dt(not_after),
        "cert_file":          os.path.relpath(cert_path, ca.path),
        "revoked":            False,
        "revoked_at":         None,
        "revoke_reason":      None,
    })

    logger.info(
        "Issued cert serial=%d cn=%r profile=%s valid until %s",
        serial, cn, profile, _format_date(not_after),
    )
    return cert_path, key_path


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

def revoke_cert(ca_dir_path, cert_path, reason="unspecified"):
    # type: (str, str, str) -> None
    """
    Revoke a certificate and regenerate the CA's CRL.

    Parameters
    ----------
    ca_dir_path: Path to the CA directory.
    cert_path:   Path to the PEM certificate to revoke.
    reason:      One of the values in :data:`REVOKE_REASONS`.

    Raises
    ------
    PKIError  if the certificate was not issued by this CA, is already
              revoked, or the CA directory does not exist.
    """
    if reason not in _REASON_FLAGS:
        raise PKIError(
            "Unknown revocation reason {!r}. Valid: {}".format(
                reason, ", ".join(REVOKE_REASONS)
            )
        )

    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))

    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())

    fp = _cert_fp(cert)
    now_str = _format_dt(_utcnow_naive())

    serial = ca.serial_db.revoke(fp, now_str, reason)
    logger.info("Revoked serial=%d reason=%s", serial, reason)

    generate_crl(ca_dir_path)


# ---------------------------------------------------------------------------
# CRL generation
# ---------------------------------------------------------------------------

def generate_crl(ca_dir_path, crl_days=30):
    # type: (str, int) -> str
    """
    Regenerate and write the CRL from the current serial database.

    Uses the current POSIX timestamp as the CRL number (monotonically
    increasing across invocations).

    Returns the path to the written CRL file.
    """
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))

    ca_cert = ca.load_cert()
    ca_key  = ca.load_key()

    now        = _utcnow_naive()
    next_update = now + timedelta(days=crl_days)
    crl_number  = int(time.time())

    # Retrieve CA SKI for AKI extension on CRL
    ca_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )

    for rec in ca.serial_db.records():
        if not rec.get("revoked"):
            continue
        revoked_at_str = rec.get("revoked_at") or _format_dt(now)
        revoked_at = datetime.strptime(revoked_at_str, "%Y-%m-%dT%H:%M:%SZ")
        reason_flag = _REASON_FLAGS.get(
            rec.get("revoke_reason", "unspecified"),
            x509.ReasonFlags.unspecified,
        )
        revoked_entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(rec["serial"])
            .revocation_date(revoked_at)
            .add_extension(x509.CRLReason(reason_flag), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_entry)

    crl = builder.sign(ca_key, _sign_hash(ca_key))
    _write_atomic(ca.crl_path, crl.public_bytes(serialization.Encoding.PEM))
    logger.info("CRL written to %s (nextUpdate %s)", ca.crl_path, _format_date(next_update))
    return ca.crl_path


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

def show_ca_info(ca_dir_path):
    # type: (str) -> dict
    """
    Return a dict describing the CA in *ca_dir_path*.

    Keys: ``ca_dir``, ``subject``, ``serial``, ``not_before``,
    ``not_after``, ``fingerprint_sha256``, ``key_type``,
    ``issued_count``, ``revoked_count``.
    """
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))

    cert    = ca.load_cert()
    records = ca.serial_db.records()

    return {
        "ca_dir":             ca.path,
        "subject":            cert.subject.rfc4514_string(),
        "serial":             str(cert.serial_number),
        "not_before":         _format_date(cert.not_valid_before),
        "not_after":          _format_date(cert.not_valid_after),
        "fingerprint_sha256": _cert_fp(cert),
        "key_type":           _key_type_label(cert.public_key()),
        "issued_count":       len(records),
        "revoked_count":      sum(1 for r in records if r.get("revoked")),
        "crl_exists":         os.path.isfile(ca.crl_path),
    }


def list_issued(ca_dir_path):
    # type: (str) -> List[dict]
    """Return all serial-database records for *ca_dir_path*."""
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))
    return ca.serial_db.records()
