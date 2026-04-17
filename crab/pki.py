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
init_ca                Create a new self-signed root CA.
init_intermediate_ca   Create an intermediate CA signed by an existing CA.
issue_cert             Issue a certificate signed by a CA.
renew_cert             Revoke an existing certificate and re-issue with the same parameters.
sign_csr               Sign a PKCS#10 CSR and issue a certificate (no key file written).
revoke_cert            Revoke a certificate and regenerate the CRL.
generate_crl           Regenerate the CRL from the serial database.
show_ca_info           Return a dict of CA details.
list_issued            Return all serial-database records.
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
from cryptography.hazmat.primitives.asymmetric import ec as _ec_mod
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519_mod
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

CERT_PROFILES = ("server", "client", "grid-host")
KEY_TYPES = ("rsa2048", "rsa4096", "ecdsa-p256", "ecdsa-p384", "ed25519")

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
_CHAIN_FILE    = "ca-chain.pem"   # intermediate cert + all parent certs
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
    if key_type == "ecdsa-p256":
        return _ec_mod.generate_private_key(_ec_mod.SECP256R1())
    if key_type == "ecdsa-p384":
        return _ec_mod.generate_private_key(_ec_mod.SECP384R1())
    if key_type == "ed25519":
        return _ed25519_mod.Ed25519PrivateKey.generate()
    raise PKIError(
        "Unknown key type {!r}. Valid types: {}".format(key_type, ", ".join(KEY_TYPES))
    )


def _is_ed25519(key):
    # Kept for backwards compatibility with any external callers.
    return isinstance(key, _ed25519_mod.Ed25519PrivateKey)


def _no_key_encipherment(key):
    # type: (...) -> bool
    """
    Return True when the key type does not support keyEncipherment.

    keyEncipherment is an RSA-specific operation (used in RSA key exchange).
    ECDSA and Ed25519 use ephemeral ECDH for key exchange instead, so the
    bit must be absent from their KeyUsage extensions or some validators
    will reject the certificate.
    """
    return not isinstance(key, _rsa_mod.RSAPrivateKey)


def _sign_hash(key):
    """Return the hash algorithm for signing, or None for Ed25519."""
    if isinstance(key, _ed25519_mod.Ed25519PrivateKey):
        return None
    if isinstance(key, _ec_mod.EllipticCurvePrivateKey):
        # Use SHA-384 for P-384 (matched security level); SHA-256 for P-256
        if isinstance(key.curve, _ec_mod.SECP384R1):
            return hashes.SHA384()
        return hashes.SHA256()
    return hashes.SHA256()


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
    if isinstance(pub, _ec_mod.EllipticCurvePublicKey):
        return "ECDSA-{}".format(pub.curve.name.upper())
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
        self.ca_cert_path  = os.path.join(self.path, _CA_CERT_FILE)
        self.ca_key_path   = os.path.join(self.path, _CA_KEY_FILE)
        self.chain_path    = os.path.join(self.path, _CHAIN_FILE)
        self.crl_path      = os.path.join(self.path, _CRL_FILE)
        self.issued_dir    = os.path.join(self.path, _ISSUED_DIR)
        self.serial_db     = SerialDB(os.path.join(self.path, _SERIAL_DB_FILE))

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
# Intermediate CA initialisation
# ---------------------------------------------------------------------------

def init_intermediate_ca(
    out_dir,                # type: str
    parent_ca_dir,          # type: str
    cn,                     # type: str
    org=None,               # type: Optional[str]
    days=1825,              # type: int
    key_type="rsa2048",     # type: str
    path_length=0,          # type: Optional[int]
    force=False,            # type: bool
    cdp_url=None,           # type: Optional[str]
):
    # type: (...) -> Tuple[str, str]
    """
    Create an intermediate CA signed by an existing CA.

    The new CA directory has the same layout as a root CA (ca-cert.pem,
    ca-key.pem, serial.db, …) and can issue certificates with
    :func:`issue_cert`.  It additionally contains ``ca-chain.pem`` — the
    concatenation of this CA's certificate and all ancestor certificates up
    to the root — which is required by relying parties to build the full
    chain.

    The issuance is recorded in the parent CA's serial database.

    Parameters
    ----------
    out_dir:       Directory to create for the intermediate CA.
    parent_ca_dir: Path to an existing CA directory (root or intermediate).
    cn:            Common Name of the intermediate CA.
    org:           Optional Organisation name.
    days:          Validity period in days (default 1825 ≈ 5 years).
    key_type:      Key algorithm (same choices as :func:`init_ca`).
    path_length:   ``BasicConstraints`` pathLenConstraint.  0 means this CA
                   can only sign end-entity certs; None means unconstrained.
                   Default 0 (typical single-level hierarchy).
    force:         Overwrite existing CA without raising.
    cdp_url:       CRL Distribution Point URL to embed in the issued cert.

    Returns
    -------
    (ca_cert_path, ca_key_path)

    Raises
    ------
    PKIError  if the parent CA is not found, the directory already exists and
              *force* is False, or on I/O errors.
    """
    out_dir = os.path.abspath(out_dir)
    parent  = CADirectory(parent_ca_dir)
    if not parent.exists():
        raise PKIError(
            "No CA found in '{}'. Run 'crabctl ca init' first.".format(parent_ca_dir)
        )

    ca = CADirectory(out_dir)
    if ca.exists() and not force:
        raise PKIError(
            "A CA already exists in '{}'. "
            "Use --force to overwrite.".format(out_dir)
        )

    os.makedirs(out_dir, mode=0o755, exist_ok=True)
    os.makedirs(ca.issued_dir, mode=0o755, exist_ok=True)

    parent_cert = parent.load_cert()
    parent_key  = parent.load_key()

    # Validate that the parent's BasicConstraints permit issuing CA certs.
    try:
        parent_bc = parent_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not parent_bc.ca:
            raise PKIError(
                "Parent certificate is not a CA (BasicConstraints CA=FALSE)."
            )
        if parent_bc.path_length is not None and parent_bc.path_length == 0:
            raise PKIError(
                "Parent CA has pathLen=0 and cannot sign further CA certificates."
            )
    except x509.ExtensionNotFound:
        raise PKIError(
            "Parent certificate has no BasicConstraints extension."
        )

    key = _generate_key(key_type)
    pub = key.public_key()

    attrs = []
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    subject = x509.Name(attrs)

    now      = _utcnow_naive()
    not_after = now + timedelta(days=days)
    serial   = parent.serial_db.next_serial()

    parent_ski = parent_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent_cert.subject)
        .public_key(pub)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
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
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(parent_ski),
            critical=False,
        )
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

    cert = builder.sign(parent_key, _sign_hash(parent_key))
    fp   = _cert_fp(cert)

    # Write the intermediate CA's own certificate and key.
    _write_atomic(ca.ca_key_path,  _key_pem(key), mode=0o600)
    _write_atomic(ca.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM))

    # Write ca-chain.pem: this cert followed by any chain from the parent.
    # If the parent itself has a chain file, include that; otherwise just
    # append the parent's own CA cert.
    chain_pem = cert.public_bytes(serialization.Encoding.PEM)
    if os.path.isfile(parent.chain_path):
        with open(parent.chain_path, "rb") as fh:
            chain_pem += fh.read()
    else:
        chain_pem += parent_cert.public_bytes(serialization.Encoding.PEM)
    _write_atomic(ca.chain_path, chain_pem)

    # Record in the parent CA's serial database.
    parent.serial_db.append({
        "serial":             serial,
        "cn":                 cn,
        "subject":            cert.subject.rfc4514_string(),
        "fingerprint_sha256": fp,
        "profile":            "intermediate-ca",
        "issued_at":          _format_dt(now),
        "expires_at":         _format_dt(not_after),
        "cert_file":          os.path.abspath(ca.ca_cert_path),
        "revoked":            False,
        "revoked_at":         None,
        "revoke_reason":      None,
    })

    logger.info(
        "Intermediate CA initialised: %s  parent=%s  key=%s  pathLen=%s  valid until %s",
        subject.rfc4514_string(),
        parent_cert.subject.rfc4514_string(),
        key_type,
        str(path_length) if path_length is not None else "unconstrained",
        _format_date(not_after),
    )
    return ca.ca_cert_path, ca.ca_key_path


# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------

_PEM_CERT_RE = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _strip_self_signed(chain_pem_bytes):
    # type: (bytes) -> bytes
    """
    Return *chain_pem_bytes* with self-signed (root CA) certificates removed.

    Used to build a fullchain file that contains only the leaf certificate
    and intermediate CAs — the root must be in the relying party's trust
    store and is conventionally excluded from presented chains.
    """
    result = b""
    for block in _PEM_CERT_RE.findall(chain_pem_bytes):
        cert = x509.load_pem_x509_certificate(block)
        if cert.subject != cert.issuer:
            result += block + b"\n"
    return result


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


def _key_type_from_public_key(pub):
    # type: (...) -> str
    """Infer a KEY_TYPES string from a public key object."""
    if isinstance(pub, _ed25519_mod.Ed25519PublicKey):
        return "ed25519"
    if isinstance(pub, _rsa_mod.RSAPublicKey):
        return "rsa4096" if pub.key_size >= 3500 else "rsa2048"
    if isinstance(pub, _ec_mod.EllipticCurvePublicKey):
        return "ecdsa-p384" if isinstance(pub.curve, _ec_mod.SECP384R1) else "ecdsa-p256"
    raise PKIError("Unrecognised public key type: {}".format(type(pub).__name__))


def _profile_from_cert(cert):
    # type: (x509.Certificate) -> str
    """
    Infer the closest CERT_PROFILES name from a certificate's EKU extension.

    Returns ``grid-host`` when both serverAuth and clientAuth are present,
    ``client`` when only clientAuth is present, and ``server`` otherwise
    (including when there is no EKU extension).
    """
    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        oids = set(eku)
        has_server = ExtendedKeyUsageOID.SERVER_AUTH in oids
        has_client = ExtendedKeyUsageOID.CLIENT_AUTH in oids
        if has_server and has_client:
            return "grid-host"
        if has_client:
            return "client"
    except x509.ExtensionNotFound:
        pass
    return "server"


def _sans_from_cert(cert):
    # type: (x509.Certificate) -> List[str]
    """
    Extract SANs from *cert* as prefixed strings (``DNS:…``, ``IP:…``, ``EMAIL:…``).

    Returns an empty list if no SubjectAlternativeName extension is present.
    Unrecognised GeneralName types are silently skipped.
    """
    import ipaddress as _ipaddress
    result = []
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        for gn in san_ext:
            if isinstance(gn, x509.DNSName):
                result.append("DNS:{}".format(gn.value))
            elif isinstance(gn, x509.IPAddress):
                result.append("IP:{}".format(str(gn.value)))
            elif isinstance(gn, x509.RFC822Name):
                result.append("EMAIL:{}".format(gn.value))
    except x509.ExtensionNotFound:
        pass
    return result


def _cdp_url_from_cert(cert):
    # type: (x509.Certificate) -> Optional[str]
    """Return the first CDP URI embedded in *cert*, or ``None``."""
    try:
        cdp_ext = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
        for dp in cdp_ext:
            if dp.full_name:
                for gn in dp.full_name:
                    if isinstance(gn, x509.UniformResourceIdentifier):
                        return gn.value
    except x509.ExtensionNotFound:
        pass
    return None


def _days_from_cert(cert):
    # type: (x509.Certificate) -> int
    """Return the validity period of *cert* in whole days (minimum 1)."""
    delta = cert.not_valid_after - cert.not_valid_before
    return max(1, delta.days)


def _key_usage_for_profile(profile, no_key_encipherment):
    # type: (str, bool) -> x509.KeyUsage
    """
    Return the KeyUsage extension for *profile*.

    RSA keys use ``keyEncipherment`` for key exchange.  ECDSA and Ed25519
    use ephemeral ECDH instead, so ``keyEncipherment`` must be absent from
    their certificates or strict validators will reject them.
    """
    if profile in ("server", "grid-host"):
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=not no_key_encipherment,
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


def _build_and_record_cert(ca, ca_cert, ca_key, public_key, cn, sans, days, profile, cdp_url, out_dir):
    # type: (...) -> str
    """
    Core certificate-signing operation.  Builds, signs, writes the cert
    file (and fullchain when appropriate), and records the issuance in the
    serial database.

    *public_key* is the subject public key — either derived from a private
    key (in :func:`_issue_cert_with_key`) or extracted from a CSR (in
    :func:`sign_csr`).  No private key material is handled here.

    Parameters
    ----------
    ca:         :class:`CADirectory` for the issuing CA.
    ca_cert:    Loaded CA certificate.
    ca_key:     Loaded CA private key (used only for signing).
    public_key: Subject public key for the new certificate.
    cn:         Common Name.
    sans:       SAN strings (``DNS:…``, ``IP:…``, ``EMAIL:…``).
    days:       Validity period in days.
    profile:    ``server``, ``client``, or ``grid-host``.
    cdp_url:    Optional CRL Distribution Point URL.
    out_dir:    Directory to write output files (must already exist).

    Returns
    -------
    cert_path
    """
    # keyEncipherment must be absent from non-RSA certs.
    no_enc = not isinstance(public_key, _rsa_mod.RSAPublicKey)

    # Build SAN list.  Auto-add CN as a DNS SAN for hostnames.
    san_objects  = []
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

    subject   = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    serial    = ca.serial_db.next_serial()
    now       = _utcnow_naive()
    not_after = now + timedelta(days=days)

    ca_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .add_extension(_key_usage_for_profile(profile, no_enc), critical=True)
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

    cert     = builder.sign(ca_key, _sign_hash(ca_key))
    fp       = _cert_fp(cert)
    safe_cn  = _safe_filename(cn)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = os.path.join(out_dir, "{}-cert.pem".format(safe_cn))

    _write_atomic(cert_path, cert_pem)

    # Write fullchain when the issuing CA is an intermediate.
    # fullchain = leaf cert + intermediate CA certs (roots excluded).
    if os.path.isfile(ca.chain_path):
        with open(ca.chain_path, "rb") as fh:
            chain_data = fh.read()
        intermediates = _strip_self_signed(chain_data)
        if intermediates:
            fullchain_path = os.path.join(out_dir, "{}-fullchain.pem".format(safe_cn))
            _write_atomic(fullchain_path, cert_pem + intermediates)
            logger.debug("Wrote fullchain to %s", fullchain_path)

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
    return cert_path


def _issue_cert_with_key(ca, ca_cert, ca_key, key, cn, sans, days, profile, cdp_url, out_dir):
    # type: (...) -> Tuple[str, str]
    """
    Issue a certificate from a private key.  Writes the key file first
    (mode 0600), then delegates to :func:`_build_and_record_cert`.

    Used by :func:`issue_cert` (fresh key) and :func:`renew_cert`
    (optionally reused key).

    Returns (cert_path, key_path).
    """
    safe_cn  = _safe_filename(cn)
    key_path = os.path.join(out_dir, "{}-key.pem".format(safe_cn))
    # Write key before cert so that if the cert write fails the key is not lost.
    _write_atomic(key_path, _key_pem(key), mode=0o600)
    cert_path = _build_and_record_cert(
        ca, ca_cert, ca_key, key.public_key(), cn, sans, days, profile, cdp_url, out_dir
    )
    return cert_path, key_path


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

    Side effects
    ------------
    When the issuing CA is an intermediate (i.e. it has a ``ca-chain.pem``),
    a ``{cn}-fullchain.pem`` is also written containing the leaf certificate
    followed by all intermediate CA certificates (roots excluded).  This file
    is suitable for use as the ``ssl_certificate`` / ``SSLCertificateFile``
    directive in nginx/Apache, the XRootD ``tls.certificate`` parameter, etc.
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

    key = _generate_key(key_type)
    return _issue_cert_with_key(ca, ca_cert, ca_key, key, cn, sans, days, profile, cdp_url, out_dir)


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
# Certificate renewal
# ---------------------------------------------------------------------------

def renew_cert(
    ca_dir_path,            # type: str
    cert_path,              # type: str
    days=None,              # type: Optional[int]
    reuse_key=False,        # type: bool
    out_dir=None,           # type: Optional[str]
):
    # type: (...) -> Tuple[str, str]
    """
    Renew a certificate by revoking the old one and issuing a replacement
    with the same CN, SANs, profile, CDP URL, and validity period.

    The new certificate is written to the same filenames as the old one
    (derived from the CN), so consuming configurations — TLS server configs,
    volume mounts, etc. — do not need updating; only a service reload or
    restart is required.

    Parameters
    ----------
    ca_dir_path: Path to the CA directory that originally issued the cert.
    cert_path:   Path to the PEM certificate to renew.
    days:        Validity period for the new cert in days.  Defaults to the
                 same period as the original (``notAfter - notBefore``).
    reuse_key:   If ``True``, reuse the existing private key instead of
                 generating a fresh one.  The key file must be present
                 alongside the cert (same directory, ``{cn}-key.pem``).
                 Defaults to ``False`` (key rotation).
    out_dir:     Directory to write the new cert and key.  Defaults to the
                 directory that contains *cert_path*.

    Returns
    -------
    (cert_path, key_path) — paths to the newly written certificate and key.

    Raises
    ------
    PKIError  if the CA or cert is not found, the cert was not issued by
              this CA, the key file is missing when ``reuse_key=True``, or
              on I/O errors.
    """
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))

    if not os.path.isfile(cert_path):
        raise PKIError("Certificate not found: {}".format(cert_path))

    with open(cert_path, "rb") as fh:
        old_cert = x509.load_pem_x509_certificate(fh.read())

    # Extract renewal parameters from the existing certificate.
    cn_attrs = old_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise PKIError("Certificate has no Common Name — cannot determine renewal parameters.")
    cn      = cn_attrs[0].value
    sans    = _sans_from_cert(old_cert)
    profile = _profile_from_cert(old_cert)
    cdp_url = _cdp_url_from_cert(old_cert)

    if days is None:
        days = _days_from_cert(old_cert)

    if out_dir is None:
        out_dir = os.path.dirname(os.path.abspath(cert_path))

    os.makedirs(out_dir, mode=0o755, exist_ok=True)

    if reuse_key:
        safe_cn      = _safe_filename(cn)
        existing_key = os.path.join(out_dir, "{}-key.pem".format(safe_cn))
        if not os.path.isfile(existing_key):
            raise PKIError(
                "Cannot reuse key: no key file found at {}".format(existing_key)
            )
        with open(existing_key, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
    else:
        key = _generate_key(_key_type_from_public_key(old_cert.public_key()))

    # Capture the old fingerprint NOW, before the cert file is overwritten.
    old_fp  = _cert_fp(old_cert)

    ca_cert = ca.load_cert()
    ca_key  = ca.load_key()

    logger.info(
        "Renewing cert cn=%r profile=%s days=%d reuse_key=%s",
        cn, profile, days, reuse_key,
    )

    # Issue first — if this fails the old cert is still valid and un-revoked.
    result = _issue_cert_with_key(
        ca, ca_cert, ca_key, key, cn, sans, days, profile, cdp_url, out_dir
    )

    # Issue succeeded: now mark the old serial revoked and rebuild the CRL.
    # We cannot call revoke_cert() here because cert_path now contains the
    # NEW certificate.  Inline the two operations using the fingerprint we
    # captured above.
    now_str = _format_dt(_utcnow_naive())
    serial  = ca.serial_db.revoke(old_fp, now_str, "superseded")
    logger.info("Revoked old cert serial=%d reason=superseded", serial)
    generate_crl(ca_dir_path)

    return result


# ---------------------------------------------------------------------------
# CSR signing
# ---------------------------------------------------------------------------

def sign_csr(
    ca_dir_path,            # type: str
    csr_path,               # type: str
    profile="server",       # type: str
    days=365,               # type: int
    extra_sans=None,        # type: Optional[List[str]]
    cdp_url=None,           # type: Optional[str]
    out_dir=None,           # type: Optional[str]
    cn=None,                # type: Optional[str]
):
    # type: (...) -> str
    """
    Sign a PKCS#10 CSR and issue a certificate.

    The private key never enters CRAB — only the public key embedded in the
    CSR is used.  No key file is written.  This is the standard workflow for
    applications that generate their own keys (Go/Rust services, HSM-backed
    keys, multi-team setups where the CA operator should not handle service
    private keys).

    Parameters
    ----------
    ca_dir_path: Path to the issuing CA directory.
    csr_path:    Path to a PEM-format PKCS#10 Certificate Signing Request.
    profile:     Certificate profile — ``server``, ``client``, or
                 ``grid-host``.  The CA applies this regardless of any EKU
                 embedded in the CSR (CA policy takes precedence).
    days:        Validity period in days.
    extra_sans:  Additional SANs to merge with those already in the CSR.
                 Each entry may be prefixed with ``DNS:``, ``IP:``, or
                 ``EMAIL:``.
    cdp_url:     CRL Distribution Point URL to embed in the certificate.
    out_dir:     Output directory (default: ``<ca-dir>/issued/``).
    cn:          Override the Common Name from the CSR.  Required when the
                 CSR has no CN subject attribute.

    Returns
    -------
    cert_path — path to the written PEM certificate.  No key file is
    written; the requester retains the private key.

    Raises
    ------
    PKIError  if the CA or CSR file is not found, the CSR cannot be
              parsed, the self-signature is invalid, no CN can be
              determined, or on I/O errors.
    """
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))

    if profile not in CERT_PROFILES:
        raise PKIError(
            "Unknown profile {!r}. Valid: {}".format(profile, ", ".join(CERT_PROFILES))
        )

    if not os.path.isfile(csr_path):
        raise PKIError("CSR file not found: {}".format(csr_path))

    with open(csr_path, "rb") as fh:
        csr_data = fh.read()

    try:
        csr = x509.load_pem_x509_csr(csr_data)
    except (ValueError, TypeError) as exc:
        raise PKIError("Cannot parse CSR: {}".format(exc))

    if not csr.is_signature_valid:
        raise PKIError(
            "CSR self-signature is invalid — the CSR may have been tampered with."
        )

    # Determine CN: override takes priority, then CSR subject.
    if cn is None:
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs:
            raise PKIError(
                "CSR has no Common Name.  Use --cn to provide one."
            )
        cn = cn_attrs[0].value

    # Collect SANs: CSR extension first, then caller-supplied extras.
    # The CA does not blindly trust what the requester asks for in the CSR
    # SAN extension, but for test/lab PKI it is conventional to honour them.
    csr_sans = []
    try:
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        for gn in san_ext:
            if isinstance(gn, x509.DNSName):
                csr_sans.append("DNS:{}".format(gn.value))
            elif isinstance(gn, x509.IPAddress):
                csr_sans.append("IP:{}".format(str(gn.value)))
            elif isinstance(gn, x509.RFC822Name):
                csr_sans.append("EMAIL:{}".format(gn.value))
    except x509.ExtensionNotFound:
        pass

    all_sans = csr_sans + list(extra_sans or [])

    ca_cert = ca.load_cert()
    ca_key  = ca.load_key()

    if out_dir is None:
        out_dir = ca.issued_dir
    os.makedirs(out_dir, mode=0o755, exist_ok=True)

    logger.info(
        "Signing CSR cn=%r profile=%s days=%d csr=%s",
        cn, profile, days, csr_path,
    )

    return _build_and_record_cert(
        ca, ca_cert, ca_key, csr.public_key(),
        cn, all_sans, days, profile, cdp_url, out_dir,
    )


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

    Keys: ``ca_dir``, ``subject``, ``issuer``, ``is_root``, ``serial``,
    ``not_before``, ``not_after``, ``fingerprint_sha256``, ``key_type``,
    ``path_length``, ``issued_count``, ``revoked_count``, ``crl_exists``,
    ``chain_exists``.
    """
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))

    cert    = ca.load_cert()
    records = ca.serial_db.records()

    # BasicConstraints path_length (None = unconstrained)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        path_length = bc.path_length   # int or None
    except x509.ExtensionNotFound:
        path_length = None

    is_root = cert.subject == cert.issuer

    return {
        "ca_dir":             ca.path,
        "subject":            cert.subject.rfc4514_string(),
        "issuer":             cert.issuer.rfc4514_string(),
        "is_root":            is_root,
        "serial":             str(cert.serial_number),
        "not_before":         _format_date(cert.not_valid_before),
        "not_after":          _format_date(cert.not_valid_after),
        "fingerprint_sha256": _cert_fp(cert),
        "key_type":           _key_type_label(cert.public_key()),
        "path_length":        path_length,
        "issued_count":       len(records),
        "revoked_count":      sum(1 for r in records if r.get("revoked")),
        "crl_exists":         os.path.isfile(ca.crl_path),
        "chain_exists":       os.path.isfile(ca.chain_path),
    }


def list_issued(ca_dir_path):
    # type: (str) -> List[dict]
    """Return all serial-database records for *ca_dir_path*."""
    ca = CADirectory(ca_dir_path)
    if not ca.exists():
        raise PKIError("No CA found in '{}'.".format(ca_dir_path))
    return ca.serial_db.records()
