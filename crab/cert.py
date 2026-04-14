"""
Certificate data model and PEM parsing utilities.

Provides CertificateInfo — the canonical in-memory representation of a single
X.509 certificate — and helpers to load PEM files/bundles.
"""

import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

logger = logging.getLogger(__name__)

# Regex to extract individual PEM blocks from a bundle
_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----",
    re.DOTALL,
)


class CertificateInfo:
    """
    Parsed X.509 certificate with all metadata needed for policy decisions,
    output rendering, and reporting.

    Attributes are intentionally public — this is a data carrier, not a
    behaviour-rich object.
    """

    __slots__ = (
        "pem_data",
        "der_data",
        "subject",
        "issuer",
        "fingerprint_sha256",
        "fingerprint_sha1",
        "not_before",
        "not_after",
        "is_ca",
        "path_len",
        "serial_number",
        "subject_hash",       # computed lazily, may be None until rehash runs
        "issuer_hash",        # for CRL linkage
        "source_name",
        "source_path",
        "key_usage",
        "extended_key_usage",
        "crl_distribution_points",
        "aia_issuer_urls",
        "igtf_info",          # parsed .info file content, if any
        "metadata",           # arbitrary extra metadata dict
    )

    def __init__(
        self,
        pem_data,               # type: bytes
        der_data,               # type: bytes
        subject,                # type: str
        issuer,                 # type: str
        fingerprint_sha256,     # type: str
        fingerprint_sha1,       # type: str
        not_before,             # type: datetime
        not_after,              # type: datetime
        is_ca,                  # type: bool
        path_len,               # type: Optional[int]
        serial_number,          # type: int
        key_usage,              # type: List[str]
        extended_key_usage,     # type: List[str]
        crl_distribution_points, # type: List[str]
        aia_issuer_urls,        # type: List[str]
        subject_hash=None,      # type: Optional[str]
        issuer_hash=None,       # type: Optional[str]
        source_name=None,       # type: Optional[str]
        source_path=None,       # type: Optional[str]
        igtf_info=None,         # type: Optional[Dict[str, str]]
        metadata=None,          # type: Optional[Dict[str, str]]
    ):
        self.pem_data = pem_data
        self.der_data = der_data
        self.subject = subject
        self.issuer = issuer
        self.fingerprint_sha256 = fingerprint_sha256
        self.fingerprint_sha1 = fingerprint_sha1
        self.not_before = not_before
        self.not_after = not_after
        self.is_ca = is_ca
        self.path_len = path_len
        self.serial_number = serial_number
        self.key_usage = key_usage
        self.extended_key_usage = extended_key_usage
        self.crl_distribution_points = crl_distribution_points
        self.aia_issuer_urls = aia_issuer_urls
        self.subject_hash = subject_hash
        self.issuer_hash = issuer_hash
        self.source_name = source_name
        self.source_path = source_path
        self.igtf_info = igtf_info or {}
        self.metadata = metadata or {}

    # ------------------------------------------------------------------
    # Convenience predicates
    # ------------------------------------------------------------------

    def is_expired(self):
        # type: () -> bool
        """Return True if the certificate's notAfter is in the past."""
        return datetime.now(timezone.utc) > self.not_after

    def is_self_signed(self):
        # type: () -> bool
        """Return True when subject == issuer (root CA heuristic)."""
        return self.subject == self.issuer

    def has_server_auth_eku(self):
        # type: () -> bool
        """Return True if the id-kp-serverAuth EKU is present."""
        return "serverAuth" in self.extended_key_usage

    def has_client_auth_eku(self):
        # type: () -> bool
        """Return True if the id-kp-clientAuth EKU is present."""
        return "clientAuth" in self.extended_key_usage

    # ------------------------------------------------------------------
    # Identity / hashing
    # ------------------------------------------------------------------

    def __eq__(self, other):
        if not isinstance(other, CertificateInfo):
            return NotImplemented
        return self.fingerprint_sha256 == other.fingerprint_sha256

    def __hash__(self):
        return hash(self.fingerprint_sha256)

    def __repr__(self):
        return "CertificateInfo(subject={!r}, hash={}, expired={})".format(
            self.subject, self.subject_hash or "?", self.is_expired()
        )


# ---------------------------------------------------------------------------
# PEM parsing
# ---------------------------------------------------------------------------

def parse_pem_data(
    pem_data,       # type: bytes
    source_name=None,  # type: Optional[str]
    source_path=None,  # type: Optional[str]
):
    # type: (...) -> List[CertificateInfo]
    """
    Parse one or more PEM-encoded certificates from *pem_data*.

    A bundle file (multiple certificates concatenated) is fully unwrapped;
    each block becomes one :class:`CertificateInfo`.  Blocks that fail to
    parse are logged and skipped.

    Returns a list (possibly empty).
    """
    results = []
    for block in _PEM_CERT_RE.finditer(pem_data):
        block_bytes = block.group(0)
        try:
            info = _parse_single_pem_block(block_bytes, source_name, source_path)
            results.append(info)
        except Exception as exc:
            logger.warning(
                "Skipping unparseable PEM block from %s: %s",
                source_path or source_name or "<unknown>",
                exc,
            )
    return results


def parse_pem_file(path, source_name=None):
    # type: (str, Optional[str]) -> List[CertificateInfo]
    """
    Load and parse all PEM certificates from *path*.

    The *source_name* label is stored in each :class:`CertificateInfo` so
    downstream reporting can attribute certificates to their origin.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise OSError("Cannot read certificate file {}: {}".format(path, exc))
    return parse_pem_data(data, source_name=source_name, source_path=path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_single_pem_block(pem_block, source_name, source_path):
    # type: (bytes, Optional[str], Optional[str]) -> CertificateInfo
    """Parse a single PEM block (must contain exactly one certificate)."""
    backend = default_backend()
    cert = x509.load_pem_x509_certificate(pem_block, backend)

    der_data = cert.public_bytes(serialization.Encoding.DER)
    subject = _name_to_string(cert.subject)
    issuer = _name_to_string(cert.issuer)

    fp_sha256 = _fingerprint(cert, hashes.SHA256())
    fp_sha1 = _fingerprint(cert, hashes.SHA1())

    # cryptography >= 42.0 exposes UTC-aware datetimes directly;
    # older versions return naive datetimes that we make aware.
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = _aware_dt(cert.not_valid_before)
        not_after = _aware_dt(cert.not_valid_after)

    is_ca, path_len = _extract_basic_constraints(cert)
    key_usage = _extract_key_usage(cert)
    eku = _extract_eku(cert)
    cdps = _extract_crl_distribution_points(cert)
    aia_issuers = _extract_aia_issuers(cert)

    return CertificateInfo(
        pem_data=pem_block,
        der_data=der_data,
        subject=subject,
        issuer=issuer,
        fingerprint_sha256=fp_sha256,
        fingerprint_sha1=fp_sha1,
        not_before=not_before,
        not_after=not_after,
        is_ca=is_ca,
        path_len=path_len,
        serial_number=cert.serial_number,
        key_usage=key_usage,
        extended_key_usage=eku,
        crl_distribution_points=cdps,
        aia_issuer_urls=aia_issuers,
        source_name=source_name,
        source_path=source_path,
    )


def _aware_dt(dt):
    # type: (datetime) -> datetime
    """Ensure a datetime is timezone-aware (UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _fingerprint(cert, algorithm):
    # type: (x509.Certificate, hashes.HashAlgorithm) -> str
    """Return a colon-delimited hex fingerprint string."""
    raw = cert.fingerprint(algorithm)
    return ":".join("{:02X}".format(b) for b in raw)


def _name_to_string(name):
    # type: (x509.Name) -> str
    """
    Render an x509.Name as an RFC2253-style /C=.../O=.../CN=... string.

    The slash-delimited format matches what OpenSSL prints for grid software.
    """
    parts = []
    for attr in name:
        try:
            oid_short = _OID_SHORT.get(attr.oid.dotted_string, attr.oid.dotted_string)
            parts.append("{}={}".format(oid_short, attr.value))
        except Exception:
            pass
    return "/" + "/".join(parts) if parts else "/"


# Short names for common DN attribute OIDs
_OID_SHORT = {
    NameOID.COUNTRY_NAME.dotted_string: "C",
    NameOID.STATE_OR_PROVINCE_NAME.dotted_string: "ST",
    NameOID.LOCALITY_NAME.dotted_string: "L",
    NameOID.ORGANIZATION_NAME.dotted_string: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string: "OU",
    NameOID.COMMON_NAME.dotted_string: "CN",
    NameOID.EMAIL_ADDRESS.dotted_string: "emailAddress",
    NameOID.DOMAIN_COMPONENT.dotted_string: "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}


def _extract_basic_constraints(cert):
    # type: (x509.Certificate) -> Tuple[bool, Optional[int]]
    """Return (is_ca, path_len) from BasicConstraints; default is_ca=False."""
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return bc.value.ca, bc.value.path_length
    except ExtensionNotFound:
        pass
    # Fallback: v1 certificates without BasicConstraints are treated as non-CA
    # unless the certificate is self-signed and has no extensions at all,
    # which was common for old root CAs.
    if cert.version == x509.Version.v1 and _is_raw_self_signed(cert):
        return True, None
    return False, None


def _is_raw_self_signed(cert):
    # type: (x509.Certificate) -> bool
    try:
        return cert.subject == cert.issuer
    except Exception:
        return False


def _extract_key_usage(cert):
    # type: (x509.Certificate) -> List[str]
    usages = []
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        for attr in (
            "digital_signature", "content_commitment", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
            "encipher_only", "decipher_only",
        ):
            try:
                if getattr(ku, attr, False):
                    usages.append(attr)
            except (ValueError, TypeError):
                # KeyUsage raises ValueError for encipher_only/decipher_only
                # when key_agreement is False
                pass
    except ExtensionNotFound:
        pass
    return usages


_EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSPSigning",
}


def _extract_eku(cert):
    # type: (x509.Certificate) -> List[str]
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        result = []
        for oid in eku.value:
            result.append(_EKU_NAMES.get(oid.dotted_string, oid.dotted_string))
        return result
    except ExtensionNotFound:
        return []


def _extract_crl_distribution_points(cert):
    # type: (x509.Certificate) -> List[str]
    urls = []
    try:
        cdp_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        for dp in cdp_ext.value:
            if dp.full_name:
                for gn in dp.full_name:
                    if isinstance(gn, x509.UniformResourceIdentifier):
                        urls.append(gn.value)
    except ExtensionNotFound:
        pass
    return urls


def _extract_aia_issuers(cert):
    # type: (x509.Certificate) -> List[str]
    urls = []
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for ad in aia.value:
            if ad.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":  # caIssuers
                if isinstance(ad.access_location, x509.UniformResourceIdentifier):
                    urls.append(ad.access_location.value)
    except ExtensionNotFound:
        pass
    return urls
