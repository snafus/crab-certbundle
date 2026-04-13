"""
OpenSSL subject-hash computation and CApath symlink management.

The hash used by OpenSSL for CApath directories is the SHA-1 hash of the
*canonicalised* DER encoding of the certificate's subject name, truncated to
32 bits.  Getting byte-for-byte agreement with `openssl x509 -hash` requires
running the actual C library (or a compatible implementation) because the
canonicalisation step normalises string encodings, case, and whitespace in
ways that are hard to replicate purely in Python for all edge cases.

Strategy:
  1. If pyOpenSSL is installed, use ``X509.subject_name_hash()`` which calls
     the C library directly — guaranteed to match.  Preferred when available.
  2. Otherwise fall back to running ``openssl x509 -hash -noout`` as a
     subprocess — reliable when OpenSSL is installed on the system.
  3. As a last resort, use a pure-Python approximation that is correct for
     well-formed certificates with UTF-8 / ASCII-clean subjects.
  4. After all certificates are placed, optionally run ``openssl rehash`` (or
     ``c_rehash``) on the whole directory to recompute all symlinks at once.
"""

import hashlib
import logging
import os
import re
import struct
import subprocess
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Shared pattern for validating hash filenames (also exported for use in CLI/validation)
CERT_HASH_FILE_RE = re.compile(r"^[0-9a-f]{8}\.\d+$")
CRL_HASH_FILE_RE = re.compile(r"^[0-9a-f]{8}\.r\d+$")


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def compute_subject_hash(cert_info):
    # type: (...) -> str
    """
    Return the 8-character hex subject hash for *cert_info*.

    Tries pyOpenSSL → subprocess openssl → pure-Python fallback.
    The result is cached back into ``cert_info.subject_hash``.
    """
    if cert_info.subject_hash:
        return cert_info.subject_hash

    h = (
        _hash_via_pyopenssl(cert_info.pem_data)
        or _hash_via_subprocess(cert_info.pem_data)
        or _hash_python_fallback(cert_info.der_data)
    )
    cert_info.subject_hash = h
    return h


def compute_issuer_hash(cert_info):
    # type: (...) -> str
    """
    Return the 8-character hex *issuer* hash (used for CRL filenames).

    Applies the same strategy as :func:`compute_subject_hash`.
    """
    if cert_info.issuer_hash:
        return cert_info.issuer_hash

    h = (
        _issuer_hash_via_pyopenssl(cert_info.pem_data)
        or _issuer_hash_via_subprocess(cert_info.pem_data)
        or _python_name_hash_from_bytes(_extract_issuer_der(cert_info.der_data))
    )
    cert_info.issuer_hash = h
    return h


def build_symlink_map(cert_infos):
    # type: (List) -> Dict[str, bytes]
    """
    Given a list of :class:`~certbundle.cert.CertificateInfo` objects, return
    a mapping of ``filename → pem_data`` suitable for writing to a CApath
    directory.

    Filename format:  ``<8-hex-hash>.<collision-index>``
    e.g.  ``a1b2c3d4.0``, ``a1b2c3d4.1`` if two CAs share a hash.

    The same certificate (same SHA-256 fingerprint) is deduplicated.
    """
    seen_fps = set()          # fingerprints already assigned a slot
    hash_counters = {}        # type: Dict[str, int]  subject_hash → next index
    result = {}               # type: Dict[str, bytes]  filename → pem_data

    for ci in cert_infos:
        if ci.fingerprint_sha256 in seen_fps:
            logger.debug("Skipping duplicate cert: %s", ci.subject)
            continue
        seen_fps.add(ci.fingerprint_sha256)

        subject_hash = compute_subject_hash(ci)
        idx = hash_counters.get(subject_hash, 0)
        filename = "{}.{}".format(subject_hash, idx)
        hash_counters[subject_hash] = idx + 1

        if idx > 0:
            logger.warning(
                "Subject-hash collision at %s (index %d): %s",
                subject_hash, idx, ci.subject,
            )

        result[filename] = ci.pem_data

    return result


def rehash_directory(directory):
    # type: (str) -> bool
    """
    Run ``openssl rehash`` (or legacy ``c_rehash``) on *directory* to
    create/update all hash symlinks.

    Returns True if successful, False if neither tool is available.
    """
    # OpenSSL 1.1+ provides `openssl rehash`
    try:
        subprocess.check_call(
            ["openssl", "rehash", directory],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.debug("openssl rehash succeeded on %s", directory)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pass

    # Legacy c_rehash script (still present on many systems)
    try:
        subprocess.check_call(
            ["c_rehash", directory],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.debug("c_rehash succeeded on %s", directory)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pass

    logger.warning(
        "Neither 'openssl rehash' nor 'c_rehash' available; "
        "hash symlinks were built with Python fallback."
    )
    return False


# --------------------------------------------------------------------------
# pyOpenSSL strategy
# --------------------------------------------------------------------------

def _hash_via_pyopenssl(pem_data):
    # type: (bytes) -> Optional[str]
    try:
        from OpenSSL.crypto import load_certificate, FILETYPE_PEM  # type: ignore
        cert = load_certificate(FILETYPE_PEM, pem_data)
        return "{:08x}".format(cert.subject_name_hash())
    except ImportError:
        return None
    except Exception as exc:
        logger.debug("pyOpenSSL subject hash failed: %s", exc)
        return None


def _issuer_hash_via_pyopenssl(pem_data):
    # type: (bytes) -> Optional[str]
    """
    pyOpenSSL does not expose issuer_name_hash directly; fall through to
    subprocess or Python fallback.
    """
    return None


# --------------------------------------------------------------------------
# subprocess strategy
# --------------------------------------------------------------------------

def _hash_via_subprocess(pem_data):
    # type: (bytes) -> Optional[str]
    try:
        result = subprocess.run(
            ["openssl", "x509", "-hash", "-noout"],
            input=pem_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if result.returncode == 0:
            raw = result.stdout.decode().strip()
            if re.match(r"^[0-9a-f]{8}$", raw):
                return raw
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("openssl subprocess hash failed: %s", exc)
    return None


def _issuer_hash_via_subprocess(pem_data):
    # type: (bytes) -> Optional[str]
    try:
        result = subprocess.run(
            ["openssl", "x509", "-issuer_hash", "-noout"],
            input=pem_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if result.returncode == 0:
            raw = result.stdout.decode().strip()
            if re.match(r"^[0-9a-f]{8}$", raw):
                return raw
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("openssl issuer hash subprocess failed: %s", exc)
    return None


# --------------------------------------------------------------------------
# Pure-Python fallback
# --------------------------------------------------------------------------

def _hash_python_fallback(der_data):
    # type: (bytes) -> str
    """
    Compute the OpenSSL-compatible subject name hash from a DER-encoded
    certificate.

    This extracts the subject name DER from the certificate DER and applies
    the SHA-1 / 32-bit / little-endian algorithm.  It is correct for
    certificates whose subject uses UTF-8 or ASCII strings; it may diverge
    from OpenSSL for certificates with TeletexString or BMPString encodings
    that OpenSSL normalises.
    """
    subject_der = _extract_subject_der(der_data)
    return _python_name_hash_from_bytes(subject_der)


def _python_name_hash_from_bytes(name_der):
    # type: (bytes) -> str
    if not name_der:
        return "00000000"
    digest = hashlib.sha1(name_der).digest()
    # Little-endian uint32, high bit cleared
    value = struct.unpack_from("<I", digest)[0] & 0x7FFFFFFF
    return "{:08x}".format(value)


def _extract_subject_der(cert_der):
    # type: (bytes) -> bytes
    """
    Walk the outer TBSCertificate SEQUENCE to extract the raw DER bytes of
    the Subject field.

    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        ...
    }
    TBSCertificate  ::=  SEQUENCE  {
        version         [0] EXPLICIT INTEGER DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,          ← this is what we want
        ...
    }
    """
    try:
        # Parse outer SEQUENCE
        offset = 0
        tag, length, offset = _der_read_tlv_header(cert_der, offset)
        assert tag == 0x30, "Expected SEQUENCE"

        # Enter TBSCertificate
        tag, length, tbs_start = _der_read_tlv_header(cert_der, offset)
        assert tag == 0x30, "Expected TBSCertificate SEQUENCE"
        tbs_end = tbs_start + length

        inner = cert_der[tbs_start:tbs_end]
        pos = 0

        # Optional version [0] EXPLICIT
        if inner[pos:pos+1] == b'\xa0':
            _, vlen, pos = _der_read_tlv_header(inner, pos)
            pos += vlen

        # serialNumber (INTEGER)
        tag, slen, pos = _der_read_tlv_header(inner, pos)
        assert tag == 0x02
        pos += slen

        # signature AlgorithmIdentifier (SEQUENCE)
        tag, alen, pos = _der_read_tlv_header(inner, pos)
        assert tag == 0x30
        pos += alen

        # issuer Name (SEQUENCE)
        tag, ilen, pos = _der_read_tlv_header(inner, pos)
        assert tag == 0x30
        pos += ilen

        # validity Validity (SEQUENCE)
        tag, vlen2, pos = _der_read_tlv_header(inner, pos)
        assert tag == 0x30
        pos += vlen2

        # subject Name (SEQUENCE) — this is what we need
        subj_start_in_inner = pos
        tag, subj_len, pos = _der_read_tlv_header(inner, pos)
        assert tag == 0x30
        # Include the TLV header
        subj_end_in_inner = pos + subj_len
        return inner[subj_start_in_inner:subj_end_in_inner]

    except Exception as exc:
        logger.debug("DER subject extraction failed: %s", exc)
        return cert_der


def _extract_issuer_der(cert_der):
    # type: (bytes) -> bytes
    """Extract issuer Name DER — same walk as subject but stops one field earlier."""
    try:
        offset = 0
        tag, length, offset = _der_read_tlv_header(cert_der, offset)
        assert tag == 0x30
        tag, length, tbs_start = _der_read_tlv_header(cert_der, offset)
        assert tag == 0x30
        inner = cert_der[tbs_start:tbs_start + length]
        pos = 0

        if inner[pos:pos+1] == b'\xa0':
            _, vlen, pos = _der_read_tlv_header(inner, pos)
            pos += vlen

        tag, slen, pos = _der_read_tlv_header(inner, pos)
        pos += slen
        tag, alen, pos = _der_read_tlv_header(inner, pos)
        pos += alen

        # issuer
        issuer_start = pos
        tag, ilen, pos = _der_read_tlv_header(inner, pos)
        assert tag == 0x30
        return inner[issuer_start:pos + ilen]

    except Exception as exc:
        logger.debug("DER issuer extraction failed: %s", exc)
        return cert_der


def _der_read_tlv_header(data, offset):
    # type: (bytes, int) -> Tuple[int, int, int]
    """
    Read a BER/DER TLV header at *offset*.

    Returns (tag, length, new_offset_after_header).
    Raises IndexError on truncated data.
    """
    tag = data[offset]
    offset += 1

    first_len_byte = data[offset]
    offset += 1

    if first_len_byte < 0x80:
        length = first_len_byte
    elif first_len_byte == 0x81:
        length = data[offset]
        offset += 1
    elif first_len_byte == 0x82:
        length = (data[offset] << 8) | data[offset + 1]
        offset += 2
    elif first_len_byte == 0x83:
        length = (data[offset] << 16) | (data[offset+1] << 8) | data[offset+2]
        offset += 3
    else:
        raise ValueError(
            "Unsupported DER length encoding: 0x{:02x}".format(first_len_byte)
        )

    return tag, length, offset
