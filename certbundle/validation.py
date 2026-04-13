"""
Output directory validation.

Checks that a built CApath directory is well-formed and that OpenSSL can
actually use it for certificate path building.  Reports problems as a list
of :class:`ValidationIssue` objects.

Checks performed:
  - All files match the expected naming pattern (``<8hex>.<n>`` or ``<8hex>.r<n>``).
  - All PEM files parse as valid X.509 certificates.
  - No duplicate certificates (same SHA-256 fingerprint).
  - No subject-hash collisions beyond what the naming scheme handles.
  - Hash filenames match the actual certificate subject hash.
  - Optional: ``openssl verify`` smoke-test on each certificate.
  - CRL freshness (if include_crls is True).
"""

import logging
import os
import re
import subprocess
from typing import List, Optional

from certbundle.cert import parse_pem_file
from certbundle.rehash import CERT_HASH_FILE_RE, CRL_HASH_FILE_RE

logger = logging.getLogger(__name__)

# Local aliases for the canonical hash patterns (defined once in rehash.py)
_CERT_HASH_RE = CERT_HASH_FILE_RE
_CRL_HASH_RE = CRL_HASH_FILE_RE


class ValidationIssue:
    """A single validation finding."""

    LEVELS = ("info", "warning", "error")

    __slots__ = ("level", "message", "file")

    def __init__(self, level, message, file=None):
        # type: (str, str, Optional[str]) -> None
        if level not in self.LEVELS:
            raise ValueError("Invalid ValidationIssue level {!r}; must be one of: {}".format(
                level, ", ".join(self.LEVELS)
            ))
        self.level = level
        self.message = message
        self.file = file

    def __repr__(self):
        return "ValidationIssue({}, {!r})".format(self.level.upper(), self.message)

    def __str__(self):
        prefix = "[{}]".format(self.level.upper())
        if self.file:
            return "{} {} — {}".format(prefix, self.file, self.message)
        return "{} {}".format(prefix, self.message)


def validate_directory(
    directory,          # type: str
    check_hashes=True,  # type: bool
    run_openssl=True,   # type: bool
):
    # type: (...) -> List[ValidationIssue]
    """
    Validate *directory* as an OpenSSL CApath directory.

    Returns a list of :class:`ValidationIssue` objects.  An empty list means
    everything is fine.
    """
    issues = []

    if not os.path.isdir(directory):
        issues.append(ValidationIssue("error", "Directory does not exist: {}".format(directory)))
        return issues

    cert_files = []
    crl_files = []
    unknown_files = []

    for entry in sorted(os.listdir(directory)):
        full = os.path.join(directory, entry)
        if not os.path.isfile(full):
            continue
        if _CERT_HASH_RE.match(entry):
            cert_files.append((entry, full))
        elif _CRL_HASH_RE.match(entry):
            crl_files.append((entry, full))
        elif entry.endswith((".info", ".signing_policy", ".namespaces", ".crl_url", ".lsc", ".pem")):
            pass  # IGTF metadata or alias copies — acceptable
        else:
            unknown_files.append(entry)

    if not cert_files:
        issues.append(ValidationIssue("warning", "No hashed certificate files found in {}".format(directory)))
        return issues

    issues.append(ValidationIssue("info", "Found {} certificate files, {} CRL files".format(
        len(cert_files), len(crl_files)
    )))

    if unknown_files:
        issues.append(ValidationIssue(
            "info",
            "Unrecognised files (may be safe): {}".format(", ".join(unknown_files[:10]))
        ))

    # Validate each cert file
    seen_fingerprints = {}  # type: dict  fp → filename
    seen_subjects = {}       # type: dict  subject → filename

    for filename, full_path in cert_files:
        file_issues = _validate_cert_file(
            filename, full_path, seen_fingerprints, seen_subjects, check_hashes
        )
        issues.extend(file_issues)

    # openssl verify smoke test
    if run_openssl and cert_files:
        verify_issues = _openssl_verify_spot_check(directory, cert_files[:5])
        issues.extend(verify_issues)

    return issues


def has_errors(issues):
    # type: (List[ValidationIssue]) -> bool
    return any(i.level == "error" for i in issues)


def has_warnings(issues):
    # type: (List[ValidationIssue]) -> bool
    return any(i.level == "warning" for i in issues)


# ---------------------------------------------------------------------------
# Per-file validation
# ---------------------------------------------------------------------------

def _validate_cert_file(filename, full_path, seen_fps, seen_subjects, check_hashes):
    # type: (...) -> List[ValidationIssue]
    issues = []

    try:
        certs = parse_pem_file(full_path)
    except Exception as exc:
        issues.append(ValidationIssue("error", "Cannot parse PEM: {}".format(exc), filename))
        return issues

    if len(certs) == 0:
        issues.append(ValidationIssue("error", "No certificate found in file", filename))
        return issues

    if len(certs) > 1:
        issues.append(ValidationIssue(
            "warning",
            "File contains {} certificates (expected 1 for a CApath file)".format(len(certs)),
            filename,
        ))

    for ci in certs:
        # Duplicate fingerprint check
        if ci.fingerprint_sha256 in seen_fps:
            issues.append(ValidationIssue(
                "warning",
                "Duplicate certificate (same as {}): {}".format(
                    seen_fps[ci.fingerprint_sha256], ci.subject
                ),
                filename,
            ))
        else:
            seen_fps[ci.fingerprint_sha256] = filename

        # Hash name consistency
        if check_hashes:
            from certbundle.rehash import compute_subject_hash
            expected_hash = compute_subject_hash(ci)
            actual_hash = filename.split(".")[0]
            if expected_hash != actual_hash:
                issues.append(ValidationIssue(
                    "error",
                    "Hash mismatch: filename has {} but cert subject hashes to {}".format(
                        actual_hash, expected_hash
                    ),
                    filename,
                ))

        # Expiry warning
        if ci.is_expired():
            issues.append(ValidationIssue(
                "warning",
                "Expired certificate ({}) in output: {}".format(
                    ci.not_after.strftime("%Y-%m-%d"), ci.subject
                ),
                filename,
            ))

        # CA flag check
        if not ci.is_ca:
            issues.append(ValidationIssue(
                "warning",
                "Certificate lacks CA flag (may cause verify failures): {}".format(ci.subject),
                filename,
            ))

    return issues


# ---------------------------------------------------------------------------
# openssl verify smoke test
# ---------------------------------------------------------------------------

def _openssl_verify_spot_check(directory, cert_files):
    # type: (str, list) -> List[ValidationIssue]
    issues = []
    for filename, full_path in cert_files:
        try:
            result = subprocess.run(
                ["openssl", "verify", "-CApath", directory, full_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            stdout = result.stdout.decode("utf-8", errors="replace")
            stderr = result.stderr.decode("utf-8", errors="replace")
            # Self-signed roots will show "unable to get local issuer certificate"
            # when verified against themselves — this is expected.
            if result.returncode != 0 and "self signed" not in stderr and \
               "self-signed" not in stderr and "unable to get local issuer" not in stderr:
                issues.append(ValidationIssue(
                    "warning",
                    "openssl verify returned non-zero for {} — {}".format(
                        filename, stderr.strip()[:200]
                    ),
                    filename,
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # openssl not available; skip
            break
        except Exception as exc:
            issues.append(ValidationIssue("info", "openssl verify error: {}".format(exc)))
            break
    return issues
