"""
CRL (Certificate Revocation List) fetching, storage, and freshness validation.

CRL files are named ``<issuer_hash>.r<collision>`` in an OpenSSL CApath
directory — the same hash algorithm is used as for certificate files but
applied to the *issuer* name.

Design:
  - CRL URLs are discovered from two places:
      1. CDP (CRL Distribution Points) extension in each CA certificate.
      2. IGTF ``.info`` files (``crlurl`` key), which may differ from the CDP.
  - Downloaded CRLs are written atomically to a configurable CRL directory
    (may be the same as the cert output directory or a separate path).
  - Freshness is evaluated against the CRL's ``nextUpdate`` field.
"""

import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import List, Optional

logger = logging.getLogger(__name__)

# Default maximum age in hours before a CRL is considered stale
DEFAULT_MAX_AGE_HOURS = 24

# Validated hash filename component pattern
_HASH_RE = re.compile(r"^[0-9a-f]{8}$")

# Pattern for parsing openssl crl -text date output
_DATE_RE = re.compile(r"(\w+\s+\d+\s+[\d:]+\s+\d{4}\s+\w+)")


class CRLInfo:
    """Parsed metadata about a single CRL."""

    __slots__ = (
        "issuer_hash",
        "issuer_dn",
        "this_update",
        "next_update",
        "file_path",
        "source_url",
    )

    def __init__(self, issuer_hash, issuer_dn, this_update, next_update,
                 file_path=None, source_url=None):
        self.issuer_hash = issuer_hash
        self.issuer_dn = issuer_dn
        self.this_update = this_update
        self.next_update = next_update
        self.file_path = file_path
        self.source_url = source_url

    def is_stale(self, max_age_hours=DEFAULT_MAX_AGE_HOURS):
        # type: (int) -> bool
        if self.next_update is None:
            return True
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        return self.this_update < cutoff

    def is_expired(self):
        # type: () -> bool
        if self.next_update is None:
            return True
        return datetime.now(timezone.utc) > self.next_update

    def __repr__(self):
        return "CRLInfo(issuer={!r}, nextUpdate={})".format(
            self.issuer_dn, self.next_update
        )


class CRLManager:
    """
    Fetch and manage CRLs for a set of CA certificates.

    Config keys (from profile → crl block):
        fetch           Whether to fetch CRLs.  Default True.
        crl_path        Directory to store CRL files.
                        Defaults to the profile output_path.
        max_age_hours   CRLs older than this are stale.  Default 24.
        verify_tls      Verify TLS when downloading CRLs.  Default True.
                        **Security note:** only set to false in air-gapped
                        environments with a known-good internal PKI.
        timeout_seconds HTTP fetch timeout.  Default 30.
        sources         ["distribution", "igtf"] — where to look for URLs.
    """

    def __init__(self, crl_config, output_path):
        # type: (dict, str) -> None
        self.fetch = bool(crl_config.get("fetch", True))
        self.crl_path = _safe_abspath(
            crl_config.get("crl_path", output_path), "crl_path"
        )
        self.max_age_hours = int(crl_config.get("max_age_hours", DEFAULT_MAX_AGE_HOURS))
        self.verify_tls = bool(crl_config.get("verify_tls", True))
        self.timeout = int(crl_config.get("timeout_seconds", 30))
        self.sources = crl_config.get("sources", ["distribution", "igtf"])

        if not self.verify_tls:
            logger.warning(
                "CRL TLS verification is DISABLED — only safe for air-gapped "
                "environments with a trusted internal PKI."
            )

    def update_crls(self, cert_infos, dry_run=False):
        # type: (list, bool) -> "CRLUpdateResult"
        """
        Fetch or refresh CRLs for all certificates in *cert_infos*.

        Returns a :class:`CRLUpdateResult` with counts and errors.
        """
        result = CRLUpdateResult()

        if not self.fetch:
            logger.info("CRL fetching disabled; skipping.")
            return result

        if not os.path.exists(self.crl_path):
            if not dry_run:
                os.makedirs(self.crl_path, 0o755)

        for ci in cert_infos:
            urls = self._get_crl_urls(ci)
            if not urls:
                result.missing.append(ci.subject)
                continue

            fetched = False
            for url in urls:
                try:
                    if dry_run:
                        logger.info("[dry-run] Would fetch CRL: %s", url)
                        result.would_fetch.append(url)
                        fetched = True
                        break
                    crl_der = self._fetch_crl(url)
                    issuer_hash = self._get_issuer_hash(ci)
                    self._write_crl(crl_der, issuer_hash)
                    result.updated.append(url)
                    fetched = True
                    logger.debug("Updated CRL for %s from %s", ci.subject, url)
                    break
                except Exception as exc:
                    logger.warning("Failed to fetch CRL from %s: %s", url, exc)
                    result.errors.append("CRL fetch failed for {} ({}): {}".format(
                        ci.subject, url, exc
                    ))

            if not fetched and not dry_run:
                result.failed.append(ci.subject)

        return result

    def validate_crls(self, cert_infos):
        # type: (list) -> List[str]
        """
        Check all CRLs in crl_path for freshness.

        Returns a list of warning strings for missing or stale CRLs.
        """
        warnings = []
        for ci in cert_infos:
            issuer_hash = self._get_issuer_hash(ci)
            crl_file = self._find_crl_file(issuer_hash)
            if crl_file is None:
                warnings.append("Missing CRL for: {}".format(ci.subject))
                continue
            try:
                crl_info = _parse_crl_file(crl_file)
                if crl_info.is_expired():
                    warnings.append("Expired CRL for {}: {}".format(
                        ci.subject, crl_file
                    ))
                elif crl_info.is_stale(self.max_age_hours):
                    warnings.append("Stale CRL for {} (thisUpdate={}): {}".format(
                        ci.subject,
                        crl_info.this_update.strftime("%Y-%m-%d")
                        if crl_info.this_update else "?",
                        crl_file,
                    ))
            except Exception as exc:
                warnings.append("Cannot parse CRL {}: {}".format(crl_file, exc))
        return warnings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_crl_urls(self, ci):
        # type: (...) -> List[str]
        urls = []
        if "distribution" in self.sources:
            urls.extend(ci.crl_distribution_points)
        if "igtf" in self.sources:
            igtf_url = ci.igtf_info.get("crlurl", "")
            if igtf_url and igtf_url not in urls:
                urls.append(igtf_url)
        return urls

    def _get_issuer_hash(self, ci):
        # type: (...) -> str
        from certbundle.rehash import compute_issuer_hash
        return compute_issuer_hash(ci)

    def _fetch_crl(self, url):
        # type: (str) -> bytes
        from certbundle.sources.http import download_to_bytes
        return download_to_bytes(url, verify_tls=self.verify_tls,
                                 timeout=(10, self.timeout))

    def _write_crl(self, crl_der, issuer_hash):
        # type: (bytes, str) -> str
        """Write CRL to <crl_path>/<issuer_hash>.r<n>, returning the path."""
        # Security: validate hash format before using in a path
        if not _HASH_RE.match(issuer_hash):
            raise ValueError(
                "Invalid issuer hash format: {!r}".format(issuer_hash)
            )

        # Convert DER to PEM via openssl if possible
        crl_pem = _der_to_pem_crl(crl_der)

        # Find a free collision index
        idx = 0
        while idx < 100:  # safety cap
            filename = "{}.r{}".format(issuer_hash, idx)
            path = os.path.join(self.crl_path, filename)
            if not os.path.exists(path):
                break
            idx += 1

        # Write atomically
        fd, tmp = tempfile.mkstemp(dir=self.crl_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(crl_pem)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.chmod(path, 0o644)
        return path

    def _find_crl_file(self, issuer_hash):
        # type: (str) -> Optional[str]
        """Return the path to the first CRL file for *issuer_hash*, or None."""
        if not _HASH_RE.match(issuer_hash):
            return None
        for idx in range(10):
            path = os.path.join(self.crl_path, "{}.r{}".format(issuer_hash, idx))
            if os.path.isfile(path):
                return path
        return None


# ---------------------------------------------------------------------------
# CRL format conversion
# ---------------------------------------------------------------------------

def _der_to_pem_crl(data):
    # type: (bytes) -> bytes
    """Convert CRL bytes from DER to PEM format.  Pass-through if already PEM."""
    if data.lstrip().startswith(b"-----"):
        return data  # already PEM
    try:
        result = subprocess.run(
            ["openssl", "crl", "-inform", "DER", "-outform", "PEM"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return data


# ---------------------------------------------------------------------------
# CRL parsing (via openssl)
# ---------------------------------------------------------------------------

def _parse_crl_file(path):
    # type: (str) -> CRLInfo
    """Parse a CRL file (PEM or DER) using openssl crl -text."""
    try:
        result = subprocess.run(
            ["openssl", "crl", "-in", path, "-noout", "-text"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        text = result.stdout.decode("utf-8", errors="replace")
        this_update = _parse_crl_date(text, "Last Update:")
        next_update = _parse_crl_date(text, "Next Update:")
        issuer = _parse_crl_field(text, "Issuer:")
        return CRLInfo(
            issuer_hash="",
            issuer_dn=issuer or "",
            this_update=this_update,
            next_update=next_update,
            file_path=path,
        )
    except Exception as exc:
        raise IOError("Failed to parse CRL {}: {}".format(path, exc))


def _parse_crl_date(text, label):
    # type: (str, str) -> Optional[datetime]
    for line in text.splitlines():
        if label in line:
            m = _DATE_RE.search(line)
            if m:
                try:
                    return datetime.strptime(
                        m.group(1).strip(), "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
    return None


def _parse_crl_field(text, label):
    # type: (str, str) -> Optional[str]
    for line in text.splitlines():
        if label in line:
            parts = line.split(label, 1)
            if len(parts) > 1:
                return parts[1].strip()
    return None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _safe_abspath(path, field_name):
    # type: (str, str) -> str
    """
    Resolve *path* to an absolute path and reject traversal attempts.

    Raises :exc:`ValueError` if the path contains suspicious sequences.
    """
    path = os.path.abspath(os.path.expanduser(path))
    # Normalised abspath should never contain these after expansion
    if ".." in path.split(os.sep):
        raise ValueError(
            "Suspicious path component in {}: {!r}".format(field_name, path)
        )
    return path


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

class CRLUpdateResult:
    """Summary of a :meth:`CRLManager.update_crls` run."""

    __slots__ = ("updated", "failed", "missing", "would_fetch", "errors")

    def __init__(self):
        self.updated = []       # type: List[str]
        self.failed = []        # type: List[str]
        self.missing = []       # type: List[str]
        self.would_fetch = []   # type: List[str]
        self.errors = []        # type: List[str]

    def __repr__(self):
        return "CRLUpdateResult(updated={}, failed={}, missing={})".format(
            len(self.updated), len(self.failed), len(self.missing)
        )
