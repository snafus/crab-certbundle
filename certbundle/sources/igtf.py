"""
IGTF trust anchor source.

Supports two input modes:

1. **Directory** — a directory that already contains extracted IGTF CA files
   (``*.pem``, ``*.info``, ``*.signing_policy``, ``*.namespaces``).

2. **Tarball** — a ``.tar.gz`` file (local path or HTTP URL) such as the
   IGTF preinstalled bundles distributed at dl.igtf.net.

The IGTF .info file format is a simple key = value text file, e.g.::

    alias           = CERN-Root-2
    subjectdn       = /DC=ch/DC=cern/CN=CERN Root Certification Authority 2
    issuerdn        = /DC=ch/DC=cern/CN=CERN Root Certification Authority 2
    crlurl          = http://crl.cern.ch/crl/CERNRootCertificationAuthority2.crl
    url             = https://cafiles.cern.ch/cafiles/
    status          = operational
    version         = 1.89
    policy          = classic
"""

import fnmatch
import io
import logging
import os
import re
import tarfile
import tempfile
from typing import Dict, List, Optional, Tuple

from certbundle.cert import CertificateInfo, parse_pem_data
from certbundle.sources.base import CertificateSource, SourceResult
from certbundle.sources.http import download_with_cache

logger = logging.getLogger(__name__)

# IGTF policy distributions recognised
IGTF_POLICIES = frozenset(["classic", "iota", "mics", "slcs", "experimental"])


class IGTFSource(CertificateSource):
    """
    Load IGTF trust anchors from a tarball (local or HTTP) or directory.

    Config keys:
        path        Local directory of already-extracted files.
        tarball     Local path to a .tar.gz bundle.
        url         HTTP(S) URL of a .tar.gz bundle (downloaded to cache).
        cache_dir   Directory for downloaded tarballs (default: /tmp).
        policies    List of IGTF policy tags to accept (default: all).
    """

    def load(self):
        # type: () -> SourceResult
        errors = []
        raw_certs = []
        info_files = {}     # type: Dict[str, Dict[str, str]]  basename → info
        extra_files = {}    # type: Dict[str, bytes]  basename → raw bytes

        # Resolve the backing store
        if "path" in self.config:
            raw_certs, info_files, extra_files, errs = _load_directory(
                self.config["path"], self.name
            )
            errors.extend(errs)

        elif "tarball" in self.config:
            raw_certs, info_files, extra_files, errs = _load_tarball(
                self.config["tarball"], self.name
            )
            errors.extend(errs)

        elif "url" in self.config:
            cache_dir = self.config.get("cache_dir", tempfile.gettempdir())
            cache_ttl_days = int(self.config.get("cache_ttl_days", 30))
            cache_pinned = bool(self.config.get("cache_pinned", False))
            raw_certs, info_files, extra_files, errs = _load_url(
                self.config["url"], cache_dir, self.name,
                cache_ttl_days=cache_ttl_days,
                cache_pinned=cache_pinned,
            )
            errors.extend(errs)

        else:
            errors.append(
                "IGTFSource '{}': no 'path', 'tarball', or 'url' configured".format(
                    self.name
                )
            )

        # Attach parsed .info metadata to the matching CertificateInfo
        policy_filter = self.config.get("policies", None)
        accepted = []
        for ci in raw_certs:
            # Find matching .info by basename of source_path
            basename = None
            if ci.source_path:
                basename = os.path.splitext(os.path.basename(ci.source_path))[0]

            info_data = {}
            if basename and basename in info_files:
                info_data = info_files[basename]
                # Annotate certificate with all IGTF metadata
                ci.igtf_info = info_data

            # Policy filtering
            if policy_filter:
                cert_policy = info_data.get("policy", "").strip().lower()
                if cert_policy and cert_policy not in policy_filter:
                    logger.debug(
                        "Skipping cert with policy=%s (not in filter %s): %s",
                        cert_policy, policy_filter, ci.subject,
                    )
                    continue

            accepted.append(ci)

        metadata = {
            "source_type": "igtf",
            "cert_count": len(accepted),
            "info_files": len(info_files),
            "extra_files_keys": list(extra_files.keys()),
        }

        # Pass extra files (signing_policy, namespaces, crl_url) through metadata
        # so the output module can optionally copy them
        metadata["igtf_extra_files"] = extra_files

        return SourceResult(
            name=self.name,
            certificates=accepted,
            metadata=metadata,
            errors=errors,
        )


# ---------------------------------------------------------------------------
# Shared entry processor
# ---------------------------------------------------------------------------

def _process_igtf_entries(entries, source_name):
    # type: (List[Tuple[str, str, bytes]], str) -> Tuple[List[CertificateInfo], Dict, Dict, List[str]]
    """Classify and parse a sequence of (basename, source_path, data) file entries.

    Used by both the directory and tarball loaders to avoid duplicating the
    extension-dispatch logic.
    """
    certs = []
    info_files = {}     # type: Dict[str, Dict[str, str]]
    extra_files = {}    # type: Dict[str, bytes]
    errors = []

    for name, source_path, data in entries:
        ext = os.path.splitext(name)[1].lower()
        stem = os.path.splitext(name)[0]

        if ext == ".pem":
            try:
                parsed = parse_pem_data(data, source_name=source_name, source_path=source_path)
                certs.extend(parsed)
            except Exception as exc:
                errors.append("Error parsing PEM {}: {}".format(source_path, exc))

        elif ext == ".info":
            try:
                info_files[stem] = _parse_info_file(data.decode("utf-8", errors="replace"))
            except Exception as exc:
                errors.append("Error parsing info {}: {}".format(source_path, exc))

        elif ext in (".signing_policy", ".namespaces", ".crl_url", ".lsc"):
            extra_files[name] = data

    return certs, info_files, extra_files, errors


# ---------------------------------------------------------------------------
# Directory loader
# ---------------------------------------------------------------------------

def _load_directory(directory, source_name):
    # type: (str, str) -> Tuple[List[CertificateInfo], Dict, Dict, List[str]]
    errors = []

    if not os.path.isdir(directory):
        errors.append("IGTF directory not found: {}".format(directory))
        return [], {}, {}, errors

    entries = []
    for entry in sorted(os.listdir(directory)):
        full = os.path.join(directory, entry)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            errors.append("Error reading {}: {}".format(full, exc))
            continue
        entries.append((entry, full, data))

    certs, info_files, extra_files, errs = _process_igtf_entries(entries, source_name)
    errors.extend(errs)
    return certs, info_files, extra_files, errors


# ---------------------------------------------------------------------------
# Tarball loader
# ---------------------------------------------------------------------------

def _load_tarball(tarball_path, source_name):
    # type: (str, str) -> Tuple[List[CertificateInfo], Dict, Dict, List[str]]
    certs = []
    info_files = {}
    extra_files = {}
    errors = []

    if not os.path.isfile(tarball_path):
        errors.append("IGTF tarball not found: {}".format(tarball_path))
        return certs, info_files, extra_files, errors

    try:
        with tarfile.open(tarball_path, "r:gz") as tf:
            certs, info_files, extra_files, errs = _process_tarfile(tf, source_name)
            errors.extend(errs)
    except Exception as exc:
        errors.append("Failed to open tarball {}: {}".format(tarball_path, exc))

    return certs, info_files, extra_files, errors


def _load_url(url, cache_dir, source_name, cache_ttl_days=30, cache_pinned=False):
    # type: (str, str, str, int, bool) -> Tuple[List[CertificateInfo], Dict, Dict, List[str]]
    errors = []
    try:
        tarball_data = download_with_cache(
            url, cache_dir,
            cache_ttl_days=cache_ttl_days,
            cache_pinned=cache_pinned,
        )
    except Exception as exc:
        errors.append("Failed to download {}: {}".format(url, exc))
        return [], {}, {}, errors

    try:
        fobj = io.BytesIO(tarball_data)
        with tarfile.open(fileobj=fobj, mode="r:gz") as tf:
            certs, info_files, extra_files, errs = _process_tarfile(tf, source_name)
            errors.extend(errs)
        return certs, info_files, extra_files, errors
    except Exception as exc:
        errors.append("Failed to process downloaded tarball from {}: {}".format(url, exc))
        return [], {}, {}, errors


def _process_tarfile(tf, source_name):
    # type: (tarfile.TarFile, str) -> Tuple[List[CertificateInfo], Dict, Dict, List[str]]
    entries = []
    errors = []

    for member in tf.getmembers():
        if not member.isfile():
            continue

        # Security: use os.path.basename() to strip all directory components,
        # including absolute paths (/etc/passwd) and Windows UNC paths.
        # This prevents path traversal during tarball extraction.
        name = os.path.basename(member.name)
        if not name or name.startswith("."):
            continue  # skip directory entries and hidden files

        try:
            fobj = tf.extractfile(member)
            if fobj is None:
                continue
            data = fobj.read()
        except Exception as exc:
            errors.append("Error reading tarball member {}: {}".format(member.name, exc))
            continue

        entries.append((name, name, data))

    certs, info_files, extra_files, errs = _process_igtf_entries(entries, source_name)
    errors.extend(errs)
    return certs, info_files, extra_files, errors


# ---------------------------------------------------------------------------
# .info file parser
# ---------------------------------------------------------------------------

_INFO_LINE_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*)$")


def _parse_info_file(text):
    # type: (str) -> Dict[str, str]
    """Parse an IGTF-style ``key = value`` info file."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _INFO_LINE_RE.match(line)
        if m:
            result[m.group(1).lower()] = m.group(2).strip()
    return result
