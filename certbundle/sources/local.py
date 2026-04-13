"""
Local directory / file source.

Loads PEM certificates from:
  - a single PEM file (may be a bundle of multiple certs)
  - a directory of PEM files (optionally with glob pattern filtering)
  - the system CA bundle (e.g. /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem)
"""

import fnmatch
import logging
import os
from typing import List

from certbundle.cert import parse_pem_data, parse_pem_file
from certbundle.sources.base import CertificateSource, SourceResult

logger = logging.getLogger(__name__)

# Default glob patterns for recognising PEM files inside a directory
DEFAULT_PEM_PATTERNS = ("*.pem", "*.crt", "*.cer")


class LocalSource(CertificateSource):
    """
    Load trust anchors from a local directory or file.

    Config keys:
        path      Required.  Path to a directory or a single PEM/bundle file.
        pattern   Glob pattern(s) for filename matching within a directory.
                  Accepts a string or a list of strings.
                  Default: ``["*.pem", "*.crt", "*.cer"]``.
        recursive Whether to recurse into subdirectories (default: False).
    """

    def load(self):
        # type: () -> SourceResult
        path = self.config.get("path", "")
        if not path:
            return SourceResult(
                name=self.name,
                errors=["LocalSource '{}': no 'path' configured".format(self.name)],
            )

        path = os.path.expanduser(path)
        errors = []
        certs = []

        if os.path.isfile(path):
            certs, errs = _load_single_file(path, self.name)
            errors.extend(errs)

        elif os.path.isdir(path):
            patterns_raw = self.config.get("pattern", list(DEFAULT_PEM_PATTERNS))
            if isinstance(patterns_raw, str):
                patterns = [patterns_raw]
            else:
                patterns = list(patterns_raw)
            recursive = bool(self.config.get("recursive", False))
            certs, errs = _load_directory(path, patterns, recursive, self.name)
            errors.extend(errs)

        else:
            errors.append(
                "LocalSource '{}': path does not exist: {}".format(self.name, path)
            )

        return SourceResult(
            name=self.name,
            certificates=certs,
            metadata={"source_type": "local", "path": path, "cert_count": len(certs)},
            errors=errors,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_single_file(path, source_name):
    # type: (str, str) -> tuple
    errors = []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        certs = parse_pem_data(data, source_name=source_name, source_path=path)
        logger.debug("LocalSource %s: loaded %d cert(s) from %s", source_name, len(certs), path)
        return certs, errors
    except Exception as exc:
        errors.append("Cannot read {}: {}".format(path, exc))
        return [], errors


def _load_directory(directory, patterns, recursive, source_name):
    # type: (str, list, bool, str) -> tuple
    errors = []
    all_certs = []

    walker = os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]

    for dirpath, _dirs, filenames in walker:
        for filename in sorted(filenames):
            if not _matches_any(filename, patterns):
                continue
            full_path = os.path.join(dirpath, filename)
            try:
                with open(full_path, "rb") as fh:
                    data = fh.read()
                certs = parse_pem_data(data, source_name=source_name, source_path=full_path)
                all_certs.extend(certs)
            except Exception as exc:
                errors.append("Cannot read {}: {}".format(full_path, exc))

    logger.debug(
        "LocalSource %s: loaded %d cert(s) from directory %s",
        source_name, len(all_certs), directory,
    )
    return all_certs, errors


def _matches_any(filename, patterns):
    # type: (str, list) -> bool
    return any(fnmatch.fnmatch(filename, p) for p in patterns)
