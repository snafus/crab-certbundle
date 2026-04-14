"""
System CA bundle source.

Loads trust anchors from the operating-system CA bundle by probing a
priority-ordered list of well-known paths.  An explicit ``path`` config
key bypasses auto-detection entirely.

Supported platforms (auto-detection):

    EL / Rocky / RHEL / CentOS / Fedora
        /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
        /etc/pki/tls/certs/ca-bundle.crt
        /etc/pki/tls/cert.pem

    Debian / Ubuntu / Alpine / Arch
        /etc/ssl/certs/ca-certificates.crt

    OpenSUSE / SLES
        /etc/ssl/ca-bundle.pem

    macOS (Homebrew / system OpenSSL symlink)
        /etc/ssl/cert.pem

Config keys:
    path    Optional.  Absolute path to the CA bundle file.  When set,
            auto-detection is skipped entirely.
"""

import logging
import os
from typing import List, Optional

from certbundle.cert import parse_pem_data
from certbundle.sources.base import CertificateSource, SourceResult

logger = logging.getLogger(__name__)

# Paths probed in order; the first one that exists is used.
_CANDIDATE_PATHS = [
    # EL / Rocky / RHEL / CentOS / Fedora (ca-certificates package)
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/tls/cert.pem",
    # Debian / Ubuntu / Alpine / Arch (ca-certificates package)
    "/etc/ssl/certs/ca-certificates.crt",
    # OpenSUSE / SLES
    "/etc/ssl/ca-bundle.pem",
    # macOS (Homebrew openssl / /etc/ssl symlink)
    "/etc/ssl/cert.pem",
    # Generic fallback
    "/etc/ssl/certs/ca-bundle.crt",
]


class SystemSource(CertificateSource):
    """
    Load trust anchors from the operating system's CA bundle.

    Probes well-known trust store paths in priority order and loads the
    first one found.  The ``path`` config key overrides auto-detection.

    Config keys:
        path    Optional.  Override the auto-detected bundle path.
    """

    def load(self):
        # type: () -> SourceResult
        override = self.config.get("path")
        auto_detected = override is None

        if override:
            resolved = os.path.expanduser(override)
        else:
            resolved = _find_system_bundle()

        if resolved is None:
            return SourceResult(
                name=self.name,
                errors=[
                    "SystemSource '{}': could not find a system CA bundle. "
                    "Tried: {}. Set 'path' explicitly if your bundle is "
                    "in a non-standard location.".format(
                        self.name, ", ".join(_CANDIDATE_PATHS)
                    )
                ],
            )

        if not os.path.isfile(resolved):
            return SourceResult(
                name=self.name,
                errors=[
                    "SystemSource '{}': path does not exist: {}".format(
                        self.name, resolved
                    )
                ],
            )

        logger.debug("SystemSource %s: loading from %s (auto=%s)",
                     self.name, resolved, auto_detected)

        try:
            with open(resolved, "rb") as fh:
                data = fh.read()
            certs = parse_pem_data(data, source_name=self.name, source_path=resolved)
        except Exception as exc:
            return SourceResult(
                name=self.name,
                errors=[
                    "SystemSource '{}': cannot read {}: {}".format(
                        self.name, resolved, exc
                    )
                ],
            )

        logger.debug("SystemSource %s: loaded %d cert(s)", self.name, len(certs))
        return SourceResult(
            name=self.name,
            certificates=certs,
            metadata={
                "source_type": "system",
                "path": resolved,
                "cert_count": len(certs),
                "auto_detected": auto_detected,
            },
        )


def _find_system_bundle():
    # type: () -> Optional[str]
    """Return the first candidate bundle path that exists, or None."""
    for path in _CANDIDATE_PATHS:
        if os.path.isfile(path):
            logger.debug("System CA bundle found: %s", path)
            return path
    return None
