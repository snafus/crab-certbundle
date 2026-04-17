"""
crab — OpenSSL-style CA certificate directory builder for research infrastructure.

Combines IGTF trust anchors and public CA roots into hashed CApath directories
compatible with XRootD, dCache clients, curl/OpenSSL consumers, and similar middleware.
"""

__version__ = "0.4.0"
__author__ = "SRCNet Infrastructure"
__license__ = "Apache-2.0"


def _resolve_commit():
    """Return the git commit SHA embedded at install time, or 'unknown'.

    Resolution order:
      1. crab/_commit.py written by setup.py build_py hook (regular installs,
         wheels, and git-archive-based RPM/deb builds).
      2. git subprocess — editable installs (pip install -e .) read the source
         tree directly, where _commit.py still contains the $Format placeholder;
         asking git gives the correct answer in a live clone.
      3. "unknown" fallback.
    """
    try:
        from crab._commit import __commit__ as _c
        if _c and not _c.startswith("$Format:"):
            return _c
    except ImportError:
        pass
    try:
        import os
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            cwd=here,
        ).decode().strip()
    except Exception:
        pass
    return "unknown"


__commit__ = _resolve_commit()

from crab.cert import CertificateInfo, parse_pem_file, parse_pem_data
from crab.config import load_config, Config

__all__ = [
    "__version__",
    "CertificateInfo",
    "parse_pem_file",
    "parse_pem_data",
    "load_config",
    "Config",
]
