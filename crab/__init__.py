"""
crab — OpenSSL-style CA certificate directory builder for research infrastructure.

Combines IGTF trust anchors and public CA roots into hashed CApath directories
compatible with XRootD, dCache clients, curl/OpenSSL consumers, and similar middleware.
"""

__version__ = "0.1.0"
__author__ = "SRCNet Infrastructure"
__license__ = "Apache-2.0"

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
