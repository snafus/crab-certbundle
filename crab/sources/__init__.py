"""Source loaders — IGTF tarballs, local directories, HTTP downloads."""

from crab.sources.base import CertificateSource, SourceResult
from crab.sources.igtf import IGTFSource
from crab.sources.local import LocalSource
from crab.sources.system import SystemSource

__all__ = [
    "CertificateSource", "SourceResult",
    "IGTFSource", "LocalSource", "SystemSource",
    "SOURCE_REGISTRY", "build_source",
]

# ---------------------------------------------------------------------------
# Source registry — single authoritative mapping of type name → class.
# To add a new source type, add one entry here; no other file needs changing.
# ---------------------------------------------------------------------------

SOURCE_REGISTRY = {
    "igtf": IGTFSource,
    "local": LocalSource,
    "system": SystemSource,
}


def build_source(source_config):
    """
    Instantiate the appropriate :class:`CertificateSource` subclass for
    *source_config* (a :class:`~crab.config.SourceConfig`).
    """
    cls = SOURCE_REGISTRY[source_config.type]
    return cls(source_config.name, source_config.raw)
