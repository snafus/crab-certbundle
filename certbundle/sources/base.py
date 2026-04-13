"""
Abstract base class for certificate sources.

All source implementations must return a :class:`SourceResult` so that the
pipeline has a uniform interface regardless of where certificates came from.
"""

import abc
import logging
from typing import Dict, List, Optional

from certbundle.cert import CertificateInfo

logger = logging.getLogger(__name__)


class SourceResult:
    """
    The product of loading one source.

    Attributes:
        name:         Logical source name from config.
        certificates: All certificates found in this source (unfiltered).
        metadata:     Arbitrary key-value metadata (version, timestamp, …).
        errors:       Non-fatal problems encountered during loading.
    """

    __slots__ = ("name", "certificates", "metadata", "errors")

    def __init__(
        self,
        name,               # type: str
        certificates=None,  # type: Optional[List[CertificateInfo]]
        metadata=None,      # type: Optional[Dict]
        errors=None,        # type: Optional[List[str]]
    ):
        self.name = name
        self.certificates = certificates if certificates is not None else []
        self.metadata = metadata or {}
        self.errors = errors or []

    def __repr__(self):
        return "SourceResult(name={!r}, certs={}, errors={})".format(
            self.name, len(self.certificates), len(self.errors)
        )


class CertificateSource(abc.ABC):
    """
    Abstract base for certificate sources.

    Subclasses implement :meth:`load`, which reads certificates from their
    respective backing store and returns a :class:`SourceResult`.
    """

    def __init__(self, name, config):
        # type: (str, dict) -> None
        self.name = name
        self.config = config

    @abc.abstractmethod
    def load(self):
        # type: () -> SourceResult
        """Load and return all certificates from this source."""

    def __repr__(self):
        return "{}(name={!r})".format(self.__class__.__name__, self.name)
