"""
Configuration loading and validation.

Config files are YAML.  A minimal example::

    version: 1
    sources:
      igtf-classic:
        type: igtf
        path: /etc/grid-security/certificates
    profiles:
      grid:
        sources: [igtf-classic]
        output_path: /etc/grid-security/certificates

See ``examples/config-full.yaml`` for a fully annotated reference.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

SUPPORTED_SOURCE_TYPES = ("igtf", "local")
SUPPORTED_REHASH_MODES = ("auto", "openssl", "builtin")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(path):
    # type: (str) -> "Config"
    """
    Load and validate a YAML config file.

    Raises :exc:`ConfigError` on missing required fields or unknown values.
    """
    if not os.path.isfile(path):
        raise ConfigError("Config file not found: {}".format(path))

    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        raise ConfigError("Config file is empty: {}".format(path))

    return Config(raw, path)


# ---------------------------------------------------------------------------
# Config classes
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised for configuration validation errors."""
    pass


class SourceConfig:
    """Parsed configuration for a single named source."""

    def __init__(self, name, raw):
        # type: (str, dict) -> None
        self.name = name
        self.type = raw.get("type", "")
        if self.type not in SUPPORTED_SOURCE_TYPES:
            raise ConfigError(
                "Source '{}': unsupported type '{}'. Must be one of: {}".format(
                    name, self.type, ", ".join(SUPPORTED_SOURCE_TYPES)
                )
            )
        self.raw = raw  # keep the full dict for source constructors

    def __repr__(self):
        return "SourceConfig(name={!r}, type={!r})".format(self.name, self.type)


class ProfileConfig:
    """Parsed configuration for a single output profile."""

    def __init__(self, name, raw, known_source_names):
        # type: (str, dict, List[str]) -> None
        self.name = name

        if "output_path" not in raw:
            raise ConfigError(
                "Profile '{}': required key 'output_path' is missing".format(name)
            )
        self.output_path = raw["output_path"]
        self.staging_path = raw.get("staging_path", self.output_path + ".staging")
        self.atomic = bool(raw.get("atomic", True))

        self.sources = raw.get("sources", [])
        if not self.sources:
            raise ConfigError(
                "Profile '{}': 'sources' list is empty or missing".format(name)
            )
        for s in self.sources:
            if s not in known_source_names:
                raise ConfigError(
                    "Profile '{}': unknown source '{}'. "
                    "Known sources: {}".format(name, s, ", ".join(known_source_names))
                )

        rehash = raw.get("rehash", "auto")
        if rehash not in SUPPORTED_REHASH_MODES:
            raise ConfigError(
                "Profile '{}': unknown rehash mode '{}'. Must be: {}".format(
                    name, rehash, ", ".join(SUPPORTED_REHASH_MODES)
                )
            )
        self.rehash = rehash

        self.write_symlinks = bool(raw.get("write_symlinks", True))
        self.include_igtf_meta = bool(raw.get("include_igtf_meta", True))
        self.include_crls = bool(raw.get("include_crls", False))
        self.file_mode = raw.get("file_mode", 0o644)
        self.dir_mode = raw.get("dir_mode", 0o755)

        self.policy = raw.get("policy", {})
        self.crl = raw.get("crl", {})

        self.raw = raw

    def as_output_profile_dict(self):
        # type: () -> dict
        """Return a dict suitable for constructing an :class:`~certbundle.output.OutputProfile`."""
        return {
            "output_path": self.output_path,
            "staging_path": self.staging_path,
            "atomic": self.atomic,
            "rehash": self.rehash,
            "write_symlinks": self.write_symlinks,
            "include_igtf_meta": self.include_igtf_meta,
            "file_mode": self.file_mode,
            "dir_mode": self.dir_mode,
        }

    def __repr__(self):
        return "ProfileConfig(name={!r}, output={!r})".format(
            self.name, self.output_path
        )


class Config:
    """
    Fully parsed and validated certbundle configuration.

    Attributes:
        sources   Dict of source name → :class:`SourceConfig`.
        profiles  Dict of profile name → :class:`ProfileConfig`.
        logging   Dict of logging settings.
        refresh   Dict of refresh/schedule settings.
    """

    def __init__(self, raw, path=None):
        # type: (dict, Optional[str]) -> None
        self.path = path

        version = raw.get("version", 1)
        if version != 1:
            raise ConfigError(
                "Unsupported config version {} (supported: 1)".format(version)
            )

        # Sources
        raw_sources = raw.get("sources", {})
        if not isinstance(raw_sources, dict):
            raise ConfigError("'sources' must be a mapping")
        self.sources = {}  # type: Dict[str, SourceConfig]
        for name, src_raw in raw_sources.items():
            if not isinstance(src_raw, dict):
                raise ConfigError("Source '{}' must be a mapping".format(name))
            self.sources[name] = SourceConfig(name, src_raw)

        # Profiles
        raw_profiles = raw.get("profiles", {})
        if not isinstance(raw_profiles, dict):
            raise ConfigError("'profiles' must be a mapping")
        if not raw_profiles:
            raise ConfigError("No profiles defined in config")

        self.profiles = {}  # type: Dict[str, ProfileConfig]
        source_names = list(self.sources.keys())
        for name, prof_raw in raw_profiles.items():
            if not isinstance(prof_raw, dict):
                raise ConfigError("Profile '{}' must be a mapping".format(name))
            self.profiles[name] = ProfileConfig(name, prof_raw, source_names)

        self.logging_config = raw.get("logging", {})
        self.refresh_config = raw.get("refresh", {})

    def get_source(self, name):
        # type: (str) -> SourceConfig
        if name not in self.sources:
            raise KeyError("Unknown source: {}".format(name))
        return self.sources[name]

    def get_profile(self, name):
        # type: (str) -> ProfileConfig
        if name not in self.profiles:
            raise KeyError("Unknown profile: {}".format(name))
        return self.profiles[name]

    def __repr__(self):
        return "Config(sources={}, profiles={}, path={!r})".format(
            list(self.sources.keys()), list(self.profiles.keys()), self.path
        )


# ---------------------------------------------------------------------------
# Source factory
# ---------------------------------------------------------------------------

def build_source(source_config):
    # type: (SourceConfig) -> Any
    """
    Instantiate the appropriate :class:`~certbundle.sources.base.CertificateSource`
    subclass for *source_config*.
    """
    from certbundle.sources.igtf import IGTFSource
    from certbundle.sources.local import LocalSource

    _TYPE_MAP = {
        "igtf": IGTFSource,
        "local": LocalSource,
    }
    cls = _TYPE_MAP[source_config.type]
    return cls(source_config.name, source_config.raw)
