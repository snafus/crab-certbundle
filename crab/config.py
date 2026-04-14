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

Environment variable interpolation
-----------------------------------
String values in the config may reference environment variables using
``${VAR}`` or ``${VAR:-default}`` syntax::

    sources:
      igtf-online:
        type: igtf
        url: "${IGTF_URL}"
        cache_dir: "${CACHE_DIR:-/var/cache/crab}"

Rules:

* ``${VAR}``          — expand ``$VAR`` from the environment; raise
  :exc:`ConfigError` if the variable is not set.
* ``${VAR:-default}`` — use *default* when ``$VAR`` is unset or empty.
* ``$$``              — literal dollar sign (escape sequence).

Only YAML string scalar values are expanded; keys, integers, booleans,
and lists of non-strings are left unchanged.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

SUPPORTED_SOURCE_TYPES = ("igtf", "local", "system")
SUPPORTED_REHASH_MODES = ("auto", "openssl", "builtin")
_VALID_LOG_LEVELS = frozenset(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(path):
    # type: (str) -> "Config"
    """
    Load and validate a YAML config file.

    Raises :exc:`ConfigError` on missing required fields or unknown values.
    Environment variables in string values are expanded before validation;
    see module docstring for syntax.
    """
    if not os.path.isfile(path):
        raise ConfigError("Config file not found: {}".format(path))

    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        raise ConfigError("Config file is empty: {}".format(path))

    raw = _expand_env_vars(raw)
    return Config(raw, path)


# ---------------------------------------------------------------------------
# Environment variable interpolation
# ---------------------------------------------------------------------------

# Matches ${VAR} and ${VAR:-default}; group 1 = name, group 2 = default (or None)
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


def _expand_env_vars(obj):
    # type: (Any) -> Any
    """
    Recursively expand ``${VAR}`` / ``${VAR:-default}`` in all string values.

    - ``$$`` is converted to a literal ``$`` before variable substitution so
      it is never treated as the start of a reference.
    - Raises :exc:`ConfigError` when a variable is referenced without a
      default and is not set in the environment.
    - Non-string scalars (int, bool, None, …) are returned unchanged.
    - Dict keys are never expanded (only values).
    """
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    if not isinstance(obj, str):
        return obj  # int, bool, None — leave untouched

    # First convert $$ → a placeholder that survives regex substitution,
    # then restore it to a literal $ afterwards.
    _PLACEHOLDER = "\x00DOLLAR\x00"
    text = obj.replace("$$", _PLACEHOLDER)

    errors = []

    def _replace(m):
        name = m.group(1)
        default = m.group(2)  # None when no ":-" clause was present
        value = os.environ.get(name)
        if value is not None:
            return value
        if default is not None:
            return default
        errors.append(name)
        return m.group(0)  # leave as-is; error reported after scan

    result = _ENV_VAR_RE.sub(_replace, text)

    if errors:
        raise ConfigError(
            "Config references undefined environment variable(s): {}. "
            "Set the variable or use ${{VAR:-default}} syntax.".format(
                ", ".join("${{{}}}".format(n) for n in errors)
            )
        )

    return result.replace(_PLACEHOLDER, "$")


# ---------------------------------------------------------------------------
# Config classes
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised for configuration validation errors."""
    pass


def _parse_file_mode(value, profile_name, key):
    # type: (Any, str, str) -> int
    """
    Parse a YAML file-mode value to an integer.

    Accepts bare integers (``0o644`` written as ``420`` in YAML, or loaded
    from a Python literal) and octal-string notation (``"0o644"``).
    YAML does not recognise the ``0o`` prefix as octal; users who write
    ``file_mode: "0o644"`` in their config get the expected result.

    Raises :exc:`ConfigError` on unrecognisable values.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)  # handles "0o644", "0644", "420"
        except ValueError:
            pass
    raise ConfigError(
        "Profile '{}': '{}' must be an integer or octal string like "
        "\"0o644\"; got {!r}".format(profile_name, key, value)
    )


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

        output_format = raw.get("output_format", "capath")
        if output_format not in ("capath", "bundle", "pkcs12"):
            raise ConfigError(
                "Profile '{}': unknown output_format '{}'. "
                "Must be 'capath', 'bundle', or 'pkcs12'".format(
                    name, output_format
                )
            )
        self.output_format = output_format

        # pkcs12_password: empty string → no encryption; use ${VAR} for secrets.
        pkcs12_password = raw.get("pkcs12_password", "")
        if not isinstance(pkcs12_password, str):
            raise ConfigError(
                "Profile '{}': 'pkcs12_password' must be a string".format(name)
            )
        self.pkcs12_password = pkcs12_password

        rehash = raw.get("rehash", "auto")
        if rehash not in SUPPORTED_REHASH_MODES:
            raise ConfigError(
                "Profile '{}': unknown rehash mode '{}'. Must be: {}".format(
                    name, rehash, ", ".join(SUPPORTED_REHASH_MODES)
                )
            )
        self.rehash = rehash

        # staging_path / device check only applies to capath output
        if self.output_format == "capath" and self.atomic:
            _check_staging_device(self.output_path, self.staging_path, name)

        self.description = raw.get("description", "")
        self.annotate_bundle = bool(raw.get("annotate_bundle", True))
        self.write_symlinks = bool(raw.get("write_symlinks", True))
        self.include_igtf_meta = bool(raw.get("include_igtf_meta", True))
        self.include_crls = bool(raw.get("include_crls", False))
        self.file_mode = _parse_file_mode(raw.get("file_mode", 0o644), name, "file_mode")
        self.dir_mode = _parse_file_mode(raw.get("dir_mode", 0o755), name, "dir_mode")

        self.policy = raw.get("policy", {})
        self.crl = raw.get("crl", {})

        self.raw = raw

    def as_output_profile_dict(self):
        # type: () -> dict
        """Return a dict suitable for constructing an :class:`~crab.output.OutputProfile`."""
        return {
            "output_path": self.output_path,
            "staging_path": self.staging_path,
            "atomic": self.atomic,
            "output_format": self.output_format,
            "pkcs12_password": self.pkcs12_password,
            "annotate_bundle": self.annotate_bundle,
            "rehash": self.rehash,
            "write_symlinks": self.write_symlinks,
            "include_igtf_meta": self.include_igtf_meta,
            "file_mode": self.file_mode,
            "dir_mode": self.dir_mode,
        }

    def __repr__(self):
        return "ProfileConfig(name={!r}, output={!r}, description={!r})".format(
            self.name, self.output_path, self.description
        )


class Config:
    """
    Fully parsed and validated crab configuration.

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

        # logging: section — validated here, applied by the CLI after load
        raw_logging = raw.get("logging", {})
        if not isinstance(raw_logging, dict):
            raise ConfigError("'logging' must be a mapping")
        if raw_logging:
            lvl = raw_logging.get("level", "INFO")
            if not isinstance(lvl, str) or lvl.upper() not in _VALID_LOG_LEVELS:
                raise ConfigError(
                    "'logging.level' must be one of {}; got {!r}".format(
                        "/".join(sorted(_VALID_LOG_LEVELS)), lvl
                    )
                )
            log_file = raw_logging.get("file")
            if log_file is not None and not isinstance(log_file, str):
                raise ConfigError("'logging.file' must be a string path")
        self.logging_config = raw_logging

        # refresh: is parsed and reserved for future scheduling support.
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
# Filesystem helpers
# ---------------------------------------------------------------------------

def _nearest_existing_dir(path):
    # type: (str) -> str
    """Return the nearest ancestor of *path* that exists as a directory."""
    path = os.path.abspath(path)
    while True:
        if os.path.isdir(path):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return path  # filesystem root
        path = parent


def _check_staging_device(output_path, staging_path, profile_name):
    # type: (str, str, str) -> None
    """
    Warn if *staging_path* and *output_path* are on different filesystems.

    ``os.rename()`` is only atomic within a single filesystem.  A cross-device
    staging path causes the rename to fail with EXDEV at swap time, which
    would leave the output directory in an inconsistent state.
    """
    try:
        out_dev = os.stat(_nearest_existing_dir(output_path)).st_dev
        stg_dev = os.stat(_nearest_existing_dir(staging_path)).st_dev
        if out_dev != stg_dev:
            logger.warning(
                "Profile '%s': staging_path '%s' is on a different filesystem "
                "from output_path '%s'. The atomic rename will fail at build "
                "time. Set staging_path to a location on the same mount point "
                "as output_path, or set atomic: false.",
                profile_name, staging_path, output_path,
            )
    except OSError:
        pass  # paths may not exist yet; skip silently


# ---------------------------------------------------------------------------
# Source factory
# ---------------------------------------------------------------------------

def _get_type_map():
    # type: () -> dict
    # Deferred import to avoid circular imports at module load time.
    from crab.sources.igtf import IGTFSource
    from crab.sources.local import LocalSource
    from crab.sources.system import SystemSource
    return {
        "igtf": IGTFSource,
        "local": LocalSource,
        "system": SystemSource,
    }


def build_source(source_config):
    # type: (SourceConfig) -> Any
    """
    Instantiate the appropriate :class:`~crab.sources.base.CertificateSource`
    subclass for *source_config*.
    """
    cls = _get_type_map()[source_config.type]
    return cls(source_config.name, source_config.raw)
