"""
crab.pki_config — declarative PKI hierarchy builder.

Reads a ``pki.yaml`` file and creates the described CA tree and leaf
certificates in a single pass.  Existing CAs are never overwritten
(they would invalidate all previously issued certificates); existing
leaf certificate files are skipped unless ``force_certs=True``.

Schema (all keys except those marked *required* are optional):

.. code-block:: yaml

    version: 1          # *required*

    root:               # *required* — root CA definition
      dir: ./pki/root-ca          # *required*
      cn: "My Root CA"            # *required*
      org: "My Org"
      key_type: ecdsa-p256        # rsa2048 | rsa4096 | ecdsa-p256 | ecdsa-p384 | ed25519
      days: 3650

      intermediates:    # list of intermediate CAs signed by this root
        - dir: ./pki/issuing-ca  # *required*
          cn: "My Issuing CA"    # *required*
          org: "My Org"
          key_type: ecdsa-p256
          days: 1825
          path_length: 0         # max depth below this CA (None = unconstrained)

          certs:         # leaf certificates issued by this CA
            - cn: host.example.com  # *required*
              profile: server       # server | client | grid-host
              days: 365
              key_type: ecdsa-p256  # overrides the issuing CA default
              san:
                - DNS:host.example.com
                - IP:10.0.0.1
              cdp_url: http://crl.example.com/issuing.crl

      certs:            # leaf certificates issued directly by the root CA
        - cn: root-direct.example.com
          profile: server
          days: 365
"""

import logging
import os

import yaml

from crab.pki import (
    CADirectory,
    PKIError,
    _safe_filename,
    init_ca,
    init_intermediate_ca,
    issue_cert,
)

logger = logging.getLogger(__name__)

_DEFAULT_KEY_TYPE      = "ecdsa-p256"
_DEFAULT_ROOT_DAYS     = 3650
_DEFAULT_INTER_DAYS    = 1825
_DEFAULT_CERT_DAYS     = 365
_DEFAULT_CERT_PROFILE  = "server"


# ---------------------------------------------------------------------------
# Config loading and validation
# ---------------------------------------------------------------------------

class PKIConfigError(ValueError):
    """Raised when the PKI config file is invalid."""


def load_pki_config(path):
    # type: (str) -> dict
    """
    Load and lightly validate a PKI hierarchy config file.

    Returns the raw parsed dict.  Raises :class:`PKIConfigError` on
    structural problems.
    """
    try:
        with open(path) as fh:
            raw = yaml.safe_load(fh)
    except (IOError, OSError) as exc:
        raise PKIConfigError("Cannot read PKI config '{}': {}".format(path, exc))
    except yaml.YAMLError as exc:
        raise PKIConfigError("YAML parse error in '{}': {}".format(path, exc))

    if not isinstance(raw, dict):
        raise PKIConfigError("PKI config must be a YAML mapping, got {}".format(type(raw).__name__))

    version = raw.get("version")
    if version not in (1, "1"):
        raise PKIConfigError(
            "PKI config 'version' must be 1 (got {!r})".format(version)
        )

    if "root" not in raw:
        raise PKIConfigError("PKI config must contain a 'root' key")

    _validate_ca_spec(raw["root"], context="root")
    return raw


def _validate_ca_spec(spec, context):
    # type: (dict, str) -> None
    if not isinstance(spec, dict):
        raise PKIConfigError("{}: must be a mapping".format(context))
    for required in ("dir", "cn"):
        if not spec.get(required):
            raise PKIConfigError("{}: missing required key '{}'".format(context, required))
    for inter in spec.get("intermediates", []):
        _validate_ca_spec(inter, context="{}.intermediates[{}]".format(context, inter.get("cn", "?")))
    for cert in spec.get("certs", []):
        if not isinstance(cert, dict) or not cert.get("cn"):
            raise PKIConfigError("{}: each cert must be a mapping with a 'cn' key".format(context))


# ---------------------------------------------------------------------------
# Hierarchy builder
# ---------------------------------------------------------------------------

class BuildResult:
    """Summary of what was created vs skipped during a hierarchy build."""

    def __init__(self):
        self.cas_created   = []   # type: list
        self.cas_skipped   = []   # type: list
        self.certs_issued  = []   # type: list
        self.certs_skipped = []   # type: list
        self.errors        = []   # type: list

    @property
    def ok(self):
        return not self.errors


def build_pki_hierarchy(config_path, force_certs=False, dry_run=False):
    # type: (str, bool, bool) -> BuildResult
    """
    Build (or resume building) a PKI hierarchy described by *config_path*.

    Parameters
    ----------
    config_path:  Path to the YAML config file.
    force_certs:  Re-issue leaf certificates even if they already exist on disk.
                  CA directories are *never* regenerated regardless of this flag
                  (regenerating a CA invalidates all previously issued certs).
    dry_run:      Log what would be done without writing any files.

    Returns
    -------
    :class:`BuildResult` describing what was created and what was skipped.
    """
    config = load_pki_config(config_path)
    result = BuildResult()
    _build_ca_node(
        spec=config["root"],
        parent_ca_dir=None,
        result=result,
        force_certs=force_certs,
        dry_run=dry_run,
    )
    return result


def _build_ca_node(spec, parent_ca_dir, result, force_certs, dry_run):
    # type: (dict, object, BuildResult, bool, bool) -> None
    ca_dir   = spec["dir"]
    cn       = spec["cn"]
    org      = spec.get("org")
    key_type = spec.get("key_type", _DEFAULT_KEY_TYPE)
    is_root  = parent_ca_dir is None
    days     = spec.get("days", _DEFAULT_ROOT_DAYS if is_root else _DEFAULT_INTER_DAYS)

    ca = CADirectory(ca_dir)

    # ── Create the CA ──────────────────────────────────────────────────────
    if ca.exists():
        logger.info("CA already exists, skipping: %s", ca_dir)
        result.cas_skipped.append(cn)
    elif dry_run:
        logger.info("[dry-run] Would %s CA: cn=%r dir=%s",
                    "init root" if is_root else "init intermediate", cn, ca_dir)
        result.cas_created.append(cn)
    else:
        try:
            if is_root:
                logger.info("Creating root CA: cn=%r dir=%s", cn, ca_dir)
                init_ca(ca_dir, cn=cn, org=org, days=days, key_type=key_type)
            else:
                path_length = spec.get("path_length", 0)
                logger.info(
                    "Creating intermediate CA: cn=%r dir=%s parent=%s",
                    cn, ca_dir, parent_ca_dir,
                )
                init_intermediate_ca(
                    ca_dir,
                    parent_ca_dir=parent_ca_dir,
                    cn=cn,
                    org=org,
                    days=days,
                    key_type=key_type,
                    path_length=path_length,
                )
            result.cas_created.append(cn)
        except PKIError as exc:
            result.errors.append("CA '{}': {}".format(cn, exc))
            return  # cannot issue certs from a CA that failed to initialise

    # ── Issue leaf certificates ────────────────────────────────────────────
    issued_dir = os.path.join(ca_dir, "issued")
    for cert_spec in spec.get("certs", []):
        cert_cn    = cert_spec["cn"]
        safe_cn    = _safe_filename(cert_cn)
        cert_path  = os.path.join(issued_dir, "{}-cert.pem".format(safe_cn))

        if os.path.exists(cert_path) and not force_certs:
            logger.info("Cert already exists, skipping: %s", cert_cn)
            result.certs_skipped.append(cert_cn)
            continue

        if dry_run:
            logger.info("[dry-run] Would issue cert: cn=%r from CA %r", cert_cn, cn)
            result.certs_issued.append(cert_cn)
            continue

        try:
            logger.info("Issuing cert: cn=%r from CA %r", cert_cn, cn)
            issue_cert(
                ca_dir,
                cn=cert_cn,
                sans=cert_spec.get("san", []),
                profile=cert_spec.get("profile", _DEFAULT_CERT_PROFILE),
                days=cert_spec.get("days", _DEFAULT_CERT_DAYS),
                key_type=cert_spec.get("key_type", key_type),
                cdp_url=cert_spec.get("cdp_url"),
            )
            result.certs_issued.append(cert_cn)
        except PKIError as exc:
            result.errors.append("Cert '{}': {}".format(cert_cn, exc))

    # ── Recurse into intermediate CAs ─────────────────────────────────────
    for inter_spec in spec.get("intermediates", []):
        _build_ca_node(
            spec=inter_spec,
            parent_ca_dir=ca_dir,
            result=result,
            force_certs=force_certs,
            dry_run=dry_run,
        )
