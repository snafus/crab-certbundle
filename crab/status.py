"""
Profile output-directory health summary for ``crabctl status``.

Reads the output directory of a built profile without network access and
returns a :class:`ProfileStatus` describing cert counts, expiry, and CRL
freshness.  Designed to be fast: it only parses files already on disk.
"""

import datetime
import logging
import os
from typing import List, Optional

from crab.rehash import CERT_HASH_FILE_RE, CRL_HASH_FILE_RE

logger = logging.getLogger(__name__)

# Certs expiring within this many days are flagged as "expiring soon"
EXPIRING_SOON_DAYS = 30


class ProfileStatus:
    """Health snapshot for a single profile output directory."""

    __slots__ = (
        "profile_name",
        "output_path",
        "exists",
        "cert_count",
        "expired_count",
        "expiring_soon_count",
        "earliest_expiry",       # datetime or None
        "earliest_expiry_cn",    # subject of the soonest-expiring cert, or None
        "crl_count",
        "stale_crl_warnings",    # list of warning strings from CRLManager.validate_crls
        "last_built",            # datetime (mtime of output dir) or None
        "errors",                # list of error strings (unreadable files, etc.)
    )

    def __init__(self, profile_name, output_path):
        self.profile_name = profile_name
        self.output_path = output_path
        self.exists = False
        self.cert_count = 0
        self.expired_count = 0
        self.expiring_soon_count = 0
        self.earliest_expiry = None     # type: Optional[datetime.datetime]
        self.earliest_expiry_cn = None  # type: Optional[str]
        self.crl_count = 0
        self.stale_crl_warnings = []    # type: List[str]
        self.last_built = None          # type: Optional[datetime.datetime]
        self.errors = []                # type: List[str]

    @property
    def healthy(self):
        # type: () -> bool
        return (
            self.exists
            and self.cert_count > 0
            and self.expired_count == 0
            and not self.stale_crl_warnings
            and not self.errors
        )

    def to_dict(self):
        # type: () -> dict
        """Serialise to a plain dict suitable for JSON output."""
        def _dt(d):
            return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None

        return {
            "profile": self.profile_name,
            "output_path": self.output_path,
            "exists": self.exists,
            "cert_count": self.cert_count,
            "expired_count": self.expired_count,
            "expiring_soon_count": self.expiring_soon_count,
            "earliest_expiry": _dt(self.earliest_expiry),
            "earliest_expiry_cn": self.earliest_expiry_cn,
            "crl_count": self.crl_count,
            "crl_warnings": self.stale_crl_warnings,
            "last_built": _dt(self.last_built),
            "healthy": self.healthy,
            "errors": self.errors,
        }


def collect_status(profile_name, profile_cfg, cert_infos=None):
    # type: (str, object, Optional[list]) -> ProfileStatus
    """
    Collect status for one profile.

    :param profile_name: Profile name (for display).
    :param profile_cfg:  A :class:`~crab.config.ProfileConfig` instance.
    :param cert_infos:   Pre-loaded certs (to check CRL freshness); if *None*
                         CRL validation is skipped.
    """
    output_path = profile_cfg.output_path
    ps = ProfileStatus(profile_name, output_path)

    if not os.path.isdir(output_path):
        return ps

    ps.exists = True

    # Directory mtime ≈ last build time
    try:
        mtime = os.path.getmtime(output_path)
        ps.last_built = datetime.datetime.utcfromtimestamp(mtime).replace(
            tzinfo=datetime.timezone.utc
        )
    except OSError:
        pass

    # Scan files
    cert_files = []
    crl_files = []
    for entry in os.listdir(output_path):
        full = os.path.join(output_path, entry)
        if not os.path.isfile(full):
            continue
        if CERT_HASH_FILE_RE.match(entry):
            cert_files.append(full)
        elif CRL_HASH_FILE_RE.match(entry):
            crl_files.append(full)

    ps.crl_count = len(crl_files)

    # Parse cert files for expiry info
    now = datetime.datetime.now(datetime.timezone.utc)
    expiry_threshold = now + datetime.timedelta(days=EXPIRING_SOON_DAYS)

    from crab.cert import parse_pem_file
    for fpath in cert_files:
        try:
            certs = parse_pem_file(fpath)
            for ci in certs:
                ps.cert_count += 1
                na = ci.not_after
                if na is None:
                    continue
                # Ensure timezone-aware
                if na.tzinfo is None:
                    na = na.replace(tzinfo=datetime.timezone.utc)
                if na < now:
                    ps.expired_count += 1
                elif na < expiry_threshold:
                    ps.expiring_soon_count += 1
                if ps.earliest_expiry is None or na < ps.earliest_expiry:
                    ps.earliest_expiry = na
                    ps.earliest_expiry_cn = ci.subject
        except Exception as exc:
            logger.debug("Could not parse cert file %s: %s", fpath, exc)
            ps.errors.append("Cannot read {}: {}".format(fpath, exc))

    # CRL freshness — requires cert_infos and include_crls
    if cert_infos is not None and getattr(profile_cfg, "include_crls", False):
        try:
            from crab.crl import CRLManager
            crl_mgr = CRLManager(profile_cfg.crl, profile_cfg.output_path)
            ps.stale_crl_warnings = crl_mgr.validate_crls(cert_infos)
        except Exception as exc:
            logger.debug("CRL validation error for profile %s: %s", profile_name, exc)
            ps.errors.append("CRL check failed: {}".format(exc))

    return ps


def render_status_text(statuses):
    # type: (List[ProfileStatus]) -> str
    """Render a list of :class:`ProfileStatus` objects as human-readable text."""
    lines = []
    for ps in statuses:
        lines.append("Profile: {}".format(ps.profile_name))
        lines.append("  Output path  : {}".format(ps.output_path))
        if not ps.exists:
            lines.append("  Status       : MISSING (directory does not exist)")
            lines.append("")
            continue
        lines.append("  Last built   : {}".format(
            ps.last_built.strftime("%Y-%m-%d %H:%M:%S UTC") if ps.last_built else "unknown"
        ))
        lines.append("  Certificates : {}".format(ps.cert_count))
        if ps.expired_count:
            lines.append("  Expired      : {} [!]".format(ps.expired_count))
        if ps.expiring_soon_count:
            lines.append(
                "  Expiring <{}d : {}".format(EXPIRING_SOON_DAYS, ps.expiring_soon_count)
            )
        if ps.earliest_expiry:
            lines.append("  Earliest exp : {} ({})".format(
                ps.earliest_expiry.strftime("%Y-%m-%d"),
                ps.earliest_expiry_cn or "?",
            ))
        if ps.crl_count:
            lines.append("  CRL files    : {}".format(ps.crl_count))
        if ps.stale_crl_warnings:
            for w in ps.stale_crl_warnings:
                lines.append("  CRL warning  : {}".format(w))
        for e in ps.errors:
            lines.append("  Error        : {}".format(e))
        lines.append(
            "  Status       : {}".format("OK" if ps.healthy else "DEGRADED")
        )
        lines.append("")
    return "\n".join(lines).rstrip()
