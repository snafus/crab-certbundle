"""
Diff and reporting utilities.

Compares two sets of :class:`~certbundle.cert.CertificateInfo` objects (e.g.
the current directory and the newly built one) and produces human-readable or
machine-readable reports describing what changed.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from certbundle.cert import CertificateInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Diff data model
# ---------------------------------------------------------------------------

class CertDiff:
    """Result of comparing two certificate sets."""

    __slots__ = ("added", "removed", "unchanged", "changed")

    def __init__(self):
        self.added = []      # type: List[CertificateInfo]  in new, not in old
        self.removed = []    # type: List[CertificateInfo]  in old, not in new
        self.unchanged = []  # type: List[CertificateInfo]  identical in both
        self.changed = []    # type: List[Tuple[CertificateInfo, CertificateInfo]]  (old, new) same subject

    @property
    def has_changes(self):
        return bool(self.added or self.removed or self.changed)

    def summary(self):
        # type: () -> str
        return "+{} added  -{} removed  ~{} changed  ={} unchanged".format(
            len(self.added), len(self.removed), len(self.changed), len(self.unchanged)
        )

    def __repr__(self):
        return "CertDiff({})".format(self.summary())


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------

def diff_cert_sets(old_certs, new_certs):
    # type: (List[CertificateInfo], List[CertificateInfo]) -> CertDiff
    """
    Compute the difference between *old_certs* and *new_certs*.

    Identity is tracked by SHA-256 fingerprint (exact bytes match) and by
    subject DN (to detect "same CA, new key/certificate" renewals).
    """
    result = CertDiff()

    old_by_fp = {c.fingerprint_sha256: c for c in old_certs}
    new_by_fp = {c.fingerprint_sha256: c for c in new_certs}
    old_by_subject = {c.subject: c for c in old_certs}
    new_by_subject = {c.subject: c for c in new_certs}

    # Unchanged: same fingerprint in both sets
    for fp, cert in new_by_fp.items():
        if fp in old_by_fp:
            result.unchanged.append(cert)
        else:
            result.added.append(cert)

    for fp, cert in old_by_fp.items():
        if fp not in new_by_fp:
            result.removed.append(cert)

    # Changed: same subject but different fingerprint (renewal / re-key)
    # Promote from added/removed lists to changed list
    added_subjects = {c.subject: c for c in result.added}
    removed_subjects = {c.subject: c for c in result.removed}
    for subject in list(added_subjects.keys()):
        if subject in removed_subjects:
            old_cert = removed_subjects[subject]
            new_cert = added_subjects[subject]
            result.changed.append((old_cert, new_cert))
            result.added = [c for c in result.added if c.subject != subject]
            result.removed = [c for c in result.removed if c.subject != subject]

    return result


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_diff_text(diff):
    # type: (CertDiff) -> str
    """Render a :class:`CertDiff` as a human-readable text report."""
    lines = []
    lines.append("Certificate Set Diff")
    lines.append("=" * 60)
    lines.append(diff.summary())
    lines.append("")

    if diff.added:
        lines.append("ADDED ({})".format(len(diff.added)))
        lines.append("-" * 40)
        for c in sorted(diff.added, key=lambda x: x.subject):
            lines.append("  + {}".format(c.subject))
            lines.append("    SHA-256: {}".format(c.fingerprint_sha256[:47] + "..."))
            lines.append("    Expires: {}".format(c.not_after.strftime("%Y-%m-%d")))
            if c.source_name:
                lines.append("    Source:  {}".format(c.source_name))
        lines.append("")

    if diff.removed:
        lines.append("REMOVED ({})".format(len(diff.removed)))
        lines.append("-" * 40)
        for c in sorted(diff.removed, key=lambda x: x.subject):
            lines.append("  - {}".format(c.subject))
            lines.append("    SHA-256: {}".format(c.fingerprint_sha256[:47] + "..."))
        lines.append("")

    if diff.changed:
        lines.append("CHANGED / RENEWED ({})".format(len(diff.changed)))
        lines.append("-" * 40)
        for old_c, new_c in sorted(diff.changed, key=lambda p: p[0].subject):
            lines.append("  ~ {}".format(old_c.subject))
            lines.append("    Old SHA-256: {}".format(old_c.fingerprint_sha256[:47] + "..."))
            lines.append("    New SHA-256: {}".format(new_c.fingerprint_sha256[:47] + "..."))
            lines.append("    Old expires: {}  New expires: {}".format(
                old_c.not_after.strftime("%Y-%m-%d"),
                new_c.not_after.strftime("%Y-%m-%d"),
            ))
        lines.append("")

    return "\n".join(lines)


def render_diff_json(diff):
    # type: (CertDiff) -> str
    """Render a :class:`CertDiff` as a JSON string."""
    def _cert_dict(c):
        return {
            "subject": c.subject,
            "fingerprint_sha256": c.fingerprint_sha256,
            "not_after": c.not_after.isoformat(),
            "source": c.source_name,
            "hash": c.subject_hash,
        }

    data = {
        "summary": {
            "added": len(diff.added),
            "removed": len(diff.removed),
            "changed": len(diff.changed),
            "unchanged": len(diff.unchanged),
        },
        "added": [_cert_dict(c) for c in diff.added],
        "removed": [_cert_dict(c) for c in diff.removed],
        "changed": [
            {"old": _cert_dict(old), "new": _cert_dict(new)}
            for old, new in diff.changed
        ],
    }
    return json.dumps(data, indent=2, default=str)


def render_source_report(source_results, policy_accepted):
    # type: (list, List[CertificateInfo]) -> str
    """
    Render a summary table of all sources and how many certs passed policy.
    """
    lines = ["Source Loading Report", "=" * 60]
    total_loaded = sum(len(sr.certificates) for sr in source_results)
    lines.append("Total loaded:  {}".format(total_loaded))
    lines.append("Policy passed: {}".format(len(policy_accepted)))
    lines.append("")
    lines.append("{:<30} {:>8} {:>8}  {}".format("Source", "Loaded", "Errors", "Type"))
    lines.append("-" * 60)
    for sr in source_results:
        src_type = sr.metadata.get("source_type", "?")
        lines.append("{:<30} {:>8} {:>8}  {}".format(
            sr.name[:30], len(sr.certificates), len(sr.errors), src_type
        ))
        for err in sr.errors:
            lines.append("    ERROR: {}".format(err))
    lines.append("")
    return "\n".join(lines)


def render_inventory(cert_infos, format="text"):
    # type: (List[CertificateInfo], str) -> str
    """
    Render the full certificate inventory as text or JSON.
    """
    if format == "json":
        data = []
        for c in cert_infos:
            data.append({
                "subject": c.subject,
                "issuer": c.issuer,
                "fingerprint_sha256": c.fingerprint_sha256,
                "not_before": c.not_before.isoformat(),
                "not_after": c.not_after.isoformat(),
                "expired": c.is_expired(),
                "is_ca": c.is_ca,
                "subject_hash": c.subject_hash,
                "source": c.source_name,
                "igtf_policy": c.igtf_info.get("policy", ""),
                "igtf_alias": c.igtf_info.get("alias", ""),
            })
        return json.dumps(data, indent=2, default=str)

    # Text format
    lines = [
        "{:<60} {:>10}  {:>10}  {}".format("Subject (truncated)", "NotAfter", "Hash", "Source"),
        "-" * 100,
    ]
    now = datetime.now(timezone.utc)
    for c in sorted(cert_infos, key=lambda x: x.subject):
        expired_flag = " [EXPIRED]" if c.is_expired() else ""
        lines.append("{:<60} {}{}  {}  {}".format(
            c.subject[:60],
            c.not_after.strftime("%Y-%m-%d"),
            expired_flag,
            c.subject_hash or "????????",
            c.source_name or "",
        ))
    return "\n".join(lines)
