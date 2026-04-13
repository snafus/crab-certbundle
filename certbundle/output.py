"""
Output directory builder.

Takes a list of :class:`~certbundle.cert.CertificateInfo` objects that have
passed policy evaluation and writes them to an OpenSSL-compatible CApath
directory::

    <output_dir>/
        a1b2c3d4.0          ← PEM certificate (or symlink to it)
        a1b2c3d4.1          ← collision index 1 for same hash
        e5f6g7h8.0
        ...
        <alias>.pem         ← optional human-readable copy / symlink
        <alias>.info        ← optional IGTF metadata file
        <alias>.signing_policy
        <alias>.namespaces

Atomic replacement is implemented with a staging directory:
  1. Write everything to ``<staging_dir>/``
  2. Rename ``<output_dir>`` to ``<output_dir>.bak`` (if it exists)
  3. Rename ``<staging_dir>`` to ``<output_dir>``
  4. Remove ``<output_dir>.bak``
"""

import logging
import os
import shutil
import stat
from typing import Dict, List, Optional

from certbundle.cert import CertificateInfo
from certbundle.rehash import build_symlink_map, rehash_directory

logger = logging.getLogger(__name__)


class OutputProfile:
    """
    Encapsulates a single output directory rendering run.

    Config keys (from profile block):
        output_path         Required.  Target directory.
        staging_path        Optional.  Staging directory for atomic swap.
                            Defaults to ``<output_path>.staging``.
        atomic              If True (default), use staging + atomic rename.
        rehash              "auto" | "openssl" | "builtin".  Default "auto".
        write_symlinks      If True, write actual files named <hash>.<n> and
                            then run openssl rehash.  If False (legacy mode),
                            write files with hash names directly without
                            relying on symlinks.  Default True.
        include_igtf_meta   Copy IGTF .info / .signing_policy / .namespaces
                            files into the output directory.  Default True.
        file_mode           Octal file permissions for written certs.
                            Default 0o644.
        dir_mode            Octal directory permissions.  Default 0o755.
    """

    def __init__(self, name, profile_config):
        # type: (str, dict) -> None
        self.name = name
        self.output_path = profile_config["output_path"]
        self.staging_path = profile_config.get(
            "staging_path", self.output_path + ".staging"
        )
        self.atomic = bool(profile_config.get("atomic", True))
        self.rehash_mode = profile_config.get("rehash", "auto")
        self.write_symlinks = bool(profile_config.get("write_symlinks", True))
        self.include_igtf_meta = bool(profile_config.get("include_igtf_meta", True))
        self.file_mode = int(str(profile_config.get("file_mode", "0o644")), 8) \
            if isinstance(profile_config.get("file_mode"), str) \
            else profile_config.get("file_mode", 0o644)
        self.dir_mode = int(str(profile_config.get("dir_mode", "0o755")), 8) \
            if isinstance(profile_config.get("dir_mode"), str) \
            else profile_config.get("dir_mode", 0o755)


def build_output(
    cert_infos,     # type: List[CertificateInfo]
    profile,        # type: OutputProfile
    source_results=None,  # type: Optional[list]
    dry_run=False,  # type: bool
):
    # type: (...) -> BuildResult
    """
    Write *cert_infos* to ``profile.output_path`` per the profile settings.

    Returns a :class:`BuildResult` describing what was written.
    """
    result = BuildResult(profile.name, profile.output_path)

    work_dir = profile.staging_path if profile.atomic else profile.output_path

    if dry_run:
        logger.info("[dry-run] Would write %d certs to %s", len(cert_infos), profile.output_path)
        result.cert_count = len(cert_infos)
        return result

    # Ensure the working directory is clean
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir, profile.dir_mode)

    # Build hash → pem map (deduplication + collision handling)
    hash_map = build_symlink_map(cert_infos)

    for filename, pem_data in sorted(hash_map.items()):
        dest = os.path.join(work_dir, filename)
        _write_file(dest, pem_data, profile.file_mode)
        result.files_written.append(filename)
        logger.debug("Wrote %s", dest)

    result.cert_count = len(hash_map)

    # Write IGTF metadata files
    if profile.include_igtf_meta and source_results:
        _write_igtf_meta(work_dir, cert_infos, source_results, profile)

    # Rehash
    rehash_ok = False
    if profile.rehash_mode in ("auto", "openssl"):
        rehash_ok = rehash_directory(work_dir)
    if not rehash_ok and profile.rehash_mode == "openssl":
        logger.error("openssl rehash failed for %s — output may be unusable", work_dir)
        result.errors.append("openssl rehash failed")

    # Atomic swap
    if profile.atomic:
        _atomic_swap(work_dir, profile.output_path)
        logger.info(
            "Built profile '%s': %d certs → %s",
            profile.name, result.cert_count, profile.output_path,
        )
    else:
        logger.info(
            "Built profile '%s' in-place: %d certs → %s",
            profile.name, result.cert_count, profile.output_path,
        )

    return result


# ---------------------------------------------------------------------------
# IGTF metadata writing
# ---------------------------------------------------------------------------

def _write_igtf_meta(work_dir, cert_infos, source_results, profile):
    # type: (...) -> None
    """
    Write IGTF .info / .signing_policy / .namespaces files from source metadata.
    """
    for sr in source_results:
        extra = sr.metadata.get("igtf_extra_files", {})
        for filename, data in extra.items():
            dest = os.path.join(work_dir, filename)
            _write_file(dest, data, profile.file_mode)
            logger.debug("Wrote IGTF meta: %s", dest)

    # Also write per-cert .info files where we have IGTF metadata
    for ci in cert_infos:
        if not ci.igtf_info:
            continue
        alias = ci.igtf_info.get("alias")
        if not alias:
            continue
        info_path = os.path.join(work_dir, alias + ".info")
        lines = ["# Generated by certbundle\n"]
        for k, v in sorted(ci.igtf_info.items()):
            lines.append("{:<16}= {}\n".format(k, v))
        _write_file(info_path, "".join(lines).encode(), profile.file_mode)


# ---------------------------------------------------------------------------
# Atomic directory swap
# ---------------------------------------------------------------------------

def _atomic_swap(staging_dir, output_dir):
    # type: (str, str) -> None
    """
    Atomically replace *output_dir* with *staging_dir*.

    Security: rejects symlinks as output_dir to prevent TOCTOU issues where
    a symlink pointing at a critical directory could be silently replaced.

    Steps:
      1. Rename output_dir → output_dir.bak  (if it exists)
      2. Rename staging_dir → output_dir
      3. Remove output_dir.bak
    """
    # Security: refuse to operate on a symlink as the output target.
    if os.path.islink(output_dir):
        raise ValueError(
            "output_path must not be a symlink (got {!r}). "
            "Configure a real directory path.".format(output_dir)
        )

    backup = output_dir + ".bak"

    # Remove stale backup from previous interrupted run
    if os.path.exists(backup):
        shutil.rmtree(backup)

    parent = os.path.dirname(output_dir) or "."
    if not os.path.exists(parent):
        os.makedirs(parent, 0o755)

    if os.path.exists(output_dir):
        os.rename(output_dir, backup)

    os.rename(staging_dir, output_dir)
    logger.debug("Atomic swap complete: %s → %s (backup removed)", staging_dir, output_dir)

    if os.path.exists(backup):
        shutil.rmtree(backup)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _write_file(path, data, mode):
    # type: (str, bytes, int) -> None
    """Write *data* to *path* with *mode* permissions."""
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, 0o755)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

class BuildResult:
    """Summary of a :func:`build_output` run."""

    __slots__ = ("profile_name", "output_path", "cert_count", "files_written", "errors")

    def __init__(self, profile_name, output_path):
        # type: (str, str) -> None
        self.profile_name = profile_name
        self.output_path = output_path
        self.cert_count = 0
        self.files_written = []   # type: List[str]
        self.errors = []          # type: List[str]

    def __repr__(self):
        return "BuildResult(profile={!r}, certs={}, errors={})".format(
            self.profile_name, self.cert_count, len(self.errors)
        )
