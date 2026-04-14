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

import ctypes
import ctypes.util
import errno as _errno
import logging
import os
import platform as _platform
import shutil
import stat
import tempfile
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
        output_format = profile_config.get("output_format", "capath")
        if output_format not in ("capath", "bundle"):
            raise ValueError(
                "Unknown output_format {!r}; must be 'capath' or 'bundle'".format(
                    output_format
                )
            )
        self.output_format = output_format
        self.annotate_bundle = bool(profile_config.get("annotate_bundle", True))
        self.rehash_mode = profile_config.get("rehash", "auto")
        self.write_symlinks = bool(profile_config.get("write_symlinks", True))
        self.include_igtf_meta = bool(profile_config.get("include_igtf_meta", True))
        self.file_mode = int(profile_config.get("file_mode", 0o644))
        self.dir_mode = int(profile_config.get("dir_mode", 0o755))


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
    if profile.output_format == "bundle":
        return _build_bundle(cert_infos, profile, dry_run=dry_run)

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
# Bundle (single-file) output
# ---------------------------------------------------------------------------

def _cert_annotation(ci):
    # type: (CertificateInfo) -> bytes
    """
    Return a block of ``#``-prefixed comment lines describing *ci*.

    Written immediately before the PEM block in annotated bundles.
    Comments in PEM files are ignored by OpenSSL, curl, Python ssl,
    and all other consumers that follow RFC 7468 / OpenSSL conventions.
    """
    lines = []
    lines.append("# Subject:  {}".format(ci.subject or "(unknown)"))
    if ci.issuer and ci.issuer != ci.subject:
        lines.append("# Issuer:   {}".format(ci.issuer))
    if ci.not_after:
        lines.append("# Expires:  {}".format(ci.not_after.strftime("%Y-%m-%d")))
    if ci.source_name:
        lines.append("# Source:   {}".format(ci.source_name))
    if ci.igtf_info and ci.igtf_info.get("alias"):
        lines.append("# Alias:    {}".format(ci.igtf_info["alias"]))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _build_bundle(cert_infos, profile, dry_run=False):
    # type: (List[CertificateInfo], OutputProfile, bool) -> BuildResult
    """
    Write all *cert_infos* as a single concatenated PEM file to
    ``profile.output_path``, replacing any existing file atomically.
    """
    result = BuildResult(profile.name, profile.output_path)

    # Deduplicate by fingerprint; sort for deterministic output
    seen = set()   # type: set
    ordered = []
    for ci in sorted(cert_infos, key=lambda c: c.fingerprint_sha256 or ""):
        fp = ci.fingerprint_sha256
        if fp in seen:
            continue
        seen.add(fp)
        ordered.append(ci)

    result.cert_count = len(ordered)

    if dry_run:
        logger.info(
            "[dry-run] Would write bundle of %d certs to %s",
            result.cert_count, profile.output_path,
        )
        return result

    # Concatenate PEM blocks, optionally preceded by human-readable annotations
    parts = []
    for ci in ordered:
        if profile.annotate_bundle:
            parts.append(_cert_annotation(ci))
        parts.append(ci.pem_data)
        if not ci.pem_data.endswith(b"\n"):
            parts.append(b"\n")
    bundle_data = b"".join(parts)

    # Ensure parent directory exists
    parent = os.path.dirname(os.path.abspath(profile.output_path))
    if not os.path.isdir(parent):
        os.makedirs(parent, profile.dir_mode)

    # Guard: refuse to overwrite a directory with a file
    if os.path.isdir(profile.output_path):
        raise ValueError(
            "output_path {!r} is a directory; cannot write bundle file there. "
            "Remove the directory or choose a different path.".format(
                profile.output_path
            )
        )

    # Atomic write via temp file in same directory (guarantees same filesystem)
    fd, tmp = tempfile.mkstemp(dir=parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(bundle_data)
        os.chmod(tmp, profile.file_mode)
        os.replace(tmp, profile.output_path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    result.files_written.append(os.path.basename(profile.output_path))
    logger.info(
        "Built bundle profile '%s': %d certs → %s",
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
# renameat2(RENAME_EXCHANGE) — truly atomic directory swap on Linux >= 3.15
# ---------------------------------------------------------------------------

_AT_FDCWD = -100
_RENAME_EXCHANGE = 2  # (1 << 1) from linux/fs.h

# SYS_renameat2 numbers for each Linux architecture.
# Reference: linux/arch/*/include/uapi/asm/unistd*.h
_RENAMEAT2_NR = {
    "x86_64":  316,
    "i386":    353,
    "i686":    353,
    "aarch64": 276,
    "arm":     382,
    "armv7l":  382,
    "ppc64":   357,
    "ppc64le": 357,
    "s390x":   347,
}


def _try_renameat2_exchange(src, dst):
    # type: (str, str) -> bool
    """
    Attempt an atomic directory exchange via renameat2(RENAME_EXCHANGE).

    If successful, *src* and *dst* swap their directory-entry contents
    simultaneously — there is no instant where either path is absent.

    Returns True on success.  Returns False without raising if the syscall
    is unavailable (old kernel, non-Linux, unknown arch); the caller should
    fall back to a two-rename swap.

    Precondition: both *src* and *dst* must already exist and be on the
    same filesystem.
    """
    if _platform.system() != "Linux":
        return False

    nr = _RENAMEAT2_NR.get(_platform.machine())
    if nr is None:
        return False

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return False

    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
        ret = libc.syscall(
            ctypes.c_long(nr),
            ctypes.c_int(_AT_FDCWD),
            ctypes.c_char_p(src.encode()),
            ctypes.c_int(_AT_FDCWD),
            ctypes.c_char_p(dst.encode()),
            ctypes.c_uint(_RENAME_EXCHANGE),
        )
        if ret == 0:
            return True
        err = ctypes.get_errno()
        # ENOSYS → kernel too old; EINVAL → flags not supported; EXDEV → cross-device
        if err not in (_errno.ENOSYS, _errno.EINVAL, _errno.EXDEV):
            logger.warning(
                "renameat2(RENAME_EXCHANGE) failed: errno %d (%s)",
                err, os.strerror(err),
            )
        return False
    except Exception as exc:
        logger.debug("renameat2 unavailable: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Atomic directory swap
# ---------------------------------------------------------------------------

def _atomic_swap(staging_dir, output_dir):
    # type: (str, str) -> None
    """
    Replace *output_dir* with *staging_dir* as atomically as possible.

    Security: rejects symlinks as output_dir to prevent TOCTOU issues where
    a symlink pointing at a critical directory could be silently replaced.

    Strategy (in order of preference):
      1. renameat2(RENAME_EXCHANGE) — Linux >= 3.15, same filesystem.
         output_dir and staging_dir swap instantaneously; no gap where
         the path is absent.  Old content lands in staging_dir and is
         removed afterwards.
      2. Two-rename fallback — universally portable but has a ~microsecond
         window between the two renames where output_dir does not exist.
         Acceptable for all known research-infrastructure consumers.
    """
    # Security: refuse to operate on a symlink as the output target.
    if os.path.islink(output_dir):
        raise ValueError(
            "output_path must not be a symlink (got {!r}). "
            "Configure a real directory path.".format(output_dir)
        )

    parent = os.path.dirname(output_dir) or "."
    if not os.path.exists(parent):
        os.makedirs(parent, 0o755)

    # ── Strategy 1: atomic exchange ──────────────────────────────────────
    if os.path.exists(output_dir):
        if _try_renameat2_exchange(staging_dir, output_dir):
            # staging_dir now holds the old content; remove it at leisure.
            shutil.rmtree(staging_dir)
            logger.debug("Atomic swap complete (renameat2 EXCHANGE): %s", output_dir)
            return

    # ── Strategy 2: two-rename fallback ──────────────────────────────────
    backup = output_dir + ".bak"
    if os.path.exists(backup):
        shutil.rmtree(backup)

    if os.path.exists(output_dir):
        os.rename(output_dir, backup)

    os.rename(staging_dir, output_dir)
    logger.debug("Atomic swap complete (rename fallback): %s", output_dir)

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
