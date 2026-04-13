"""Tests for certbundle.sources.igtf — tarball, URL, and directory loading."""

import io
import os
import tarfile as tarfile_mod
import pytest
from unittest.mock import patch

from certbundle.sources.igtf import (
    IGTFSource,
    _load_tarball,
    _load_url,
    _process_tarfile,
    _process_igtf_entries,
)


# ---------------------------------------------------------------------------
# Helper: build an in-memory .tar.gz
# ---------------------------------------------------------------------------

def _make_tarball(files):
    """Return bytes of a .tar.gz archive containing (member_name, data) pairs."""
    buf = io.BytesIO()
    with tarfile_mod.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files:
            info = tarfile_mod.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _load_tarball
# ---------------------------------------------------------------------------

class TestLoadTarball:
    def test_missing_file_returns_error(self):
        _, _, _, errors = _load_tarball("/no/such/bundle.tar.gz", "test")
        assert errors
        assert "not found" in errors[0]

    def test_loads_pem_cert(self, ca_pem, tmp_path):
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([("test-ca.pem", ca_pem)]))
        certs, _, _, errors = _load_tarball(str(path), "test")
        assert len(certs) == 1
        assert errors == []

    def test_loads_info_file(self, ca_pem, tmp_path):
        info = b"alias = TestCA\npolicy = classic\n"
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([
            ("test-ca.pem", ca_pem),
            ("test-ca.info", info),
        ]))
        _, info_files, _, _ = _load_tarball(str(path), "test")
        assert "test-ca" in info_files
        assert info_files["test-ca"]["policy"] == "classic"

    def test_loads_signing_policy_as_extra(self, ca_pem, tmp_path):
        sp = b"access_id_CA X509:...\ngrantee_groups *\n"
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([
            ("test-ca.pem", ca_pem),
            ("test-ca.signing_policy", sp),
        ]))
        _, _, extra_files, _ = _load_tarball(str(path), "test")
        assert "test-ca.signing_policy" in extra_files
        assert extra_files["test-ca.signing_policy"] == sp

    def test_corrupt_tarball_returns_error(self, tmp_path):
        path = tmp_path / "bad.tar.gz"
        path.write_bytes(b"not a gzip file at all")
        _, _, _, errors = _load_tarball(str(path), "test")
        assert errors
        assert "Failed to open" in errors[0]

    def test_two_certs_both_loaded(self, ca_pem, second_ca_pem, tmp_path):
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([
            ("ca1.pem", ca_pem),
            ("ca2.pem", second_ca_pem),
        ]))
        certs, _, _, errors = _load_tarball(str(path), "test")
        assert len(certs) == 2
        assert errors == []


# ---------------------------------------------------------------------------
# _process_tarfile — security and edge cases
# ---------------------------------------------------------------------------

class TestProcessTarfile:
    def test_hidden_files_skipped(self, ca_pem, tmp_path):
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([(".hidden.pem", ca_pem)]))
        with tarfile_mod.open(str(path), "r:gz") as tf:
            certs, _, _, _ = _process_tarfile(tf, "test")
        assert certs == []

    def test_path_traversal_components_stripped(self, ca_pem, tmp_path):
        # tarball member names with directory components: basename is used
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([("subdir/nested/test-ca.pem", ca_pem)]))
        with tarfile_mod.open(str(path), "r:gz") as tf:
            certs, _, _, _ = _process_tarfile(tf, "test")
        assert len(certs) == 1
        # source_path should be just the basename
        assert certs[0].source_path == "test-ca.pem"

    def test_namespaces_file_stored_as_extra(self, ca_pem, tmp_path):
        ns = b"TO Issuer ...\nSUBJECT ...\n"
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([("test-ca.namespaces", ns)]))
        with tarfile_mod.open(str(path), "r:gz") as tf:
            _, _, extra_files, _ = _process_tarfile(tf, "test")
        assert "test-ca.namespaces" in extra_files

    def test_unrecognised_extension_ignored(self, tmp_path):
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([("README.txt", b"hello")]))
        with tarfile_mod.open(str(path), "r:gz") as tf:
            certs, info_files, extra_files, errors = _process_tarfile(tf, "test")
        assert certs == [] and info_files == {} and extra_files == {} and errors == []


# ---------------------------------------------------------------------------
# _load_url
# ---------------------------------------------------------------------------

class TestLoadUrl:
    def test_download_success_returns_certs(self, ca_pem):
        tarball = _make_tarball([("test-ca.pem", ca_pem)])
        with patch("certbundle.sources.igtf.download_with_cache", return_value=tarball):
            certs, _, _, errors = _load_url("http://example.com/b.tar.gz", "/tmp", "test")
        assert len(certs) == 1
        assert errors == []

    def test_download_failure_returns_error(self):
        with patch("certbundle.sources.igtf.download_with_cache",
                   side_effect=IOError("network error")):
            _, _, _, errors = _load_url("http://example.com/b.tar.gz", "/tmp", "test")
        assert errors
        assert "Failed to download" in errors[0]

    def test_corrupt_tarball_bytes_returns_error(self):
        with patch("certbundle.sources.igtf.download_with_cache",
                   return_value=b"not a tarball"):
            _, _, _, errors = _load_url("http://example.com/b.tar.gz", "/tmp", "test")
        assert errors
        assert "Failed to process" in errors[0]

    def test_info_and_policy_attached(self, ca_pem):
        info = b"alias = MyCA\npolicy = classic\n"
        tarball = _make_tarball([
            ("my-ca.pem", ca_pem),
            ("my-ca.info", info),
        ])
        with patch("certbundle.sources.igtf.download_with_cache", return_value=tarball):
            certs, info_files, _, errors = _load_url(
                "http://example.com/b.tar.gz", "/tmp", "test"
            )
        assert len(certs) == 1
        assert "my-ca" in info_files
        assert errors == []


# ---------------------------------------------------------------------------
# IGTFSource.load() — end-to-end via different backing stores
# ---------------------------------------------------------------------------

class TestIGTFSourceLoad:
    def test_load_from_tarball(self, ca_pem, tmp_path):
        info = b"alias = TestCA\npolicy = classic\n"
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([
            ("test-ca.pem", ca_pem),
            ("test-ca.info", info),
        ]))
        source = IGTFSource("igtf", {"tarball": str(path)})
        result = source.load()
        assert len(result.certificates) == 1
        assert result.errors == []
        assert result.certificates[0].igtf_info["policy"] == "classic"

    def test_load_from_url(self, ca_pem):
        tarball = _make_tarball([("test-ca.pem", ca_pem)])
        with patch("certbundle.sources.igtf.download_with_cache", return_value=tarball):
            source = IGTFSource("igtf", {"url": "http://example.com/b.tar.gz"})
            result = source.load()
        assert len(result.certificates) == 1
        assert result.errors == []

    def test_no_source_config_returns_error(self):
        source = IGTFSource("igtf", {})
        result = source.load()
        assert result.errors
        assert "no 'path'" in result.errors[0]

    def test_missing_tarball_path_returns_error(self):
        source = IGTFSource("igtf", {"tarball": "/no/such/file.tar.gz"})
        result = source.load()
        assert result.errors

    def test_policy_filter_excludes_non_matching(self, ca_pem):
        info = b"alias = TestCA\npolicy = slcs\n"
        tarball = _make_tarball([
            ("test-ca.pem", ca_pem),
            ("test-ca.info", info),
        ])
        with patch("certbundle.sources.igtf.download_with_cache", return_value=tarball):
            source = IGTFSource("igtf", {
                "url": "http://example.com/b.tar.gz",
                "policies": ["classic"],
            })
            result = source.load()
        assert len(result.certificates) == 0  # slcs filtered out

    def test_policy_filter_passes_matching(self, ca_pem):
        info = b"alias = TestCA\npolicy = classic\n"
        tarball = _make_tarball([
            ("test-ca.pem", ca_pem),
            ("test-ca.info", info),
        ])
        with patch("certbundle.sources.igtf.download_with_cache", return_value=tarball):
            source = IGTFSource("igtf", {
                "url": "http://example.com/b.tar.gz",
                "policies": ["classic"],
            })
            result = source.load()
        assert len(result.certificates) == 1

    def test_metadata_includes_cert_count(self, ca_pem, tmp_path):
        path = tmp_path / "bundle.tar.gz"
        path.write_bytes(_make_tarball([("test-ca.pem", ca_pem)]))
        source = IGTFSource("igtf", {"tarball": str(path)})
        result = source.load()
        assert result.metadata["cert_count"] == 1
        assert result.metadata["source_type"] == "igtf"


# ---------------------------------------------------------------------------
# _load_directory — non-file entries and unreadable files
# ---------------------------------------------------------------------------

class TestLoadDirectory:
    def test_subdirectory_skipped(self, ca_pem, tmp_path):
        """Non-file entries (subdirs) in the IGTF directory are skipped silently."""
        from certbundle.sources.igtf import _load_directory
        (tmp_path / "sub").mkdir()
        (tmp_path / "test-ca.pem").write_bytes(ca_pem)
        certs, _, _, errors = _load_directory(str(tmp_path), "test")
        assert len(certs) == 1
        assert errors == []

    def test_unreadable_file_recorded_as_error(self, ca_pem, tmp_path):
        """A file whose open() raises is captured as an error, not a crash."""
        from certbundle.sources.igtf import _load_directory
        (tmp_path / "aaa-good.pem").write_bytes(ca_pem)
        (tmp_path / "zzz-bad.pem").write_bytes(ca_pem)

        real_open = open

        def selective_open(path, *args, **kwargs):
            if "zzz-bad" in str(path):
                raise PermissionError("Permission denied: {}".format(path))
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=selective_open):
            certs, _, _, errors = _load_directory(str(tmp_path), "test")

        assert len(certs) == 1
        assert any("zzz-bad" in e for e in errors)


# ---------------------------------------------------------------------------
# _process_tarfile — directory member and extractfile returning None
# ---------------------------------------------------------------------------

class TestProcessTarfileEdgeCases:
    def test_directory_member_skipped(self, tmp_path):
        """Tarball directory entries (not files) are skipped."""
        buf = io.BytesIO()
        with tarfile_mod.open(fileobj=buf, mode="w:gz") as tf:
            dir_info = tarfile_mod.TarInfo(name="igtf-bundle")
            dir_info.type = tarfile_mod.DIRTYPE
            tf.addfile(dir_info)
        buf.seek(0)
        with tarfile_mod.open(fileobj=buf, mode="r:gz") as tf:
            certs, _, _, errors = _process_tarfile(tf, "test")
        assert certs == [] and errors == []

    def test_extractfile_returns_none_skipped(self, tmp_path):
        """If extractfile() returns None (e.g. for a symlink), the member is skipped."""
        from unittest.mock import MagicMock
        buf = io.BytesIO()
        with tarfile_mod.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile_mod.TarInfo(name="test-ca.pem")
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
        buf.seek(0)
        with tarfile_mod.open(fileobj=buf, mode="r:gz") as tf:
            with patch.object(tf, "extractfile", return_value=None):
                certs, _, _, errors = _process_tarfile(tf, "test")
        assert certs == []

    def test_extractfile_exception_recorded_as_error(self, tmp_path):
        """If extractfile() raises, the error is captured and the member skipped."""
        buf = io.BytesIO()
        with tarfile_mod.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile_mod.TarInfo(name="test-ca.pem")
            info.size = 4
            tf.addfile(info, io.BytesIO(b"data"))
        buf.seek(0)
        with tarfile_mod.open(fileobj=buf, mode="r:gz") as tf:
            with patch.object(tf, "extractfile", side_effect=OSError("read error")):
                certs, _, _, errors = _process_tarfile(tf, "test")
        assert certs == []
        assert errors and "read error" in errors[0]
