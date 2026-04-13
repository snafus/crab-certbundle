"""Tests for source loaders — local and IGTF."""

import os
import tarfile
import io
import pytest

from certbundle.sources.local import LocalSource
from certbundle.sources.igtf import IGTFSource, _parse_info_file


class TestLocalSource:
    def test_loads_directory(self, pem_dir, ca_pem, second_ca_pem):
        src = LocalSource("test-local", {"path": pem_dir})
        result = src.load()
        assert len(result.certificates) == 2
        assert len(result.errors) == 0

    def test_loads_single_file(self, tmp_path, ca_pem):
        path = str(tmp_path / "ca.pem")
        with open(path, "wb") as fh:
            fh.write(ca_pem)
        src = LocalSource("single", {"path": path})
        result = src.load()
        assert len(result.certificates) == 1

    def test_loads_bundle_file(self, tmp_path, bundle_pem):
        path = str(tmp_path / "bundle.pem")
        with open(path, "wb") as fh:
            fh.write(bundle_pem)
        src = LocalSource("bundle", {"path": path})
        result = src.load()
        assert len(result.certificates) == 2

    def test_missing_path_error(self, tmp_path):
        src = LocalSource("missing", {"path": str(tmp_path / "does-not-exist")})
        result = src.load()
        assert len(result.errors) > 0

    def test_no_path_configured(self):
        src = LocalSource("no-path", {})
        result = src.load()
        assert len(result.errors) > 0

    def test_pattern_filtering(self, tmp_path, ca_pem):
        (tmp_path / "good.pem").write_bytes(ca_pem)
        (tmp_path / "bad.txt").write_bytes(ca_pem)
        src = LocalSource("test", {"path": str(tmp_path), "pattern": "*.pem"})
        result = src.load()
        assert len(result.certificates) == 1

    def test_source_name_propagated(self, pem_dir):
        src = LocalSource("my-name", {"path": pem_dir})
        result = src.load()
        assert all(c.source_name == "my-name" for c in result.certificates)

    def test_metadata_has_source_type(self, pem_dir):
        src = LocalSource("t", {"path": pem_dir})
        result = src.load()
        assert result.metadata.get("source_type") == "local"


class TestIGTFSource:
    def test_loads_directory(self, igtf_dir):
        src = IGTFSource("igtf-test", {"path": igtf_dir})
        result = src.load()
        assert len(result.certificates) >= 1
        assert len(result.errors) == 0

    def test_igtf_info_attached(self, igtf_dir):
        src = IGTFSource("igtf-test", {"path": igtf_dir})
        result = src.load()
        ci = result.certificates[0]
        assert ci.igtf_info.get("alias") == "TestCA"
        assert ci.igtf_info.get("policy") == "classic"

    def test_policy_filter_accept(self, igtf_dir):
        src = IGTFSource("igtf-test", {"path": igtf_dir, "policies": ["classic"]})
        result = src.load()
        assert len(result.certificates) >= 1

    def test_policy_filter_reject(self, igtf_dir):
        src = IGTFSource("igtf-test", {"path": igtf_dir, "policies": ["slcs"]})
        result = src.load()
        assert len(result.certificates) == 0

    def test_missing_path_error(self, tmp_path):
        src = IGTFSource("igtf-test", {"path": str(tmp_path / "nope")})
        result = src.load()
        assert len(result.errors) > 0

    def test_loads_tarball(self, tmp_path, ca_pem):
        # Build a minimal tarball
        tgz_path = str(tmp_path / "bundle.tar.gz")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("bundle/TestCA.pem")
            info.size = len(ca_pem)
            tf.addfile(info, io.BytesIO(ca_pem))
            igtf_info = b"alias = TestCA\npolicy = classic\n"
            info2 = tarfile.TarInfo("bundle/TestCA.info")
            info2.size = len(igtf_info)
            tf.addfile(info2, io.BytesIO(igtf_info))
        buf.seek(0)
        with open(tgz_path, "wb") as fh:
            fh.write(buf.read())

        src = IGTFSource("igtf-tgz", {"tarball": tgz_path})
        result = src.load()
        assert len(result.certificates) >= 1
        assert result.certificates[0].igtf_info.get("alias") == "TestCA"

    def test_no_config_error(self):
        src = IGTFSource("igtf-bad", {})
        result = src.load()
        assert len(result.errors) > 0

    def test_extra_files_in_metadata(self, igtf_dir):
        src = IGTFSource("igtf-test", {"path": igtf_dir})
        result = src.load()
        extra = result.metadata.get("igtf_extra_files", {})
        assert any(".signing_policy" in k for k in extra.keys())


class TestParseInfoFile:
    def test_basic_parsing(self):
        text = "alias = TestCA\npolicy = classic\nstatus = operational\n"
        result = _parse_info_file(text)
        assert result["alias"] == "TestCA"
        assert result["policy"] == "classic"

    def test_comments_ignored(self):
        text = "# comment\nalias = TestCA\n"
        result = _parse_info_file(text)
        assert "alias" in result
        assert len(result) == 1

    def test_empty_file(self):
        assert _parse_info_file("") == {}

    def test_extra_whitespace(self):
        text = "alias     =    TestCA   \n"
        result = _parse_info_file(text)
        assert result["alias"] == "TestCA"

    def test_value_with_equals(self):
        text = "subjectdn = /C=GB/O=Test/CN=Test CA\n"
        result = _parse_info_file(text)
        assert result["subjectdn"] == "/C=GB/O=Test/CN=Test CA"
