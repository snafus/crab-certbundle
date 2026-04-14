"""Tests for certbundle.output — directory building and atomic replacement."""

import os
import re
import sys
import pytest
from unittest.mock import patch, MagicMock

from certbundle.cert import parse_pem_data
from certbundle.output import (
    OutputProfile, build_output, BuildResult,
    _atomic_swap, _try_renameat2_exchange, _build_bundle, _cert_annotation,
    _write_igtf_meta, _write_file,
)
from certbundle.sources.base import SourceResult


def _make_profile(tmp_path, name="test", atomic=False, rehash="builtin"):
    output_path = str(tmp_path / "output" / name)
    staging_path = str(tmp_path / "staging" / name)
    return OutputProfile(
        name,
        {
            "output_path": output_path,
            "staging_path": staging_path,
            "atomic": atomic,
            "rehash": rehash,
            "include_igtf_meta": False,
        },
    )


class TestBuildOutput:
    def test_creates_output_directory(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path)
        result = build_output(certs, profile)
        assert os.path.isdir(profile.output_path)

    def test_writes_hashed_files(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path)
        result = build_output(certs, profile)
        entries = os.listdir(profile.output_path)
        hash_files = [e for e in entries if re.match(r"^[0-9a-f]{8}\.\d+$", e)]
        assert len(hash_files) == 1

    def test_cert_count_in_result(self, tmp_path, ca_pem, second_ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        profile = _make_profile(tmp_path)
        result = build_output(certs, profile)
        assert result.cert_count == 2

    def test_dry_run_does_not_write(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path)
        build_output(certs, profile, dry_run=True)
        assert not os.path.exists(profile.output_path)

    def test_idempotent_rebuild(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path)
        r1 = build_output(certs, profile)
        r2 = build_output(certs, profile)
        assert r1.cert_count == r2.cert_count

    def test_deduplicates_certs(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path)
        result = build_output(certs, profile)
        assert result.cert_count == 1

    def test_file_permissions(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path)
        build_output(certs, profile)
        for entry in os.listdir(profile.output_path):
            if re.match(r"^[0-9a-f]{8}\.\d+$", entry):
                full = os.path.join(profile.output_path, entry)
                mode = oct(os.stat(full).st_mode & 0o777)
                assert mode == oct(0o644)

    def test_returns_build_result(self, tmp_path, ca_pem):
        profile = _make_profile(tmp_path)
        result = build_output(parse_pem_data(ca_pem), profile)
        assert isinstance(result, BuildResult)
        assert result.profile_name == "test"


class TestAtomicSwap:
    def test_atomic_swap_produces_output(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_profile(tmp_path, atomic=True)
        build_output(certs, profile)
        assert os.path.isdir(profile.output_path)
        # Staging dir should be gone after atomic swap
        assert not os.path.exists(profile.staging_path)

    def test_atomic_swap_removes_backup(self, tmp_path, ca_pem):
        profile = _make_profile(tmp_path, atomic=True)
        certs = parse_pem_data(ca_pem)
        build_output(certs, profile)
        build_output(certs, profile)  # second build — exercises existing output
        backup = profile.output_path + ".bak"
        assert not os.path.exists(backup)

    def test_atomic_swap_first_run_no_existing_dir(self, tmp_path):
        """First build: output_dir doesn't exist yet — must work without EXCHANGE."""
        src = tmp_path / "staging"
        dst = tmp_path / "output"
        src.mkdir()
        (src / "sentinel").write_text("hello")
        _atomic_swap(str(src), str(dst))
        assert (dst / "sentinel").read_text() == "hello"
        assert not dst.with_name("output.bak").exists()

    def test_atomic_swap_replaces_existing(self, tmp_path):
        """Second build: output_dir exists — new content replaces old."""
        src = tmp_path / "staging"
        dst = tmp_path / "output"
        dst.mkdir()
        (dst / "old").write_text("old")
        src.mkdir()
        (src / "new").write_text("new")
        _atomic_swap(str(src), str(dst))
        assert (dst / "new").exists()
        assert not (dst / "old").exists()

    def test_atomic_swap_rejects_symlink_output(self, tmp_path):
        """Symlink as output_path must raise ValueError."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        src = tmp_path / "staging"
        src.mkdir()
        with pytest.raises(ValueError, match="symlink"):
            _atomic_swap(str(src), str(link))

    def test_atomic_swap_cleans_stale_backup(self, tmp_path):
        """A leftover .bak from a previous interrupted run is removed."""
        src = tmp_path / "staging"
        bak = tmp_path / "output.bak"
        dst = tmp_path / "output"
        src.mkdir()
        bak.mkdir()
        (bak / "stale").write_text("stale")
        _atomic_swap(str(src), str(dst))
        assert not bak.exists()


class TestRenameat2:
    def test_exchange_swaps_directories(self, tmp_path):
        """renameat2(EXCHANGE) — if available — leaves no gap."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / "from_a").write_text("a")
        (b / "from_b").write_text("b")

        ok = _try_renameat2_exchange(str(a), str(b))
        if not ok:
            pytest.skip("renameat2 not available on this platform/kernel")

        # After exchange: b has from_a, a has from_b
        assert (b / "from_a").exists()
        assert (a / "from_b").exists()

    def test_exchange_returns_false_on_nonexistent_src(self, tmp_path):
        """Must return False (not raise) when src doesn't exist."""
        result = _try_renameat2_exchange(
            str(tmp_path / "nosuchdir"), str(tmp_path / "other")
        )
        assert result is False

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
    def test_exchange_returns_bool(self, tmp_path):
        """Always returns a bool, never raises."""
        a = tmp_path / "x"
        b = tmp_path / "y"
        a.mkdir()
        b.mkdir()
        result = _try_renameat2_exchange(str(a), str(b))
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Bundle output
# ---------------------------------------------------------------------------

def _make_bundle_profile(tmp_path, name="bundle-test", **extra):
    output_path = str(tmp_path / (name + ".pem"))
    cfg = {
        "output_path": output_path,
        "output_format": "bundle",
    }
    cfg.update(extra)
    return OutputProfile(name, cfg)


class TestBuildBundle:
    def test_writes_single_file(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_bundle_profile(tmp_path)
        build_output(certs, profile)
        assert os.path.isfile(profile.output_path)
        assert not os.path.isdir(profile.output_path)

    def test_file_contains_pem_block(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        profile = _make_bundle_profile(tmp_path)
        build_output(certs, profile)
        data = open(profile.output_path, "rb").read()
        assert b"-----BEGIN CERTIFICATE-----" in data
        assert b"-----END CERTIFICATE-----" in data

    def test_two_certs_both_present(self, tmp_path, ca_pem, second_ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        profile = _make_bundle_profile(tmp_path)
        build_output(certs, profile)
        data = open(profile.output_path, "rb").read()
        assert data.count(b"-----BEGIN CERTIFICATE-----") == 2

    def test_deduplicates_certs(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(ca_pem)
        profile = _make_bundle_profile(tmp_path)
        result = build_output(certs, profile)
        assert result.cert_count == 1
        data = open(profile.output_path, "rb").read()
        assert data.count(b"-----BEGIN CERTIFICATE-----") == 1

    def test_cert_count_in_result(self, tmp_path, ca_pem, second_ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        profile = _make_bundle_profile(tmp_path)
        result = build_output(certs, profile)
        assert result.cert_count == 2

    def test_deterministic_order(self, tmp_path, ca_pem, second_ca_pem):
        """Output order is fingerprint-sorted, not input-order-dependent."""
        certs_ab = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        certs_ba = parse_pem_data(second_ca_pem) + parse_pem_data(ca_pem)
        p1 = _make_bundle_profile(tmp_path, name="p1")
        p2 = _make_bundle_profile(tmp_path, name="p2")
        build_output(certs_ab, p1)
        build_output(certs_ba, p2)
        assert open(p1.output_path, "rb").read() == open(p2.output_path, "rb").read()

    def test_atomically_replaces_existing_file(self, tmp_path, ca_pem, second_ca_pem):
        """A second build replaces the existing bundle without leaving a gap."""
        profile = _make_bundle_profile(tmp_path)
        build_output(parse_pem_data(ca_pem), profile)
        first_data = open(profile.output_path, "rb").read()

        build_output(parse_pem_data(second_ca_pem), profile)
        second_data = open(profile.output_path, "rb").read()

        assert first_data != second_data
        assert b"-----BEGIN CERTIFICATE-----" in second_data

    def test_no_temp_file_left_on_success(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path)
        build_output(parse_pem_data(ca_pem), profile)
        tmp_files = [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]
        assert tmp_files == []

    def test_dry_run_does_not_write(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path)
        result = build_output(parse_pem_data(ca_pem), profile, dry_run=True)
        assert not os.path.exists(profile.output_path)
        assert result.cert_count == 1

    def test_file_permissions(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path, file_mode=0o640)
        build_output(parse_pem_data(ca_pem), profile)
        mode = oct(os.stat(profile.output_path).st_mode & 0o777)
        assert mode == oct(0o640)

    def test_creates_parent_directory(self, tmp_path, ca_pem):
        output_path = str(tmp_path / "new" / "subdir" / "bundle.pem")
        profile = OutputProfile("p", {"output_path": output_path, "output_format": "bundle"})
        build_output(parse_pem_data(ca_pem), profile)
        assert os.path.isfile(output_path)

    def test_raises_if_output_path_is_directory(self, tmp_path, ca_pem):
        out_dir = tmp_path / "mydir"
        out_dir.mkdir()
        profile = OutputProfile("p", {"output_path": str(out_dir), "output_format": "bundle"})
        with pytest.raises(ValueError, match="directory"):
            build_output(parse_pem_data(ca_pem), profile)

    def test_empty_cert_list_writes_empty_file(self, tmp_path):
        profile = _make_bundle_profile(tmp_path)
        result = build_output([], profile)
        assert os.path.isfile(profile.output_path)
        assert open(profile.output_path, "rb").read() == b""
        assert result.cert_count == 0

    def test_invalid_output_format_raises(self, tmp_path):
        with pytest.raises(ValueError, match="output_format"):
            OutputProfile("p", {"output_path": str(tmp_path / "f.pem"), "output_format": "tarball"})

    # -- annotation behaviour -------------------------------------------------

    def test_annotations_present_by_default(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path)
        build_output(parse_pem_data(ca_pem), profile)
        data = open(profile.output_path, "rb").read()
        assert b"# Subject:" in data

    def test_annotations_disabled_by_flag(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path, annotate_bundle=False)
        build_output(parse_pem_data(ca_pem), profile)
        data = open(profile.output_path, "rb").read()
        assert b"#" not in data

    def test_annotation_before_each_cert(self, tmp_path, ca_pem, second_ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        profile = _make_bundle_profile(tmp_path)
        build_output(certs, profile)
        data = open(profile.output_path, "rb").read()
        assert data.count(b"# Subject:") == 2

    def test_annotation_contains_expiry(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path)
        build_output(parse_pem_data(ca_pem), profile)
        data = open(profile.output_path, "rb").read()
        assert b"# Expires:" in data

    def test_annotation_contains_source(self, tmp_path, ca_pem):
        profile = _make_bundle_profile(tmp_path)
        certs = parse_pem_data(ca_pem, source_name="test-source")
        build_output(certs, profile)
        data = open(profile.output_path, "rb").read()
        assert b"# Source:   test-source" in data

    def test_issuer_line_omitted_for_self_signed(self, tmp_path, ca_pem):
        """Root CAs are self-signed: Issuer == Subject, so the Issuer line is redundant."""
        profile = _make_bundle_profile(tmp_path)
        build_output(parse_pem_data(ca_pem), profile)
        data = open(profile.output_path, "rb").read()
        assert b"# Issuer:" not in data


# ---------------------------------------------------------------------------
# _cert_annotation unit tests
# ---------------------------------------------------------------------------

class TestCertAnnotation:
    def _make_cert(self, ca_pem, **kwargs):
        certs = parse_pem_data(ca_pem, **kwargs)
        return certs[0]

    def test_subject_line_always_present(self, ca_pem):
        ci = self._make_cert(ca_pem)
        ann = _cert_annotation(ci)
        assert b"# Subject:" in ann

    def test_expires_line_present(self, ca_pem):
        ci = self._make_cert(ca_pem)
        ann = _cert_annotation(ci)
        assert b"# Expires:" in ann

    def test_issuer_line_absent_for_self_signed(self, ca_pem):
        ci = self._make_cert(ca_pem)
        # Root CAs are self-signed
        assert ci.subject == ci.issuer
        ann = _cert_annotation(ci)
        assert b"# Issuer:" not in ann

    def test_source_line_present_when_set(self, ca_pem):
        ci = self._make_cert(ca_pem, source_name="my-source")
        ann = _cert_annotation(ci)
        assert b"# Source:   my-source" in ann

    def test_source_line_absent_when_not_set(self, ca_pem):
        ci = self._make_cert(ca_pem)
        ci.source_name = None
        ann = _cert_annotation(ci)
        assert b"# Source:" not in ann

    def test_alias_line_present_when_igtf_info_has_alias(self, ca_pem):
        ci = self._make_cert(ca_pem)
        ci.igtf_info = {"alias": "TestCA-Root", "policy": "classic"}
        ann = _cert_annotation(ci)
        assert b"# Alias:    TestCA-Root" in ann

    def test_alias_line_absent_without_igtf_info(self, ca_pem):
        ci = self._make_cert(ca_pem)
        ann = _cert_annotation(ci)
        assert b"# Alias:" not in ann

    def test_annotation_ends_with_newline(self, ca_pem):
        ci = self._make_cert(ca_pem)
        ann = _cert_annotation(ci)
        assert ann.endswith(b"\n")

    def test_expires_date_format(self, ca_pem):
        """Date should be ISO YYYY-MM-DD, not a datetime with time component."""
        ci = self._make_cert(ca_pem)
        ann = _cert_annotation(ci).decode()
        line = next(l for l in ann.splitlines() if "Expires" in l)
        date_part = line.split("Expires:")[1].strip()
        # Must match YYYY-MM-DD exactly
        import re
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", date_part), repr(date_part)

    def test_issuer_line_present_for_intermediate(self, ca_pem):
        """When issuer differs from subject, the Issuer line is included."""
        ci = self._make_cert(ca_pem)
        # Force subject != issuer to simulate an intermediate CA
        ci.issuer = "/CN=Root CA"
        ci.subject = "/CN=Intermediate CA"
        ann = _cert_annotation(ci)
        assert b"# Issuer:   /CN=Root CA" in ann


# ---------------------------------------------------------------------------
# rehash mode paths
# ---------------------------------------------------------------------------

class TestRehashModes:
    def test_auto_rehash_mode_runs_rehash(self, tmp_path, ca_pem):
        """rehash='auto' must call rehash_directory (line 134)."""
        certs = parse_pem_data(ca_pem)
        output_path = str(tmp_path / "out")
        profile = OutputProfile("r", {
            "output_path": output_path,
            "atomic": False,
            "rehash": "auto",
        })
        # If openssl is available it succeeds; if not, falls back to builtin.
        # Either way the build should succeed.
        result = build_output(certs, profile)
        assert os.path.isdir(output_path)
        assert result.cert_count == 1

    def test_openssl_rehash_failure_adds_error(self, tmp_path, ca_pem):
        """rehash='openssl' with a failed rehash_directory → result.errors."""
        certs = parse_pem_data(ca_pem)
        output_path = str(tmp_path / "out2")
        profile = OutputProfile("r2", {
            "output_path": output_path,
            "atomic": False,
            "rehash": "openssl",
        })
        with patch("certbundle.output.rehash_directory", return_value=False):
            result = build_output(certs, profile)
        assert any("rehash failed" in e for e in result.errors)


# ---------------------------------------------------------------------------
# _write_igtf_meta
# ---------------------------------------------------------------------------

class TestWriteIgtfMeta:
    def test_writes_extra_files_from_source_results(self, tmp_path, ca_pem):
        """igtf_extra_files in source metadata are written to the work dir."""
        certs = parse_pem_data(ca_pem)
        work_dir = str(tmp_path / "work")
        os.makedirs(work_dir)

        sr = SourceResult(name="test")
        sr.metadata["igtf_extra_files"] = {
            "TestCA.signing_policy": b"access_id_CA X509 ...\n",
        }

        profile = OutputProfile("p", {
            "output_path": str(tmp_path / "out"),
            "include_igtf_meta": True,
        })
        _write_igtf_meta(work_dir, certs, [sr], profile)
        assert os.path.isfile(os.path.join(work_dir, "TestCA.signing_policy"))

    def test_writes_per_cert_info_files(self, tmp_path, ca_pem):
        """Certs with igtf_info and an alias get a generated .info file."""
        certs = parse_pem_data(ca_pem)
        certs[0].igtf_info = {"alias": "TestCA", "policy": "classic"}
        work_dir = str(tmp_path / "work2")
        os.makedirs(work_dir)

        sr = SourceResult(name="test")
        profile = OutputProfile("p", {
            "output_path": str(tmp_path / "out"),
            "include_igtf_meta": True,
        })
        _write_igtf_meta(work_dir, certs, [sr], profile)
        info_path = os.path.join(work_dir, "TestCA.info")
        assert os.path.isfile(info_path)
        content = open(info_path).read()
        assert "classic" in content

    def test_cert_with_igtf_info_but_no_alias_is_skipped(self, tmp_path, ca_pem):
        """A cert with igtf_info but no alias key produces no .info file."""
        certs = parse_pem_data(ca_pem)
        certs[0].igtf_info = {"policy": "classic"}  # no alias key
        work_dir = str(tmp_path / "work3")
        os.makedirs(work_dir)

        sr = SourceResult(name="test")
        profile = OutputProfile("p", {
            "output_path": str(tmp_path / "out"),
            "include_igtf_meta": True,
        })
        _write_igtf_meta(work_dir, certs, [sr], profile)
        # No .info file should be written since there's no alias
        info_files = [f for f in os.listdir(work_dir) if f.endswith(".info")]
        assert info_files == []


# ---------------------------------------------------------------------------
# _build_bundle — exception cleanup
# ---------------------------------------------------------------------------

class TestBuildBundleCleanup:
    def test_temp_file_cleaned_up_on_error(self, tmp_path, ca_pem):
        """If writing the temp file fails, no .tmp file is left behind."""
        profile = _make_bundle_profile(tmp_path, name="cleanup")
        with patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                build_output(parse_pem_data(ca_pem), profile)
        tmp_files = [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]
        assert tmp_files == []

    def test_unlink_failure_does_not_mask_original_error(self, tmp_path, ca_pem):
        """If os.unlink fails in cleanup, the original os.replace error is still raised."""
        profile = _make_bundle_profile(tmp_path, name="cleanup2")
        with patch("os.replace", side_effect=OSError("disk full")):
            with patch("os.unlink", side_effect=OSError("unlink failed")):
                with pytest.raises(OSError, match="disk full"):
                    build_output(parse_pem_data(ca_pem), profile)

    def test_creates_nested_parent_directory(self, tmp_path, ca_pem):
        """_build_bundle creates parent dirs when they don't exist."""
        output_path = str(tmp_path / "deep" / "nested" / "bundle.pem")
        profile = OutputProfile("p", {"output_path": output_path, "output_format": "bundle"})
        build_output(parse_pem_data(ca_pem), profile)
        assert os.path.isfile(output_path)


# ---------------------------------------------------------------------------
# _atomic_swap — parent directory creation
# ---------------------------------------------------------------------------

class TestAtomicSwapParent:
    def test_creates_parent_of_output_dir(self, tmp_path):
        """_atomic_swap creates the parent directory if needed."""
        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "file").write_text("hello")
        output = tmp_path / "new_parent" / "output"
        _atomic_swap(str(staging), str(output))
        assert (output / "file").read_text() == "hello"

    def test_two_rename_fallback_with_existing_output(self, tmp_path):
        """Forces the two-rename fallback even when output_dir exists."""
        staging = tmp_path / "staging"
        output = tmp_path / "output"
        staging.mkdir()
        output.mkdir()
        (staging / "new").write_text("new")
        (output / "old").write_text("old")
        # Force the fallback even though renameat2 might succeed on Linux
        with patch("certbundle.output._try_renameat2_exchange", return_value=False):
            _atomic_swap(str(staging), str(output))
        assert (output / "new").exists()
        assert not (output / "old").exists()
        # Backup must be cleaned up
        assert not (tmp_path / "output.bak").exists()


# ---------------------------------------------------------------------------
# BuildResult.__repr__
# ---------------------------------------------------------------------------

class TestBuildResultRepr:
    def test_repr_contains_profile_name(self):
        r = BuildResult("my-profile", "/some/path")
        assert "my-profile" in repr(r)

    def test_repr_contains_cert_count(self):
        r = BuildResult("p", "/path")
        r.cert_count = 42
        assert "42" in repr(r)


# ---------------------------------------------------------------------------
# _try_renameat2_exchange — non-Linux platform
# ---------------------------------------------------------------------------

class TestRenameat2NonLinux:
    def test_returns_false_on_non_linux(self, tmp_path):
        """On non-Linux platforms, the call returns False without raising."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        with patch("certbundle.output._platform.system", return_value="Darwin"):
            result = _try_renameat2_exchange(str(a), str(b))
        assert result is False

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
    def test_unknown_architecture_returns_false(self, tmp_path):
        """If the machine architecture is unknown, return False."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        with patch("certbundle.output._platform.machine", return_value="mips"):
            result = _try_renameat2_exchange(str(a), str(b))
        assert result is False

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
    def test_no_libc_found_returns_false(self, tmp_path):
        """If ctypes.util.find_library returns None, return False."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        with patch("certbundle.output.ctypes.util.find_library", return_value=None):
            result = _try_renameat2_exchange(str(a), str(b))
        assert result is False

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
    def test_cdll_exception_returns_false(self, tmp_path):
        """If ctypes.CDLL raises, return False (catches via except Exception)."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        with patch("certbundle.output.ctypes.CDLL", side_effect=OSError("load failed")):
            result = _try_renameat2_exchange(str(a), str(b))
        assert result is False


# ---------------------------------------------------------------------------
# _write_file — parent directory creation
# ---------------------------------------------------------------------------

class TestWriteFile:
    def test_creates_parent_dirs(self, tmp_path):
        """_write_file creates intermediate directories as needed."""
        dest = str(tmp_path / "a" / "b" / "c" / "file.pem")
        _write_file(dest, b"data", 0o644)
        assert open(dest, "rb").read() == b"data"

    def test_sets_file_permissions(self, tmp_path):
        """_write_file applies the requested file mode."""
        dest = str(tmp_path / "sub" / "file.pem")
        _write_file(dest, b"data", 0o600)
        mode = oct(os.stat(dest).st_mode & 0o777)
        assert mode == oct(0o600)
