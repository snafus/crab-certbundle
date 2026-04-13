"""Tests for certbundle.output — directory building and atomic replacement."""

import os
import re
import sys
import pytest

from certbundle.cert import parse_pem_data
from certbundle.output import (
    OutputProfile, build_output, BuildResult,
    _atomic_swap, _try_renameat2_exchange,
)


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
