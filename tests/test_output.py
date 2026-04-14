"""Tests for certbundle.output — directory building and atomic replacement."""

import os
import re
import sys
import pytest

from certbundle.cert import parse_pem_data
from certbundle.output import (
    OutputProfile, build_output, BuildResult,
    _atomic_swap, _try_renameat2_exchange, _build_bundle, _cert_annotation,
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
