"""Tests for certbundle.output — directory building and atomic replacement."""

import os
import re
import pytest

from certbundle.cert import parse_pem_data
from certbundle.output import OutputProfile, build_output, BuildResult


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
