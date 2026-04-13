"""Tests for certbundle.validation — output directory checks."""

import os
import re
import pytest

from certbundle.cert import parse_pem_data
from certbundle.output import OutputProfile, build_output
from certbundle.validation import (
    validate_directory,
    has_errors,
    has_warnings,
    ValidationIssue,
)


def _make_output(tmp_path, pems, name="v-test"):
    certs = []
    for p in pems:
        certs.extend(parse_pem_data(p))
    output_path = str(tmp_path / name)
    profile = OutputProfile(
        name,
        {
            "output_path": output_path,
            "staging_path": output_path + ".staging",
            "atomic": False,
            "rehash": "builtin",
            "include_igtf_meta": False,
        },
    )
    build_output(certs, profile)
    return output_path


class TestValidateDirectory:
    def test_valid_single_ca(self, tmp_path, ca_pem):
        d = _make_output(tmp_path, [ca_pem])
        issues = validate_directory(d, check_hashes=True, run_openssl=False)
        assert not has_errors(issues)

    def test_missing_directory(self, tmp_path):
        issues = validate_directory(str(tmp_path / "nope"), run_openssl=False)
        assert has_errors(issues)
        assert any("does not exist" in i.message for i in issues)

    def test_empty_directory(self, tmp_path):
        d = str(tmp_path / "empty")
        os.makedirs(d)
        issues = validate_directory(d, run_openssl=False)
        assert has_warnings(issues)

    def test_info_message_cert_count(self, tmp_path, ca_pem):
        d = _make_output(tmp_path, [ca_pem])
        issues = validate_directory(d, check_hashes=False, run_openssl=False)
        info_msgs = [i for i in issues if i.level == "info"]
        assert any("certificate" in i.message.lower() for i in info_msgs)

    def test_expired_cert_warns(self, tmp_path, expired_ca_pem):
        d = _make_output(tmp_path, [expired_ca_pem], name="exp")
        issues = validate_directory(d, check_hashes=False, run_openssl=False)
        warn_msgs = [i for i in issues if i.level == "warning"]
        assert any("expired" in i.message.lower() for i in warn_msgs)

    def test_hash_consistency(self, tmp_path, ca_pem):
        d = _make_output(tmp_path, [ca_pem])
        issues = validate_directory(d, check_hashes=True, run_openssl=False)
        # Should have no hash mismatch errors
        hash_errors = [
            i for i in issues
            if i.level == "error" and "mismatch" in i.message.lower()
        ]
        assert hash_errors == []


class TestValidationIssue:
    def test_str_with_file(self):
        issue = ValidationIssue("error", "something broke", file="a1b2c3d4.0")
        s = str(issue)
        assert "ERROR" in s
        assert "something broke" in s
        assert "a1b2c3d4.0" in s

    def test_str_without_file(self):
        issue = ValidationIssue("info", "all good")
        s = str(issue)
        assert "INFO" in s
        assert "all good" in s

    def test_has_errors_false(self, tmp_path, ca_pem):
        d = _make_output(tmp_path, [ca_pem])
        issues = validate_directory(d, check_hashes=True, run_openssl=False)
        assert not has_errors(issues)

    def test_has_errors_true(self, tmp_path):
        issues = validate_directory(str(tmp_path / "nope"), run_openssl=False)
        assert has_errors(issues)

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="level"):
            ValidationIssue("critical", "bad level")

    def test_repr(self):
        issue = ValidationIssue("warning", "watch out")
        assert "WARNING" in repr(issue)
        assert "watch out" in repr(issue)


# ---------------------------------------------------------------------------
# Hash mismatch detection
# ---------------------------------------------------------------------------

class TestHashMismatch:
    def test_detects_wrong_hash_in_filename(self, tmp_path, ca_pem):
        """Place a cert under the wrong hash filename; expect an error."""
        # Write the cert under a filename with a known-wrong hash
        (tmp_path / "00000000.0").write_bytes(ca_pem)
        issues = validate_directory(str(tmp_path), check_hashes=True, run_openssl=False)
        hash_errors = [i for i in issues if i.level == "error" and "mismatch" in i.message.lower()]
        assert hash_errors, "Expected a hash mismatch error but got: {}".format(issues)

    def test_no_mismatch_for_correct_filename(self, tmp_path, ca_pem):
        d = _make_output(tmp_path, [ca_pem])
        issues = validate_directory(d, check_hashes=True, run_openssl=False)
        assert not any("mismatch" in i.message.lower() for i in issues)


# ---------------------------------------------------------------------------
# Multi-cert file warning
# ---------------------------------------------------------------------------

class TestMultiCertFile:
    def test_warns_when_file_contains_two_certs(self, tmp_path, ca_pem, second_ca_pem):
        """A CApath file should contain exactly one certificate."""
        from certbundle.cert import parse_pem_data
        from certbundle.rehash import compute_subject_hash
        certs = parse_pem_data(ca_pem)
        hash0 = compute_subject_hash(certs[0])
        bundle = ca_pem + b"\n" + second_ca_pem
        (tmp_path / (hash0 + ".0")).write_bytes(bundle)
        issues = validate_directory(str(tmp_path), check_hashes=False, run_openssl=False)
        warn_msgs = [str(i) for i in issues if i.level == "warning"]
        assert any("2 certificate" in m.lower() or "contains 2" in m.lower() for m in warn_msgs)


# ---------------------------------------------------------------------------
# Unknown files info message
# ---------------------------------------------------------------------------

class TestUnknownFiles:
    def test_info_for_unrecognised_files(self, tmp_path, ca_pem):
        d = _make_output(tmp_path, [ca_pem])
        # Drop a random file in the built directory
        open(os.path.join(d, "random.txt"), "w").close()
        issues = validate_directory(d, check_hashes=False, run_openssl=False)
        info_msgs = [i for i in issues if i.level == "info"]
        assert any("unrecognised" in i.message.lower() for i in info_msgs)


# ---------------------------------------------------------------------------
# openssl verify spot-check (graceful unavailability)
# ---------------------------------------------------------------------------

class TestOpensslSpotCheck:
    def test_skips_gracefully_when_openssl_absent(self, tmp_path, ca_pem):
        """validate_directory with run_openssl=True should not crash even
        when the openssl binary is absent; it should just produce no extra issues."""
        from unittest.mock import patch
        d = _make_output(tmp_path, [ca_pem], name="ssl-check")
        with patch("subprocess.run", side_effect=FileNotFoundError("openssl not found")):
            issues = validate_directory(d, check_hashes=False, run_openssl=True)
        # Should have no openssl-related errors
        openssl_errors = [i for i in issues if i.level == "error"]
        assert openssl_errors == []
