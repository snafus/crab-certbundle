"""Tests for crab.validation — output directory checks."""

import os
import re
import pytest
from unittest.mock import patch, MagicMock

from crab.cert import parse_pem_data
from crab.output import OutputProfile, build_output
from crab.validation import (
    validate_directory,
    has_errors,
    has_warnings,
    ValidationIssue,
    _openssl_verify_spot_check,
    _validate_cert_file,
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
        from crab.cert import parse_pem_data
        from crab.rehash import compute_subject_hash
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
        d = _make_output(tmp_path, [ca_pem], name="ssl-check")
        with patch("subprocess.run", side_effect=FileNotFoundError("openssl not found")):
            issues = validate_directory(d, check_hashes=False, run_openssl=True)
        # Should have no openssl-related errors
        openssl_errors = [i for i in issues if i.level == "error"]
        assert openssl_errors == []

    def test_generic_exception_produces_info_not_crash(self, tmp_path, ca_pem):
        """A non-FileNotFoundError exception must be caught and reported as info."""
        d = _make_output(tmp_path, [ca_pem], name="ssl-exc")
        files = [(e, os.path.join(d, e)) for e in os.listdir(d)
                 if re.match(r"^[0-9a-f]{8}\.\d+$", e)]
        with patch("subprocess.run", side_effect=RuntimeError("unexpected")):
            issues = _openssl_verify_spot_check(d, files[:1])
        # Should produce an info issue, not propagate the exception
        assert any(i.level == "info" for i in issues)

    def test_openssl_failure_not_selfsigned_produces_warning(self, tmp_path, ca_pem):
        """Non-zero return code that is NOT a self-signed error → warning."""
        d = _make_output(tmp_path, [ca_pem], name="ssl-warn")
        files = [(e, os.path.join(d, e)) for e in os.listdir(d)
                 if re.match(r"^[0-9a-f]{8}\.\d+$", e)]
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = b""
        mock_result.stderr = b"error: unknown certificate"
        with patch("subprocess.run", return_value=mock_result):
            issues = _openssl_verify_spot_check(d, files[:1])
        assert any(i.level == "warning" for i in issues)

    def test_openssl_success_zero_return_no_issues(self, tmp_path, ca_pem):
        """Zero return code from openssl verify should add no issues."""
        d = _make_output(tmp_path, [ca_pem], name="ssl-ok")
        files = [(e, os.path.join(d, e)) for e in os.listdir(d)
                 if re.match(r"^[0-9a-f]{8}\.\d+$", e)]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"OK"
        mock_result.stderr = b""
        with patch("subprocess.run", return_value=mock_result):
            issues = _openssl_verify_spot_check(d, files[:1])
        assert issues == []


# ---------------------------------------------------------------------------
# Directory entries: CRL files and metadata files are silently skipped
# ---------------------------------------------------------------------------

class TestDirectoryEntryTypes:
    def test_crl_file_not_counted_as_cert(self, tmp_path, ca_pem):
        """*.r0 CRL files in the directory should not trigger errors."""
        d = _make_output(tmp_path, [ca_pem], name="crl-entries")
        # Drop a fake CRL file alongside the cert
        (d / "a1b2c3d4.r0") if False else open(os.path.join(d, "a1b2c3d4.r0"), "wb").close()
        issues = validate_directory(d, check_hashes=False, run_openssl=False)
        # No error about the .r0 file; cert count info still present
        assert not any("a1b2c3d4.r0" in i.message for i in issues if i.level == "error")

    def test_info_files_silently_accepted(self, tmp_path, ca_pem):
        """.info, .signing_policy, .namespaces files are quietly ignored."""
        d = _make_output(tmp_path, [ca_pem], name="meta-entries")
        open(os.path.join(d, "TestCA.info"), "w").close()
        open(os.path.join(d, "TestCA.signing_policy"), "w").close()
        issues = validate_directory(d, check_hashes=False, run_openssl=False)
        # No unrecognised-file info about them
        assert not any(
            "TestCA.info" in i.message or "TestCA.signing_policy" in i.message
            for i in issues
        )

    def test_subdirectory_not_treated_as_cert(self, tmp_path, ca_pem):
        """Subdirectories inside the CApath dir are silently skipped."""
        d = _make_output(tmp_path, [ca_pem], name="subdir-entry")
        os.makedirs(os.path.join(d, "subdir"))
        issues = validate_directory(d, check_hashes=False, run_openssl=False)
        # No error caused by the subdirectory
        assert not any("subdir" in (i.file or "") for i in issues if i.level == "error")


# ---------------------------------------------------------------------------
# _validate_cert_file — parse failure and empty cert cases
# ---------------------------------------------------------------------------

class TestValidateCertFileParsing:
    def test_parse_error_produces_error_issue(self, tmp_path):
        """parse_pem_file raising an exception produces a 'Cannot parse' error."""
        cert_file = str(tmp_path / "a1b2c3d4.0")
        open(cert_file, "wb").write(b"dummy")
        with patch("crab.validation.parse_pem_file", side_effect=ValueError("bad cert")):
            issues = _validate_cert_file("a1b2c3d4.0", cert_file, {}, {}, check_hashes=False)
        assert any(i.level == "error" and "Cannot parse" in i.message for i in issues)

    def test_empty_cert_produces_error_issue(self, tmp_path):
        """A PEM file that parses but yields zero certs gets an error."""
        empty_file = str(tmp_path / "a1b2c3d4.0")
        open(empty_file, "wb").write(b"")
        # parse_pem_file on an empty file returns []
        issues = _validate_cert_file("a1b2c3d4.0", empty_file, {}, {}, check_hashes=False)
        assert any(i.level == "error" and "No certificate" in i.message for i in issues)


# ---------------------------------------------------------------------------
# Duplicate fingerprint detection
# ---------------------------------------------------------------------------

class TestDuplicateFingerprint:
    def test_duplicate_fingerprint_across_files_warns(self, tmp_path, ca_pem):
        """The same cert in two files should produce a duplicate warning."""
        from crab.cert import parse_pem_data
        from crab.rehash import compute_subject_hash
        certs = parse_pem_data(ca_pem)
        h = compute_subject_hash(certs[0])
        # Write the same cert under two different collision-index filenames
        (tmp_path / (h + ".0")).write_bytes(ca_pem)
        (tmp_path / (h + ".1")).write_bytes(ca_pem)
        issues = validate_directory(str(tmp_path), check_hashes=False, run_openssl=False)
        warn_msgs = [i.message for i in issues if i.level == "warning"]
        assert any("Duplicate" in m for m in warn_msgs)


# ---------------------------------------------------------------------------
# Non-CA certificate warning
# ---------------------------------------------------------------------------

class TestNonCACertWarning:
    def test_non_ca_cert_produces_warning(self, tmp_path, leaf_pem):
        """A leaf (non-CA) cert written into a CApath dir should warn."""
        from crab.cert import parse_pem_data
        from crab.rehash import compute_subject_hash
        certs = parse_pem_data(leaf_pem)
        h = compute_subject_hash(certs[0])
        (tmp_path / (h + ".0")).write_bytes(leaf_pem)
        issues = validate_directory(str(tmp_path), check_hashes=False, run_openssl=False)
        warn_msgs = [i.message for i in issues if i.level == "warning"]
        assert any("CA flag" in m for m in warn_msgs)
