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
