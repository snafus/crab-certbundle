"""Tests for certbundle.cert — parsing and data model."""

import pytest
from datetime import timezone

from certbundle.cert import parse_pem_data, parse_pem_file, CertificateInfo


class TestParsePemData:
    def test_parses_single_ca_cert(self, ca_pem):
        certs = parse_pem_data(ca_pem)
        assert len(certs) == 1
        ci = certs[0]
        assert isinstance(ci, CertificateInfo)
        assert ci.is_ca is True
        assert "Test CA" in ci.subject
        assert ci.fingerprint_sha256
        assert ":" in ci.fingerprint_sha256

    def test_parses_bundle(self, bundle_pem):
        certs = parse_pem_data(bundle_pem)
        assert len(certs) == 2

    def test_source_name_propagated(self, ca_pem):
        certs = parse_pem_data(ca_pem, source_name="my-source")
        assert certs[0].source_name == "my-source"

    def test_source_path_propagated(self, ca_pem):
        certs = parse_pem_data(ca_pem, source_path="/some/path.pem")
        assert certs[0].source_path == "/some/path.pem"

    def test_skips_garbage(self, ca_pem):
        # Garbage between certs should be silently skipped
        garbage = ca_pem + b"\n\nNOT A CERT\n\n"
        certs = parse_pem_data(garbage)
        assert len(certs) == 1

    def test_empty_data_returns_empty_list(self):
        assert parse_pem_data(b"") == []

    def test_leaf_cert_is_not_ca(self, leaf_pem):
        certs = parse_pem_data(leaf_pem)
        assert len(certs) == 1
        assert certs[0].is_ca is False

    def test_validity_dates_are_timezone_aware(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert ci.not_before.tzinfo is not None
        assert ci.not_after.tzinfo is not None

    def test_self_signed_detection(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert ci.is_self_signed() is True

    def test_expired_detection(self, expired_ca_pem):
        ci = parse_pem_data(expired_ca_pem)[0]
        assert ci.is_expired() is True

    def test_not_expired_for_valid_cert(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert ci.is_expired() is False

    def test_key_usage_parsed(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert "key_cert_sign" in ci.key_usage
        assert "crl_sign" in ci.key_usage

    def test_der_data_present(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert isinstance(ci.der_data, bytes)
        assert len(ci.der_data) > 0

    def test_serial_number_present(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert isinstance(ci.serial_number, int)

    def test_equality_by_fingerprint(self, ca_pem, second_ca_pem):
        ci1a = parse_pem_data(ca_pem)[0]
        ci1b = parse_pem_data(ca_pem)[0]
        ci2 = parse_pem_data(second_ca_pem)[0]
        assert ci1a == ci1b
        assert ci1a != ci2

    def test_hashable(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        s = {ci, ci}
        assert len(s) == 1


class TestParsePemFile:
    def test_reads_file(self, tmp_path, ca_pem):
        path = str(tmp_path / "ca.pem")
        with open(path, "wb") as fh:
            fh.write(ca_pem)
        certs = parse_pem_file(path, source_name="file-test")
        assert len(certs) == 1
        assert certs[0].source_path == path
        assert certs[0].source_name == "file-test"

    def test_raises_on_missing_file(self, tmp_path):
        with pytest.raises(IOError):
            parse_pem_file(str(tmp_path / "nonexistent.pem"))
