"""Tests for crab.cert — parsing and data model."""

import os
import sys
import pytest

from cryptography.x509.oid import ExtendedKeyUsageOID

sys.path.insert(0, os.path.dirname(__file__))
from conftest import _make_ca_cert  # noqa: E402

from crab.cert import parse_pem_data, parse_pem_file, CertificateInfo


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
        with pytest.raises(OSError):
            parse_pem_file(str(tmp_path / "nonexistent.pem"))


# ---------------------------------------------------------------------------
# EKU predicate helpers
# ---------------------------------------------------------------------------

class TestEKUHelpers:
    def test_has_server_auth_eku_true(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH], key_size=1024)
        ci = parse_pem_data(pem)[0]
        assert ci.has_server_auth_eku() is True

    def test_has_server_auth_eku_false_when_absent(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.CLIENT_AUTH], key_size=1024)
        ci = parse_pem_data(pem)[0]
        assert ci.has_server_auth_eku() is False

    def test_has_client_auth_eku_true(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.CLIENT_AUTH], key_size=1024)
        ci = parse_pem_data(pem)[0]
        assert ci.has_client_auth_eku() is True

    def test_has_client_auth_eku_false_when_absent(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH], key_size=1024)
        ci = parse_pem_data(pem)[0]
        assert ci.has_client_auth_eku() is False

    def test_both_eku_present(self):
        pem, _, _ = _make_ca_cert(
            eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
            key_size=1024,
        )
        ci = parse_pem_data(pem)[0]
        assert ci.has_server_auth_eku() is True
        assert ci.has_client_auth_eku() is True


# ---------------------------------------------------------------------------
# CertificateInfo equality / hashing edge cases
# ---------------------------------------------------------------------------

class TestCertificateInfoEquality:
    def test_eq_with_non_certinfo_returns_not_implemented(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        result = ci.__eq__("not a CertificateInfo")
        assert result is NotImplemented

    def test_hash_is_consistent(self, ca_pem):
        ci1 = parse_pem_data(ca_pem)[0]
        ci2 = parse_pem_data(ca_pem)[0]
        assert hash(ci1) == hash(ci2)


# ---------------------------------------------------------------------------
# Bundle parsing skip-on-bad-block
# ---------------------------------------------------------------------------

class TestBundleParseSkipsGarbage:
    def test_partial_garbage_still_yields_good_certs(self, ca_pem):
        garbage = b"-----BEGIN CERTIFICATE-----\nbad data\n-----END CERTIFICATE-----\n"
        data = garbage + b"\n" + ca_pem
        certs = parse_pem_data(data)
        assert len(certs) == 1  # garbage skipped, good cert parsed
