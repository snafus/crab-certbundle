"""Tests for certbundle.rehash — hash computation and symlink map building."""

import re
import sys
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from certbundle.cert import parse_pem_data
from certbundle.rehash import (
    compute_subject_hash,
    compute_issuer_hash,
    build_symlink_map,
    rehash_directory,
    _hash_python_fallback,
    _hash_via_pyopenssl,
    _run_openssl_hash,
    _extract_subject_der,
    _extract_issuer_der,
    _python_name_hash_from_bytes,
    _der_read_tlv_header,
)


class TestComputeSubjectHash:
    def test_returns_8_hex_chars(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        h = compute_subject_hash(ci)
        assert re.match(r"^[0-9a-f]{8}$", h), "Hash must be 8 lowercase hex chars"

    def test_same_cert_same_hash(self, ca_pem):
        ci1 = parse_pem_data(ca_pem)[0]
        ci2 = parse_pem_data(ca_pem)[0]
        assert compute_subject_hash(ci1) == compute_subject_hash(ci2)

    def test_different_certs_different_hashes(self, ca_pem, second_ca_pem):
        ci1 = parse_pem_data(ca_pem)[0]
        ci2 = parse_pem_data(second_ca_pem)[0]
        # Different subjects; hashes should differ (with very high probability)
        assert compute_subject_hash(ci1) != compute_subject_hash(ci2)

    def test_caches_result(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        h1 = compute_subject_hash(ci)
        # Corrupt the PEM to verify caching (second call should still return h1)
        ci.pem_data = b"corrupted"
        ci.der_data = b"corrupted"
        h2 = compute_subject_hash(ci)
        assert h1 == h2

    def test_compute_issuer_hash_returns_hex(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        h = compute_issuer_hash(ci)
        assert re.match(r"^[0-9a-f]{8}$", h)

    def test_self_signed_subject_equals_issuer_hash(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        sh = compute_subject_hash(ci)
        ih = compute_issuer_hash(ci)
        # For self-signed roots, subject == issuer, so both hashes should match.
        assert sh == ih


class TestPythonFallback:
    def test_fallback_returns_8_hex(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        h = _hash_python_fallback(ci.der_data)
        assert re.match(r"^[0-9a-f]{8}$", h)

    def test_extract_subject_der(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        subj_der = _extract_subject_der(ci.der_data)
        assert isinstance(subj_der, bytes)
        assert len(subj_der) > 0
        # DER subject name starts with 0x30 (SEQUENCE)
        assert subj_der[0] == 0x30


class TestBuildSymlinkMap:
    def test_single_cert(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        m = build_symlink_map([ci])
        assert len(m) == 1
        filename = list(m.keys())[0]
        assert re.match(r"^[0-9a-f]{8}\.0$", filename)

    def test_filename_starts_with_zero(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        m = build_symlink_map([ci])
        assert list(m.keys())[0].endswith(".0")

    def test_deduplication(self, ca_pem):
        ci1 = parse_pem_data(ca_pem)[0]
        ci2 = parse_pem_data(ca_pem)[0]
        m = build_symlink_map([ci1, ci2])
        assert len(m) == 1

    def test_two_different_certs(self, ca_pem, second_ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        m = build_symlink_map(certs)
        assert len(m) == 2

    def test_collision_handling(self, ca_pem):
        """
        Simulate a hash collision by injecting two certs with the same subject_hash.
        """
        ci1 = parse_pem_data(ca_pem)[0]
        ci2 = parse_pem_data(ca_pem)[0]
        # Give them different fingerprints but same hash
        ci2.fingerprint_sha256 = "DIFFERENT:FINGERPRINT"
        ci2.subject_hash = ci1.subject_hash  # force collision

        m = build_symlink_map([ci1, ci2])
        assert len(m) == 2
        # Should have .0 and .1
        keys = sorted(m.keys())
        assert keys[0].endswith(".0")
        assert keys[1].endswith(".1")

    def test_pem_data_in_map(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        m = build_symlink_map([ci])
        pem = list(m.values())[0]
        assert pem == ci.pem_data

    def test_empty_list(self):
        m = build_symlink_map([])
        assert m == {}


# ---------------------------------------------------------------------------
# rehash_directory — external openssl rehash / c_rehash  (item 5)
# ---------------------------------------------------------------------------

class TestRehashDirectory:
    def test_openssl_rehash_succeeds(self, tmp_path):
        with patch("subprocess.check_call") as mock_call:
            result = rehash_directory(str(tmp_path))
        assert result is True
        args = mock_call.call_args[0][0]
        assert args[0] == "openssl" and args[1] == "rehash"

    def test_falls_back_to_c_rehash(self, tmp_path):
        call_count = [0]

        def side_effect(cmd, **kwargs):
            call_count[0] += 1
            if cmd[0] == "openssl":
                raise FileNotFoundError("no openssl")
            # c_rehash succeeds

        with patch("subprocess.check_call", side_effect=side_effect):
            result = rehash_directory(str(tmp_path))
        assert result is True
        assert call_count[0] == 2

    def test_both_unavailable_returns_false(self, tmp_path):
        with patch("subprocess.check_call", side_effect=FileNotFoundError):
            result = rehash_directory(str(tmp_path))
        assert result is False

    def test_openssl_nonzero_exit_falls_back(self, tmp_path):
        call_count = [0]

        def side_effect(cmd, **kwargs):
            call_count[0] += 1
            if cmd[0] == "openssl":
                raise subprocess.CalledProcessError(1, cmd)
            # c_rehash succeeds

        with patch("subprocess.check_call", side_effect=side_effect):
            result = rehash_directory(str(tmp_path))
        assert result is True


# ---------------------------------------------------------------------------
# pyOpenSSL strategy paths
# ---------------------------------------------------------------------------

class TestPyOpenSSL:
    def test_pyopenssl_success_path(self, ca_pem):
        mock_cert = MagicMock()
        mock_cert.subject_name_hash.return_value = 0xA1B2C3D4
        mock_crypto = MagicMock()
        mock_crypto.load_certificate.return_value = mock_cert
        mock_crypto.FILETYPE_PEM = 1
        mock_openssl_mod = MagicMock()
        mock_openssl_mod.crypto = mock_crypto

        with patch.dict(sys.modules, {
            "OpenSSL": mock_openssl_mod,
            "OpenSSL.crypto": mock_crypto,
        }):
            result = _hash_via_pyopenssl(ca_pem)
        assert result == "a1b2c3d4"

    def test_pyopenssl_exception_returns_none(self, ca_pem):
        mock_crypto = MagicMock()
        mock_crypto.load_certificate.side_effect = Exception("parse failed")
        mock_crypto.FILETYPE_PEM = 1
        mock_openssl_mod = MagicMock()
        mock_openssl_mod.crypto = mock_crypto

        with patch.dict(sys.modules, {
            "OpenSSL": mock_openssl_mod,
            "OpenSSL.crypto": mock_crypto,
        }):
            result = _hash_via_pyopenssl(ca_pem)
        assert result is None


# ---------------------------------------------------------------------------
# _run_openssl_hash exception path
# ---------------------------------------------------------------------------

class TestRunOpensslHash:
    def test_file_not_found_returns_none(self, ca_pem):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = _run_openssl_hash(ca_pem, "-hash")
        assert result is None

    def test_timeout_returns_none(self, ca_pem):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["openssl"], 10)):
            result = _run_openssl_hash(ca_pem, "-hash")
        assert result is None


# ---------------------------------------------------------------------------
# _python_name_hash_from_bytes edge case
# ---------------------------------------------------------------------------

class TestPythonNameHash:
    def test_empty_bytes_returns_zeros(self):
        assert _python_name_hash_from_bytes(b"") == "00000000"

    def test_nonempty_returns_8_hex(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        h = _python_name_hash_from_bytes(_extract_subject_der(ci.der_data))
        assert re.match(r"^[0-9a-f]{8}$", h)


# ---------------------------------------------------------------------------
# _extract_issuer_der
# ---------------------------------------------------------------------------

class TestExtractIssuerDer:
    def test_returns_sequence_bytes(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        issuer_der = _extract_issuer_der(ci.der_data)
        assert isinstance(issuer_der, bytes)
        assert len(issuer_der) > 0
        assert issuer_der[0] == 0x30  # DER SEQUENCE tag

    def test_self_signed_issuer_equals_subject(self, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        assert _extract_issuer_der(ci.der_data) == _extract_subject_der(ci.der_data)

    def test_garbage_der_returns_input_bytes(self):
        garbage = b"not DER at all"
        result = _extract_issuer_der(garbage)
        assert result == garbage


# ---------------------------------------------------------------------------
# _extract_subject_der exception path
# ---------------------------------------------------------------------------

class TestExtractSubjectDer:
    def test_garbage_der_returns_input_bytes(self):
        garbage = b"\xff\xff garbage"
        result = _extract_subject_der(garbage)
        assert result == garbage

    def test_fallback_hash_on_garbage_is_stable(self):
        # Even with garbage DER the fallback must return a valid 8-char hex string.
        h = _hash_python_fallback(b"completely invalid DER")
        assert re.match(r"^[0-9a-f]{8}$", h)


# ---------------------------------------------------------------------------
# _der_read_tlv_header — multi-byte length encodings
# ---------------------------------------------------------------------------

class TestDerReadTlvHeader:
    def test_short_form_length(self):
        data = bytes([0x30, 0x05]) + b"\x00" * 5
        tag, length, offset = _der_read_tlv_header(data, 0)
        assert tag == 0x30 and length == 5 and offset == 2

    def test_0x81_length_encoding(self):
        # 0x81 nn  →  length = nn
        data = bytes([0x04, 0x81, 0x80]) + b"\x00" * 0x80
        tag, length, offset = _der_read_tlv_header(data, 0)
        assert length == 0x80 and offset == 3

    def test_0x82_length_encoding(self):
        # 0x82 hi lo  →  length = hi<<8 | lo
        data = bytes([0x04, 0x82, 0x01, 0x00]) + b"\x00" * 0x100
        tag, length, offset = _der_read_tlv_header(data, 0)
        assert length == 0x100 and offset == 4

    def test_0x83_length_encoding(self):
        # 0x83 b2 b1 b0  →  length = (b2<<16)|(b1<<8)|b0
        data = bytes([0x04, 0x83, 0x00, 0x01, 0x00]) + b"\x00" * 0x100
        tag, length, offset = _der_read_tlv_header(data, 0)
        assert length == 0x100 and offset == 5

    def test_unsupported_length_raises_value_error(self):
        # 0x84 is not handled → ValueError
        data = bytes([0x04, 0x84, 0x00, 0x00, 0x00, 0x01])
        with pytest.raises(ValueError, match="Unsupported"):
            _der_read_tlv_header(data, 0)
