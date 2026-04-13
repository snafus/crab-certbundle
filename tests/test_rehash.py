"""Tests for certbundle.rehash — hash computation and symlink map building."""

import re
import pytest

from certbundle.cert import parse_pem_data
from certbundle.rehash import (
    compute_subject_hash,
    compute_issuer_hash,
    build_symlink_map,
    _hash_python_fallback,
    _extract_subject_der,
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
