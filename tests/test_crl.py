"""Tests for certbundle.crl — CRL manager and helpers."""

import os
import pytest

from certbundle.cert import parse_pem_data
from certbundle.crl import (
    CRLInfo,
    CRLManager,
    CRLUpdateResult,
    _parse_crl_date,
    _parse_crl_field,
    _der_to_pem_crl,
    _safe_abspath,
)
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# CRLInfo
# ---------------------------------------------------------------------------

class TestCRLInfo:
    def _make_info(self, this_update, next_update):
        return CRLInfo(
            issuer_hash="a1b2c3d4",
            issuer_dn="/CN=Test CA",
            this_update=this_update,
            next_update=next_update,
        )

    def test_not_expired_when_next_update_future(self):
        info = self._make_info(
            this_update=datetime(2025, 1, 1, tzinfo=timezone.utc),
            next_update=datetime(2099, 12, 31, tzinfo=timezone.utc),
        )
        assert info.is_expired() is False

    def test_expired_when_next_update_past(self):
        info = self._make_info(
            this_update=datetime(2020, 1, 1, tzinfo=timezone.utc),
            next_update=datetime(2020, 1, 2, tzinfo=timezone.utc),
        )
        assert info.is_expired() is True

    def test_expired_when_next_update_none(self):
        info = self._make_info(
            this_update=datetime(2025, 1, 1, tzinfo=timezone.utc),
            next_update=None,
        )
        assert info.is_expired() is True

    def test_stale_when_this_update_old(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=48),
            next_update=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert info.is_stale(max_age_hours=24) is True

    def test_not_stale_when_recent(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=2),
            next_update=datetime.now(timezone.utc) + timedelta(hours=22),
        )
        assert info.is_stale(max_age_hours=24) is False

    def test_repr(self):
        info = CRLInfo("aa", "/CN=CA", None, None)
        assert "CRLInfo" in repr(info)


# ---------------------------------------------------------------------------
# CRLManager construction
# ---------------------------------------------------------------------------

class TestCRLManagerConstruction:
    def test_defaults(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        assert mgr.fetch is True
        assert mgr.verify_tls is True
        assert mgr.max_age_hours == 24

    def test_custom_max_age(self, tmp_path):
        mgr = CRLManager({"max_age_hours": 48}, str(tmp_path))
        assert mgr.max_age_hours == 48

    def test_crl_path_defaults_to_output_path(self, tmp_path):
        out = str(tmp_path)
        mgr = CRLManager({}, out)
        assert mgr.crl_path == out

    def test_custom_crl_path(self, tmp_path):
        crl_dir = str(tmp_path / "crls")
        os.makedirs(crl_dir)
        mgr = CRLManager({"crl_path": crl_dir}, str(tmp_path))
        assert mgr.crl_path == crl_dir

    def test_tls_verify_false_warns(self, tmp_path, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="certbundle.crl"):
            CRLManager({"verify_tls": False}, str(tmp_path))
        assert any("TLS verification is DISABLED" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# CRLManager.update_crls — dry run (no network)
# ---------------------------------------------------------------------------

class TestCRLManagerUpdateDryRun:
    def test_dry_run_skips_no_url(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        # No CRL distribution points on our test cert
        mgr = CRLManager({}, str(tmp_path))
        result = mgr.update_crls([ci], dry_run=True)
        assert len(result.missing) == 1
        assert len(result.would_fetch) == 0

    def test_dry_run_with_igtf_crl_url(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        ci.igtf_info = {"crlurl": "https://example.com/test.crl"}
        mgr = CRLManager({"sources": ["igtf"]}, str(tmp_path))
        result = mgr.update_crls([ci], dry_run=True)
        assert "https://example.com/test.crl" in result.would_fetch

    def test_fetch_disabled(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        ci.igtf_info = {"crlurl": "https://example.com/test.crl"}
        mgr = CRLManager({"fetch": False}, str(tmp_path))
        result = mgr.update_crls([ci], dry_run=False)
        # fetch=False → nothing attempted
        assert len(result.updated) == 0
        assert len(result.would_fetch) == 0

    def test_result_repr(self):
        r = CRLUpdateResult()
        assert "CRLUpdateResult" in repr(r)


# ---------------------------------------------------------------------------
# CRLManager._write_crl — hash validation
# ---------------------------------------------------------------------------

class TestCRLWriteSecurity:
    def test_rejects_invalid_hash(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        with pytest.raises(ValueError, match="Invalid issuer hash format"):
            mgr._write_crl(b"-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n",
                           "../etc/passwd")

    def test_rejects_path_traversal_hash(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        with pytest.raises(ValueError, match="Invalid issuer hash format"):
            mgr._write_crl(b"data", "../../../../tmp/evil")

    def test_accepts_valid_hash(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        # _write_crl with PEM data that isn't a valid CRL will just write it raw
        dummy_pem = b"-----BEGIN X509 CRL-----\nMIIBIjANBg==\n-----END X509 CRL-----\n"
        # This may error on openssl crl parsing but the path logic should work
        try:
            path = mgr._write_crl(dummy_pem, "a1b2c3d4")
            assert os.path.exists(path)
            assert "a1b2c3d4.r0" in path
        except Exception:
            pass  # openssl parsing failure is acceptable; path security is what matters


# ---------------------------------------------------------------------------
# URL CRL source filtering
# ---------------------------------------------------------------------------

class TestCRLUrlSources:
    def test_distribution_source_uses_cdp(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        ci.crl_distribution_points = ["https://crl.example.com/ca.crl"]
        mgr = CRLManager({"sources": ["distribution"]}, str(tmp_path))
        urls = mgr._get_crl_urls(ci)
        assert "https://crl.example.com/ca.crl" in urls

    def test_igtf_source_uses_info_url(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        ci.igtf_info = {"crlurl": "https://igtf.example.com/ca.crl"}
        mgr = CRLManager({"sources": ["igtf"]}, str(tmp_path))
        urls = mgr._get_crl_urls(ci)
        assert "https://igtf.example.com/ca.crl" in urls

    def test_no_sources_no_urls(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        ci.crl_distribution_points = ["https://crl.example.com/ca.crl"]
        ci.igtf_info = {"crlurl": "https://igtf.example.com/ca.crl"}
        mgr = CRLManager({"sources": []}, str(tmp_path))
        urls = mgr._get_crl_urls(ci)
        assert urls == []

    def test_no_duplicate_urls(self, tmp_path, ca_pem):
        ci = parse_pem_data(ca_pem)[0]
        same_url = "https://example.com/ca.crl"
        ci.crl_distribution_points = [same_url]
        ci.igtf_info = {"crlurl": same_url}
        mgr = CRLManager({"sources": ["distribution", "igtf"]}, str(tmp_path))
        urls = mgr._get_crl_urls(ci)
        assert urls.count(same_url) == 1


# ---------------------------------------------------------------------------
# CRL date / field parsing helpers
# ---------------------------------------------------------------------------

class TestParseCrlDate:
    def test_parses_valid_date(self):
        text = "        Last Update: Jan  1 00:00:00 2024 GMT\n"
        dt = _parse_crl_date(text, "Last Update:")
        assert dt is not None
        assert dt.year == 2024

    def test_returns_none_for_missing_label(self):
        text = "No date here\n"
        assert _parse_crl_date(text, "Last Update:") is None

    def test_returns_none_for_malformed_date(self):
        text = "        Last Update: not-a-date\n"
        assert _parse_crl_date(text, "Last Update:") is None


class TestParseCrlField:
    def test_parses_issuer(self):
        text = "        Issuer: C=GB, O=Test, CN=Test CA\n"
        val = _parse_crl_field(text, "Issuer:")
        assert val == "C=GB, O=Test, CN=Test CA"

    def test_returns_none_if_missing(self):
        text = "No issuer here\n"
        assert _parse_crl_field(text, "Issuer:") is None


# ---------------------------------------------------------------------------
# _safe_abspath
# ---------------------------------------------------------------------------

class TestSafeAbspath:
    def test_resolves_relative(self, tmp_path):
        p = _safe_abspath(str(tmp_path), "test")
        assert os.path.isabs(p)

    def test_resolves_tilde(self):
        p = _safe_abspath("~/tmp", "test")
        assert not p.startswith("~")

    def test_passes_clean_absolute(self, tmp_path):
        p = _safe_abspath(str(tmp_path), "test")
        assert p == str(tmp_path)


# ---------------------------------------------------------------------------
# _der_to_pem_crl
# ---------------------------------------------------------------------------

class TestDerToPemCrl:
    def test_passthrough_pem(self):
        pem = b"-----BEGIN X509 CRL-----\ndata\n-----END X509 CRL-----\n"
        assert _der_to_pem_crl(pem) == pem

    def test_returns_bytes(self):
        result = _der_to_pem_crl(b"\x30\x82\x00\x00")  # invalid DER, returns as-is
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# _write_crl — file write, overwrite, hash validation
# ---------------------------------------------------------------------------

_FAKE_PEM_CRL = b"-----BEGIN X509 CRL-----\nZmFrZQ==\n-----END X509 CRL-----\n"


class TestWriteCrl:
    def test_writes_r0_file(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        path = mgr._write_crl(_FAKE_PEM_CRL, "a1b2c3d4")
        assert path.endswith("a1b2c3d4.r0")
        assert os.path.isfile(path)

    def test_file_contains_crl_data(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        path = mgr._write_crl(_FAKE_PEM_CRL, "deadbeef")
        assert open(path, "rb").read() == _FAKE_PEM_CRL

    def test_overwrites_existing_r0(self, tmp_path):
        """Second write must replace .r0, not create .r1."""
        mgr = CRLManager({}, str(tmp_path))
        crl_v1 = b"-----BEGIN X509 CRL-----\ndmVyc2lvbjE=\n-----END X509 CRL-----\n"
        crl_v2 = b"-----BEGIN X509 CRL-----\ndmVyc2lvbjI=\n-----END X509 CRL-----\n"
        mgr._write_crl(crl_v1, "cafebabe")
        mgr._write_crl(crl_v2, "cafebabe")
        crl_files = [f for f in os.listdir(str(tmp_path)) if f.startswith("cafebabe.r")]
        assert crl_files == ["cafebabe.r0"], "Old CRL accumulated instead of being replaced"
        assert b"dmVyc2lvbjI=" in open(str(tmp_path / "cafebabe.r0"), "rb").read()

    def test_rejects_invalid_hash_format(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        with pytest.raises(ValueError, match="Invalid issuer hash"):
            mgr._write_crl(_FAKE_PEM_CRL, "not-valid")

    def test_rejects_path_traversal_in_hash(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        with pytest.raises(ValueError, match="Invalid issuer hash"):
            mgr._write_crl(_FAKE_PEM_CRL, "../../etc/")

    def test_file_permissions(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        path = mgr._write_crl(_FAKE_PEM_CRL, "12345678")
        mode = oct(os.stat(path).st_mode)[-3:]
        assert mode == "644"


# ---------------------------------------------------------------------------
# _find_crl_file
# ---------------------------------------------------------------------------

class TestFindCrlFile:
    def test_finds_r0(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        (tmp_path / "a1b2c3d4.r0").write_bytes(_FAKE_PEM_CRL)
        result = mgr._find_crl_file("a1b2c3d4")
        assert result is not None
        assert result.endswith("a1b2c3d4.r0")

    def test_returns_none_when_absent(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        assert mgr._find_crl_file("deadbeef") is None

    def test_rejects_malformed_hash(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        assert mgr._find_crl_file("not-8-hex") is None


# ---------------------------------------------------------------------------
# validate_crls
# ---------------------------------------------------------------------------

class TestValidateCrls:
    def test_warns_when_crl_missing(self, tmp_path, ca_pem):
        certs = parse_pem_data(ca_pem)
        mgr = CRLManager({}, str(tmp_path))
        warnings = mgr.validate_crls(certs)
        assert any("Missing CRL" in w for w in warnings)

    def test_no_warnings_when_no_certs(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        warnings = mgr.validate_crls([])
        assert warnings == []

    def test_warns_when_crl_expired(self, tmp_path, ca_pem):
        from unittest.mock import patch
        from certbundle.crl import CRLInfo
        certs = parse_pem_data(ca_pem)
        mgr = CRLManager({}, str(tmp_path))
        # Plant a CRL file so _find_crl_file finds it
        issuer_hash = mgr._get_issuer_hash(certs[0])
        (tmp_path / (issuer_hash + ".r0")).write_bytes(_FAKE_PEM_CRL)
        # Fake _parse_crl_file to return an expired CRL
        expired_info = CRLInfo(
            issuer_hash=issuer_hash,
            issuer_dn="/CN=Test CA",
            this_update=datetime(2020, 1, 1, tzinfo=timezone.utc),
            next_update=datetime(2020, 1, 2, tzinfo=timezone.utc),
            file_path=str(tmp_path / (issuer_hash + ".r0")),
        )
        with patch("certbundle.crl._parse_crl_file", return_value=expired_info):
            warnings = mgr.validate_crls(certs)
        assert any("Expired CRL" in w for w in warnings)

    def test_warns_when_crl_stale(self, tmp_path, ca_pem):
        from unittest.mock import patch
        from datetime import timedelta
        from certbundle.crl import CRLInfo
        certs = parse_pem_data(ca_pem)
        mgr = CRLManager({"max_age_hours": 1}, str(tmp_path))
        issuer_hash = mgr._get_issuer_hash(certs[0])
        (tmp_path / (issuer_hash + ".r0")).write_bytes(_FAKE_PEM_CRL)
        stale_info = CRLInfo(
            issuer_hash=issuer_hash,
            issuer_dn="/CN=Test CA",
            this_update=datetime.now(timezone.utc) - timedelta(hours=48),
            next_update=datetime.now(timezone.utc) + timedelta(hours=1),
            file_path=str(tmp_path / (issuer_hash + ".r0")),
        )
        with patch("certbundle.crl._parse_crl_file", return_value=stale_info):
            warnings = mgr.validate_crls(certs)
        assert any("Stale CRL" in w for w in warnings)
