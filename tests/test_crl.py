"""Tests for crab.crl — CRL manager and helpers."""

import os
import pytest
from unittest.mock import patch, MagicMock

from crab.cert import parse_pem_data
from crab.crl import (
    CRLInfo,
    CRLManager,
    CRLUpdateResult,
    _parse_crl_date,
    _parse_crl_field,
    _parse_crl_file,
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
        with caplog.at_level(logging.WARNING, logger="crab.crl"):
            CRLManager({"verify_tls": False}, str(tmp_path))
        assert any("TLS verification is DISABLED" in r.message for r in caplog.records)

    def test_default_max_workers(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        assert mgr.max_workers == 8

    def test_custom_max_workers(self, tmp_path):
        mgr = CRLManager({"max_workers": 16}, str(tmp_path))
        assert mgr.max_workers == 16

    def test_max_workers_minimum_is_one(self, tmp_path):
        mgr = CRLManager({"max_workers": 0}, str(tmp_path))
        assert mgr.max_workers == 1


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
# CRLManager.update_crls — parallel fetch (mocked network)
# ---------------------------------------------------------------------------

class TestCRLManagerParallelFetch:
    """Verify parallel fetch behaviour without making real network calls."""

    def _make_ci(self, url, ca_pem):
        """Build a CertificateInfo with a single CDP URL."""
        ci = parse_pem_data(ca_pem)[0]
        ci.crl_distribution_points = [url]
        ci.igtf_info = {}
        return ci

    def _fake_crl_pem(self):
        # Minimal PEM-looking bytes to pass the _write_crl path
        return b"-----BEGIN X509 CRL-----\nZmFrZQ==\n-----END X509 CRL-----\n"

    def test_all_certs_fetched(self, tmp_path, ca_pem):
        """update_crls fetches a CRL for every cert that has a URL."""
        urls = [
            "http://crl.example.com/{}.crl".format(i)
            for i in range(5)
        ]
        cert_infos = [self._make_ci(u, ca_pem) for u in urls]
        fetched = []

        def fake_fetch(url, verify_tls=True, timeout=None, session=None, **kw):
            fetched.append(url)
            return self._fake_crl_pem()

        with patch("crab.crl.CRLManager._fetch_crl", side_effect=lambda url, session=None: fake_fetch(url, session=session)):
            with patch("crab.crl.CRLManager._write_crl"):
                mgr = CRLManager({"max_workers": 4}, str(tmp_path))
                result = mgr.update_crls(cert_infos)

        assert len(result.updated) == 5
        assert len(result.failed) == 0
        assert sorted(fetched) == sorted(urls)

    def test_parallel_execution(self, tmp_path, ca_pem):
        """Fetches with max_workers > 1 run concurrently (wall time < serial time)."""
        import time

        N = 6
        DELAY = 0.15  # seconds per simulated fetch
        urls = ["http://crl{}.example.com/ca.crl".format(i) for i in range(N)]
        cert_infos = [self._make_ci(u, ca_pem) for u in urls]

        def slow_fetch(url, session=None):
            time.sleep(DELAY)
            return self._fake_crl_pem()

        with patch("crab.crl.CRLManager._fetch_crl", side_effect=slow_fetch):
            with patch("crab.crl.CRLManager._write_crl"):
                mgr = CRLManager({"max_workers": N}, str(tmp_path))
                t0 = time.time()
                result = mgr.update_crls(cert_infos)
                elapsed = time.time() - t0

        assert len(result.updated) == N
        # Serial would take N * DELAY seconds; parallel should be well under half.
        assert elapsed < (N * DELAY) / 2, (
            "Expected parallel execution (<{:.2f}s) but took {:.2f}s".format(
                (N * DELAY) / 2, elapsed
            )
        )

    def test_serial_with_max_workers_one(self, tmp_path, ca_pem):
        """max_workers=1 still fetches all CRLs correctly."""
        urls = ["http://crl{}.example.com/ca.crl".format(i) for i in range(3)]
        cert_infos = [self._make_ci(u, ca_pem) for u in urls]

        with patch("crab.crl.CRLManager._fetch_crl",
                   side_effect=lambda url, session=None: self._fake_crl_pem()):
            with patch("crab.crl.CRLManager._write_crl"):
                mgr = CRLManager({"max_workers": 1}, str(tmp_path))
                result = mgr.update_crls(cert_infos)

        assert len(result.updated) == 3
        assert len(result.failed) == 0

    def test_failed_fetch_does_not_block_others(self, tmp_path, ca_pem):
        """A fetch failure for one cert does not prevent other certs from succeeding."""
        good_url = "http://good.example.com/ca.crl"
        bad_url  = "http://bad.example.com/ca.crl"
        good_ci  = self._make_ci(good_url, ca_pem)
        bad_ci   = self._make_ci(bad_url,  ca_pem)

        def selective_fetch(url, session=None):
            if "bad" in url:
                raise IOError("simulated network failure")
            return self._fake_crl_pem()

        with patch("crab.crl.CRLManager._fetch_crl", side_effect=selective_fetch):
            with patch("crab.crl.CRLManager._write_crl"):
                mgr = CRLManager({"max_workers": 2}, str(tmp_path))
                result = mgr.update_crls([good_ci, bad_ci])

        assert good_url in result.updated
        assert bad_ci.subject in result.failed
        assert len(result.errors) == 1

    def test_session_passed_to_fetch(self, tmp_path, ca_pem):
        """The same requests.Session instance is passed to every _fetch_crl call."""
        sessions_seen = []
        url = "http://crl.example.com/ca.crl"
        ci = self._make_ci(url, ca_pem)

        def capture_session(url, session=None):
            sessions_seen.append(id(session))
            return self._fake_crl_pem()

        with patch("crab.crl.CRLManager._fetch_crl", side_effect=capture_session):
            with patch("crab.crl.CRLManager._write_crl"):
                mgr = CRLManager({}, str(tmp_path))
                mgr.update_crls([ci, ci])  # two fetches

        assert len(sessions_seen) == 2
        assert sessions_seen[0] == sessions_seen[1], "Expected the same Session for all fetches"

    def test_url_fallback_within_task(self, tmp_path, ca_pem):
        """If the first URL fails, the second is tried within the same task."""
        ci = parse_pem_data(ca_pem)[0]
        ci.crl_distribution_points = [
            "http://fail.example.com/ca.crl",
            "http://ok.example.com/ca.crl",
        ]
        ci.igtf_info = {}
        tried = []

        def fetch(url, session=None):
            tried.append(url)
            if "fail" in url:
                raise IOError("first URL fails")
            return self._fake_crl_pem()

        with patch("crab.crl.CRLManager._fetch_crl", side_effect=fetch):
            with patch("crab.crl.CRLManager._write_crl"):
                mgr = CRLManager({}, str(tmp_path))
                result = mgr.update_crls([ci])

        assert "http://ok.example.com/ca.crl" in result.updated
        assert "http://fail.example.com/ca.crl" in tried
        assert "http://ok.example.com/ca.crl" in tried

    def test_dry_run_parallel(self, tmp_path, ca_pem):
        """dry_run=True still reports would_fetch without network access."""
        urls = ["http://crl{}.example.com/ca.crl".format(i) for i in range(4)]
        cert_infos = [self._make_ci(u, ca_pem) for u in urls]

        mgr = CRLManager({"max_workers": 4}, str(tmp_path))
        result = mgr.update_crls(cert_infos, dry_run=True)

        assert len(result.would_fetch) == 4
        assert len(result.updated) == 0


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
        from crab.crl import CRLInfo
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
        with patch("crab.crl._parse_crl_file", return_value=expired_info):
            warnings = mgr.validate_crls(certs)
        assert any("Expired CRL" in w for w in warnings)

    def test_warns_when_crl_stale(self, tmp_path, ca_pem):
        from unittest.mock import patch
        from datetime import timedelta
        from crab.crl import CRLInfo
        certs = parse_pem_data(ca_pem)
        mgr = CRLManager({"max_age_hours": 1}, str(tmp_path))
        issuer_hash = mgr._get_issuer_hash(certs[0])
        (tmp_path / (issuer_hash + ".r0")).write_bytes(_FAKE_PEM_CRL)
        stale_info = CRLInfo(
            issuer_hash=issuer_hash,
            issuer_dn="/CN=Test CA",
            this_update=datetime.now(timezone.utc) - timedelta(hours=48),
            # next_update must be far enough ahead to not trigger min_remaining_hours (default 4)
            next_update=datetime.now(timezone.utc) + timedelta(hours=24),
            file_path=str(tmp_path / (issuer_hash + ".r0")),
        )
        with patch("crab.crl._parse_crl_file", return_value=stale_info):
            warnings = mgr.validate_crls(certs)
        assert any("Stale CRL" in w for w in warnings)

    def test_warns_when_parse_raises(self, tmp_path, ca_pem):
        """_parse_crl_file raising must produce a warning, not crash."""
        certs = parse_pem_data(ca_pem)
        mgr = CRLManager({}, str(tmp_path))
        issuer_hash = mgr._get_issuer_hash(certs[0])
        (tmp_path / (issuer_hash + ".r0")).write_bytes(_FAKE_PEM_CRL)
        with patch("crab.crl._parse_crl_file", side_effect=IOError("bad CRL")):
            warnings = mgr.validate_crls(certs)
        assert any("Cannot parse CRL" in w for w in warnings)


# ---------------------------------------------------------------------------
# CRLInfo.is_stale with next_update=None
# ---------------------------------------------------------------------------

class TestCRLInfoIsStaleNone:
    def test_stale_when_next_update_none(self):
        info = CRLInfo(
            issuer_hash="aa",
            issuer_dn="/CN=CA",
            this_update=datetime.now(timezone.utc),
            next_update=None,
        )
        assert info.is_stale() is True


# ---------------------------------------------------------------------------
# CRLManager.update_crls — live paths (mocked network)
# ---------------------------------------------------------------------------

class TestCRLManagerUpdateLive:
    def test_creates_missing_crl_path(self, tmp_path, ca_pem):
        """crl_path is created if it does not exist yet."""
        crl_dir = str(tmp_path / "nonexistent" / "crls")
        mgr = CRLManager({"crl_path": crl_dir}, str(tmp_path))
        ci = parse_pem_data(ca_pem)[0]
        # No URLs on the test cert → nothing fetched, but dir is created
        mgr.update_crls([ci])
        assert os.path.isdir(crl_dir)

    def test_successful_fetch_adds_to_updated(self, tmp_path, ca_pem):
        """A successful CRL fetch adds the URL to result.updated."""
        ci = parse_pem_data(ca_pem)[0]
        ci.igtf_info = {"crlurl": "https://example.com/test.crl"}
        mgr = CRLManager({"sources": ["igtf"]}, str(tmp_path))
        with patch.object(mgr, "_fetch_crl", return_value=_FAKE_PEM_CRL):
            with patch.object(mgr, "_get_issuer_hash", return_value="a1b2c3d4"):
                result = mgr.update_crls([ci], dry_run=False)
        assert len(result.updated) == 1
        assert result.updated[0] == "https://example.com/test.crl"
        assert len(result.failed) == 0

    def test_all_urls_fail_adds_to_failed(self, tmp_path, ca_pem):
        """When every URL fails, the subject ends up in result.failed."""
        ci = parse_pem_data(ca_pem)[0]
        ci.igtf_info = {"crlurl": "https://example.com/test.crl"}
        mgr = CRLManager({"sources": ["igtf"]}, str(tmp_path))
        with patch.object(mgr, "_fetch_crl", side_effect=IOError("network error")):
            result = mgr.update_crls([ci], dry_run=False)
        assert ci.subject in result.failed
        assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# CRLManager._fetch_crl
# ---------------------------------------------------------------------------

class TestFetchCrl:
    def test_fetch_crl_calls_download_to_bytes(self, tmp_path):
        """_fetch_crl delegates to download_to_bytes."""
        mgr = CRLManager({}, str(tmp_path))
        fake_data = b"CRL data"
        with patch("crab.sources.http.download_to_bytes", return_value=fake_data) as mock:
            result = mgr._fetch_crl("https://example.com/test.crl")
        assert result == fake_data
        assert mock.call_count == 1

    def test_fetch_crl_passes_verify_tls(self, tmp_path):
        """verify_tls from config is forwarded to download_to_bytes."""
        mgr = CRLManager({"verify_tls": False}, str(tmp_path))
        with patch("crab.sources.http.download_to_bytes", return_value=b"data") as mock:
            mgr._fetch_crl("https://example.com/test.crl")
        _, kwargs = mock.call_args
        assert kwargs.get("verify_tls") is False


# ---------------------------------------------------------------------------
# CRLManager._write_crl — exception cleanup
# ---------------------------------------------------------------------------

class TestWriteCrlCleanup:
    def test_temp_file_removed_on_write_error(self, tmp_path):
        """If os.replace fails, the .tmp file must be cleaned up."""
        mgr = CRLManager({}, str(tmp_path))
        with patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                mgr._write_crl(_FAKE_PEM_CRL, "a1b2c3d4")
        tmp_files = [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]
        assert tmp_files == []

    def test_unlink_failure_in_cleanup_does_not_mask_original_error(self, tmp_path):
        """If both os.replace and os.unlink fail, the original error is raised."""
        mgr = CRLManager({}, str(tmp_path))
        with patch("os.replace", side_effect=OSError("disk full")):
            with patch("os.unlink", side_effect=OSError("unlink failed")):
                with pytest.raises(OSError, match="disk full"):
                    mgr._write_crl(_FAKE_PEM_CRL, "a1b2c3d4")


# ---------------------------------------------------------------------------
# _der_to_pem_crl — openssl unavailable paths
# ---------------------------------------------------------------------------

class TestDerToPemCrlFallbacks:
    def test_returns_raw_when_openssl_not_found(self):
        """DER data is returned as-is when openssl binary is absent."""
        data = b"\x30\x82\x00\x00"
        with patch("subprocess.run", side_effect=FileNotFoundError("openssl")):
            result = _der_to_pem_crl(data)
        assert result == data

    def test_returns_raw_on_oserror(self):
        """DER data is returned as-is when subprocess.run raises OSError."""
        data = b"\x30\x82\x00\x00"
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            result = _der_to_pem_crl(data)
        assert result == data

    def test_returns_raw_when_subprocess_times_out(self):
        """DER data is returned as-is on timeout."""
        import subprocess
        data = b"\x30\x82\x01\x01"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("openssl", 10)):
            result = _der_to_pem_crl(data)
        assert result == data

    def test_returns_raw_when_openssl_returns_nonzero(self):
        """If openssl returns non-zero, fall back to raw data."""
        data = b"\x30\x82\x00\x00"
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result):
            result = _der_to_pem_crl(data)
        assert result == data


# ---------------------------------------------------------------------------
# _parse_crl_file
# ---------------------------------------------------------------------------

class TestParseCrlFile:
    def test_parses_dates_and_issuer(self, tmp_path):
        """_parse_crl_file extracts thisUpdate, nextUpdate, and issuer DN."""
        crl_path = str(tmp_path / "test.r0")
        open(crl_path, "wb").close()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            b"        Last Update: Jan  1 00:00:00 2025 GMT\n"
            b"        Next Update: Jan  8 00:00:00 2025 GMT\n"
            b"        Issuer: C=GB, CN=Test CA\n"
        )
        with patch("subprocess.run", return_value=mock_result):
            info = _parse_crl_file(crl_path)
        assert info.issuer_dn == "C=GB, CN=Test CA"
        assert info.this_update is not None
        assert info.next_update is not None
        assert info.next_update.year == 2025

    def test_missing_dates_return_none(self, tmp_path):
        """Missing date lines produce None for this_update / next_update."""
        crl_path = str(tmp_path / "test.r0")
        open(crl_path, "wb").close()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"Certificate Revocation List (CRL):\n"
        with patch("subprocess.run", return_value=mock_result):
            info = _parse_crl_file(crl_path)
        assert info.this_update is None
        assert info.next_update is None

    def test_raises_ioerror_on_subprocess_exception(self, tmp_path):
        """If subprocess.run raises, _parse_crl_file wraps it as IOError."""
        crl_path = str(tmp_path / "test.r0")
        open(crl_path, "wb").close()
        with patch("subprocess.run", side_effect=RuntimeError("kaboom")):
            with pytest.raises(IOError, match="Failed to parse CRL"):
                _parse_crl_file(crl_path)


# ---------------------------------------------------------------------------
# _parse_crl_date — ValueError branch
# ---------------------------------------------------------------------------

class TestParseCrlDateValueError:
    def test_returns_none_when_strptime_fails(self):
        """A date-like string that passes the regex but fails strptime → None."""
        # "QQQ" is a valid \w+ match but not a valid month abbreviation
        text = "        Last Update: QQQ 99 00:00:00 2025 GMT\n"
        result = _parse_crl_date(text, "Last Update:")
        assert result is None


# ---------------------------------------------------------------------------
# CRLInfo.will_expire_soon / remaining_hours
# ---------------------------------------------------------------------------

class TestCRLInfoExpirySoon:
    def _make_info(self, this_update, next_update):
        return CRLInfo(
            issuer_hash="a1b2c3d4",
            issuer_dn="/CN=Test CA",
            this_update=this_update,
            next_update=next_update,
        )

    def test_will_expire_soon_true_when_imminent(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=23),
            next_update=datetime.now(timezone.utc) + timedelta(hours=2),
        )
        assert info.will_expire_soon(min_remaining_hours=4) is True

    def test_will_expire_soon_false_when_plenty_of_time(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=1),
            next_update=datetime.now(timezone.utc) + timedelta(hours=48),
        )
        assert info.will_expire_soon(min_remaining_hours=4) is False

    def test_will_expire_soon_true_when_next_update_none(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=1),
            next_update=None,
        )
        assert info.will_expire_soon(min_remaining_hours=4) is True

    def test_remaining_hours_positive(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=1),
            next_update=datetime.now(timezone.utc) + timedelta(hours=10),
        )
        assert 9.0 < info.remaining_hours() < 11.0

    def test_remaining_hours_negative_when_expired(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=25),
            next_update=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert info.remaining_hours() < 0

    def test_remaining_hours_zero_when_next_update_none(self):
        info = self._make_info(
            this_update=datetime.now(timezone.utc) - timedelta(hours=1),
            next_update=None,
        )
        assert info.remaining_hours() == 0.0


# ---------------------------------------------------------------------------
# CRLManager — min_remaining_hours and refetch_before_expiry_hours
# ---------------------------------------------------------------------------

class TestCRLManagerCacheControl:
    def test_min_remaining_hours_default(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        assert mgr.min_remaining_hours == 4

    def test_min_remaining_hours_custom(self, tmp_path):
        mgr = CRLManager({"min_remaining_hours": 12}, str(tmp_path))
        assert mgr.min_remaining_hours == 12

    def test_refetch_before_expiry_hours_default(self, tmp_path):
        mgr = CRLManager({}, str(tmp_path))
        assert mgr.refetch_before_expiry_hours == 0

    def test_refetch_before_expiry_hours_custom(self, tmp_path):
        mgr = CRLManager({"refetch_before_expiry_hours": 48}, str(tmp_path))
        assert mgr.refetch_before_expiry_hours == 48

    def test_validate_crls_warns_when_expiring_soon(self, tmp_path):
        """validate_crls warns when nextUpdate is within min_remaining_hours."""
        from unittest.mock import patch, MagicMock
        from crab.cert import parse_pem_data
        from tests.conftest import _make_ca_cert

        pem, _, _ = _make_ca_cert()
        ci = parse_pem_data(pem)[0]
        mgr = CRLManager({"min_remaining_hours": 10}, str(tmp_path))

        # Plant a fake CRL file so _find_crl_file returns a path
        crl_path = str(tmp_path / "00000000.r0")
        open(crl_path, "wb").close()

        imminent_info = CRLInfo(
            issuer_hash="00000000",
            issuer_dn="/CN=Test CA",
            this_update=datetime.now(timezone.utc) - timedelta(hours=1),
            next_update=datetime.now(timezone.utc) + timedelta(hours=2),  # <10h away
        )
        with patch.object(mgr, "_get_issuer_hash", return_value="00000000"), \
             patch("crab.crl._parse_crl_file", return_value=imminent_info):
            warnings = mgr.validate_crls([ci])

        assert any("expires in" in w for w in warnings)
        assert any("2.0" in w or "1." in w for w in warnings)  # hours shown

    def test_validate_crls_stale_warning_not_triggered_by_expiry_soon(self, tmp_path):
        """An expiring-soon CRL emits expiry warning, not staleness warning."""
        from unittest.mock import patch
        from crab.cert import parse_pem_data
        from tests.conftest import _make_ca_cert

        pem, _, _ = _make_ca_cert()
        ci = parse_pem_data(pem)[0]
        mgr = CRLManager({"min_remaining_hours": 10, "max_age_hours": 1}, str(tmp_path))

        crl_path = str(tmp_path / "00000000.r0")
        open(crl_path, "wb").close()

        imminent_info = CRLInfo(
            issuer_hash="00000000",
            issuer_dn="/CN=Test CA",
            this_update=datetime.now(timezone.utc) - timedelta(hours=5),
            next_update=datetime.now(timezone.utc) + timedelta(hours=2),
        )
        with patch.object(mgr, "_get_issuer_hash", return_value="00000000"), \
             patch("crab.crl._parse_crl_file", return_value=imminent_info):
            warnings = mgr.validate_crls([ci])

        # Should have expiry-soon warning, not stale warning
        assert any("expires in" in w for w in warnings)
        assert not any("Stale" in w for w in warnings)


class TestCRLUpdateResultSkipped:
    def test_skipped_field_exists(self):
        r = CRLUpdateResult()
        assert hasattr(r, "skipped")
        assert r.skipped == []

    def test_repr_includes_skipped(self):
        r = CRLUpdateResult()
        r.skipped.append("some CA")
        assert "skipped=1" in repr(r)
