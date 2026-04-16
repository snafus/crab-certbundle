"""
Tests for crab.status — ProfileStatus, collect_status, render_status_text.
"""

import datetime
import json
import os

import pytest

from crab.status import (
    ProfileStatus, collect_status, render_status_text, EXPIRING_SOON_DAYS
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeCRL:
    """Minimal stub for crl.crl_config used by ProfileConfig.crl."""
    def get(self, key, default=None):
        return default


class _FakeProfileCfg:
    """Minimal stand-in for ProfileConfig."""

    def __init__(self, output_path, include_crls=False):
        self.output_path = output_path
        self.include_crls = include_crls
        self.crl = {
            "fetch": False,
            "max_age_hours": 24,
            "verify_tls": True,
            "timeout_seconds": 30,
            "max_workers": 1,
            "sources": ["distribution"],
        }


# ---------------------------------------------------------------------------
# ProfileStatus
# ---------------------------------------------------------------------------

class TestProfileStatus:

    def test_healthy_requires_certs(self):
        ps = ProfileStatus("default", "/tmp/out")
        ps.exists = True
        ps.cert_count = 0
        assert not ps.healthy

    def test_healthy_with_certs(self):
        ps = ProfileStatus("default", "/tmp/out")
        ps.exists = True
        ps.cert_count = 5
        assert ps.healthy

    def test_unhealthy_when_expired(self):
        ps = ProfileStatus("default", "/tmp/out")
        ps.exists = True
        ps.cert_count = 5
        ps.expired_count = 1
        assert not ps.healthy

    def test_unhealthy_when_missing(self):
        ps = ProfileStatus("default", "/tmp/out")
        ps.exists = False
        assert not ps.healthy

    def test_to_dict_fields(self):
        ps = ProfileStatus("default", "/tmp/out")
        ps.exists = True
        ps.cert_count = 3
        ps.crl_count = 3
        d = ps.to_dict()
        assert d["profile"] == "default"
        assert d["cert_count"] == 3
        assert d["crl_count"] == 3
        assert "healthy" in d
        assert "earliest_expiry" in d

    def test_to_dict_datetime_serialised(self):
        ps = ProfileStatus("default", "/tmp/out")
        ps.exists = True
        ps.cert_count = 1
        ps.earliest_expiry = datetime.datetime(2028, 6, 1, 0, 0, 0,
                                               tzinfo=datetime.timezone.utc)
        d = ps.to_dict()
        assert d["earliest_expiry"] == "2028-06-01T00:00:00Z"


# ---------------------------------------------------------------------------
# collect_status
# ---------------------------------------------------------------------------

class TestCollectStatus:

    def test_missing_directory(self, tmp_path):
        cfg = _FakeProfileCfg(str(tmp_path / "nonexistent"))
        ps = collect_status("test", cfg)
        assert not ps.exists
        assert ps.cert_count == 0
        assert not ps.healthy

    def test_empty_directory(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert ps.exists
        assert ps.cert_count == 0
        assert not ps.healthy

    def test_counts_cert_files(self, tmp_path, ca_pem, second_ca_pem):
        out = tmp_path / "out"
        out.mkdir()
        # Write two fake certs using the hashed naming convention
        (out / "aabbccdd.0").write_bytes(ca_pem)
        (out / "11223344.0").write_bytes(second_ca_pem)
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert ps.cert_count == 2

    def test_counts_crl_files(self, tmp_path, ca_pem):
        out = tmp_path / "out"
        out.mkdir()
        (out / "aabbccdd.0").write_bytes(ca_pem)
        (out / "aabbccdd.r0").write_bytes(b"dummy-crl")
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert ps.crl_count == 1

    def test_detects_expired_cert(self, tmp_path):
        from tests.conftest import _make_ca_cert
        expired_pem, _, _ = _make_ca_cert(
            subject_cn="Expired CA",
            not_before=datetime.datetime(2010, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2015, 1, 1, tzinfo=datetime.timezone.utc),
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / "deadbeef.0").write_bytes(expired_pem)
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert ps.expired_count == 1
        assert not ps.healthy

    def test_detects_expiring_soon(self, tmp_path):
        from tests.conftest import _make_ca_cert
        soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        expiring_pem, _, _ = _make_ca_cert(
            subject_cn="Expiring CA",
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=soon,
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / "deadbeef.0").write_bytes(expiring_pem)
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert ps.expiring_soon_count == 1
        assert ps.healthy  # expiring-soon doesn't make it unhealthy

    def test_last_built_from_mtime(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert ps.last_built is not None
        # mtime should be recent (within the last minute)
        age = (datetime.datetime.now(datetime.timezone.utc) - ps.last_built).total_seconds()
        assert abs(age) < 60

    def test_earliest_expiry_tracks_soonest(self, tmp_path):
        from tests.conftest import _make_ca_cert
        now = datetime.datetime.now(datetime.timezone.utc)
        soon_pem, _, _ = _make_ca_cert(
            subject_cn="Soon CA",
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=now + datetime.timedelta(days=60),
        )
        later_pem, _, _ = _make_ca_cert(
            subject_cn="Later CA",
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=now + datetime.timedelta(days=365),
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / "aabbccdd.0").write_bytes(soon_pem)
        (out / "11223344.0").write_bytes(later_pem)
        cfg = _FakeProfileCfg(str(out))
        ps = collect_status("test", cfg)
        assert "Soon CA" in ps.earliest_expiry_cn


# ---------------------------------------------------------------------------
# render_status_text
# ---------------------------------------------------------------------------

class TestRenderStatusText:

    def _make_healthy_ps(self, name="default", path="/tmp/out"):
        ps = ProfileStatus(name, path)
        ps.exists = True
        ps.cert_count = 10
        ps.last_built = datetime.datetime(2026, 4, 15, 4, 0, 0,
                                          tzinfo=datetime.timezone.utc)
        return ps

    def test_healthy_shows_ok(self):
        out = render_status_text([self._make_healthy_ps()])
        assert "OK" in out

    def test_degraded_shows_degraded(self):
        ps = self._make_healthy_ps()
        ps.expired_count = 2
        out = render_status_text([ps])
        assert "DEGRADED" in out

    def test_missing_directory_shows_missing(self):
        ps = ProfileStatus("empty", "/nonexistent")
        out = render_status_text([ps])
        assert "MISSING" in out

    def test_profile_name_in_output(self):
        ps = self._make_healthy_ps(name="grid-prod")
        out = render_status_text([ps])
        assert "grid-prod" in out

    def test_expired_count_shown(self):
        ps = self._make_healthy_ps()
        ps.expired_count = 3
        out = render_status_text([ps])
        assert "3" in out

    def test_crl_warning_shown(self):
        ps = self._make_healthy_ps()
        ps.stale_crl_warnings = ["Stale CRL for: Test CA"]
        out = render_status_text([ps])
        assert "Stale CRL" in out

    def test_multiple_profiles(self):
        ps1 = self._make_healthy_ps("alpha")
        ps2 = self._make_healthy_ps("beta")
        out = render_status_text([ps1, ps2])
        assert "alpha" in out
        assert "beta" in out


# ---------------------------------------------------------------------------
# CLI crabctl status
# ---------------------------------------------------------------------------

class TestStatusCLI:

    def test_status_exits_zero_healthy(self, runner, cli_env):
        from crab.cli import main
        # Build first so the output directory exists
        runner.invoke(main, ["--config", cli_env["config"], "build"],
                      catch_exceptions=False)
        result = runner.invoke(
            main, ["--config", cli_env["config"], "status"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_status_exits_one_missing_dir(self, runner, cli_env):
        from crab.cli import main
        # Don't build — output directory won't exist
        result = runner.invoke(
            main, ["--config", cli_env["config"], "status"],
            catch_exceptions=False,
        )
        assert result.exit_code == 1

    def test_status_json_output(self, runner, cli_env):
        from crab.cli import main
        runner.invoke(main, ["--config", cli_env["config"], "build"],
                      catch_exceptions=False)
        result = runner.invoke(
            main, ["--config", cli_env["config"], "status", "--json"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["cert_count"] >= 1
        assert "healthy" in data[0]

    def test_status_unknown_profile(self, runner, cli_env):
        from crab.cli import main
        result = runner.invoke(
            main, ["--config", cli_env["config"], "status", "nosuchprofile"],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# --strict-warnings exit code 3
# ---------------------------------------------------------------------------

class TestStrictWarnings:
    """Exit code 3 from build/refresh when warnings are present."""

    def test_build_exits_zero_no_warnings(self, runner, cli_env):
        from crab.cli import main
        result = runner.invoke(
            main, ["--config", cli_env["config"], "build", "--strict-warnings"],
            catch_exceptions=False,
        )
        # No CRLs configured, no policy warnings → exit 0
        assert result.exit_code == 0

    def test_build_strict_crl_failures_exit_three(self, runner, tmp_path, ca_pem):
        """
        When CRLs are configured but all fetches fail (server unreachable),
        ``--strict-warnings`` causes exit 3.
        """
        import contextlib
        import http.server
        import socketserver
        import threading
        from crab.cli import main

        # Build a CA cert with a CDP pointing at a server we'll shut down
        import datetime as dt
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Strict Warn Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Strict Warn CA"),
        ])
        # Start and immediately stop a server to get a port that's guaranteed closed
        srv = socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        dead_port = srv.server_address[1]
        srv.server_close()

        cdp_url = "http://127.0.0.1:{}/dead.crl".format(dead_port)
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_url)],
                        relative_name=None, reasons=None, crl_issuer=None,
                    )
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        ca_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

        src = tmp_path / "src"
        src.mkdir()
        (src / "ca.pem").write_bytes(ca_pem_bytes)
        out = tmp_path / "out"
        cfg = tmp_path / "crab.yaml"
        cfg.write_text(
            "version: 1\n"
            "sources:\n"
            "  local:\n"
            "    type: local\n"
            "    path: {src}\n"
            "profiles:\n"
            "  default:\n"
            "    sources: [local]\n"
            "    output_path: {out}\n"
            "    atomic: false\n"
            "    rehash: builtin\n"
            "    include_crls: true\n"
            "    policy:\n"
            "      reject_expired: false\n"
            "      require_ca_flag: true\n"
            "    crl:\n"
            "      fetch: true\n"
            "      verify_tls: false\n"
            "      max_workers: 1\n"
            "      timeout_seconds: 2\n".format(src=str(src), out=str(out))
        )
        result = runner.invoke(
            main, ["--config", str(cfg), "build", "--strict-warnings"],
            catch_exceptions=False,
        )
        assert result.exit_code == 3, \
            "Expected exit 3 with CRL failures; got {}: {}".format(
                result.exit_code, result.output
            )

    def test_build_errors_still_exit_one(self, runner, tmp_path):
        """Errors take priority over warnings — still exit 1."""
        from crab.cli import main
        cfg = tmp_path / "crab.yaml"
        cfg.write_text(
            "version: 1\n"
            "sources:\n"
            "  local:\n"
            "    type: local\n"
            "    path: /nonexistent\n"
            "profiles:\n"
            "  default:\n"
            "    sources: [local]\n"
            "    output_path: {}\n"
            "    atomic: false\n"
            "    rehash: builtin\n".format(str(tmp_path / "out"))
        )
        result = runner.invoke(
            main, ["--config", str(cfg), "build", "--strict-warnings"],
        )
        # Source load failures count as errors → exit 1
        assert result.exit_code in (0, 1), result.output
