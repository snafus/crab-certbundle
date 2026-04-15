"""
Integration tests — full build/validate pipeline using real files and the
real crabctl entry point invoked as a subprocess.

These tests do not touch the network.  They write a real config file,
run crabctl build against a temp directory of PEM files, and then run
crabctl validate to check the resulting CApath directory.

All tests use tmp_path and the session-scoped ca_pem / second_ca_pem
fixtures from the root conftest so no additional network access or
external CA data is required.
"""

import os
import subprocess
import sys
import textwrap

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _crabctl(*args, **kwargs):
    """Run crabctl as a subprocess.  Returns a CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "crab.cli"] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,  # text= alias not available in Python 3.6
        **kwargs
    )


def _write_config(path, source_dir, output_dir, staging_dir, output_format="capath", extra=""):
    """Write a minimal crab.yaml config to *path*."""
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            version: 1
            sources:
              local-ca:
                type: local
                path: {source_dir}
                pattern:
                  - "*.pem"
            profiles:
              test:
                sources: [local-ca]
                output_format: {output_format}
                output_path: {output_dir}
                staging_path: {staging_dir}
                atomic: true
                rehash: builtin
                include_igtf_meta: false
                include_crls: false
                policy:
                  reject_expired: false
                  require_ca_flag: true
            {extra}
        """).format(
            source_dir=source_dir,
            output_dir=output_dir,
            staging_path=staging_dir,
            staging_dir=staging_dir,
            output_format=output_format,
            extra=extra,
        ))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pem_source(tmp_path, ca_pem, second_ca_pem):
    """A temp directory containing two real CA PEM files."""
    src = tmp_path / "source"
    src.mkdir()
    (src / "root-ca.pem").write_bytes(ca_pem)
    (src / "second-ca.pem").write_bytes(second_ca_pem)
    return src


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBuildPipeline:
    """End-to-end build → validate using crabctl as a subprocess."""

    def test_build_creates_capath(self, tmp_path, pem_source):
        """crabctl build exits 0 and produces a populated CApath directory."""
        output_dir = tmp_path / "output"
        staging_dir = tmp_path / "staging"
        config = tmp_path / "crab.yaml"
        _write_config(str(config), str(pem_source), str(output_dir), str(staging_dir))

        result = _crabctl("--config", str(config), "build")

        assert result.returncode == 0, "build failed:\n" + result.stderr
        assert output_dir.is_dir(), "output directory was not created"

        # Should contain hash-named files like a1b2c3d4.0
        hash_files = [f for f in os.listdir(output_dir) if len(f) == 10 and f.endswith(".0")]
        assert len(hash_files) >= 1, "no hash-named cert files found in output"

    def test_build_validate_exits_zero(self, tmp_path, pem_source):
        """crabctl validate returns exit 0 on a freshly built directory."""
        output_dir = tmp_path / "output"
        staging_dir = tmp_path / "staging"
        config = tmp_path / "crab.yaml"
        _write_config(str(config), str(pem_source), str(output_dir), str(staging_dir))

        build = _crabctl("--config", str(config), "build")
        assert build.returncode == 0, build.stderr

        validate = _crabctl("--config", str(config), "validate", "--no-openssl")
        assert validate.returncode == 0, "validate failed:\n" + validate.stderr

    def test_build_is_idempotent(self, tmp_path, pem_source):
        """Running build twice produces the same set of output files."""
        output_dir = tmp_path / "output"
        staging_dir = tmp_path / "staging"
        config = tmp_path / "crab.yaml"
        _write_config(str(config), str(pem_source), str(output_dir), str(staging_dir))

        r1 = _crabctl("--config", str(config), "build")
        assert r1.returncode == 0, r1.stderr
        files_after_first = sorted(os.listdir(output_dir))

        r2 = _crabctl("--config", str(config), "build")
        assert r2.returncode == 0, r2.stderr
        files_after_second = sorted(os.listdir(output_dir))

        assert files_after_first == files_after_second

    def test_dry_run_writes_nothing(self, tmp_path, pem_source):
        """--dry-run exits 0 and does not create the output directory."""
        output_dir = tmp_path / "output"
        staging_dir = tmp_path / "staging"
        config = tmp_path / "crab.yaml"
        _write_config(str(config), str(pem_source), str(output_dir), str(staging_dir))

        result = _crabctl("--config", str(config), "build", "--dry-run")

        assert result.returncode == 0, result.stderr
        assert not output_dir.exists(), "dry-run should not write output directory"

    def test_build_pkcs12(self, tmp_path, pem_source):
        """output_format: pkcs12 produces a non-empty .p12 file."""
        output_file = tmp_path / "trust.p12"
        staging_dir = tmp_path / "staging"
        config = tmp_path / "crab.yaml"
        _write_config(
            str(config), str(pem_source), str(output_file), str(staging_dir),
            output_format="pkcs12",
        )

        result = _crabctl("--config", str(config), "build")

        assert result.returncode == 0, result.stderr
        assert output_file.is_file(), ".p12 file was not created"
        assert output_file.stat().st_size > 0

    def test_list_output(self, tmp_path, pem_source):
        """crabctl list reports the expected number of certificates."""
        output_dir = tmp_path / "output"
        staging_dir = tmp_path / "staging"
        config = tmp_path / "crab.yaml"
        _write_config(str(config), str(pem_source), str(output_dir), str(staging_dir))

        build = _crabctl("--config", str(config), "build")
        assert build.returncode == 0, build.stderr

        result = _crabctl("--config", str(config), "list", "test")
        assert result.returncode == 0, result.stderr
        # Two source PEM files → two certs listed
        assert "Total: 2 certificate(s)" in result.stdout

    def test_missing_config_exits_nonzero(self, tmp_path):
        """crabctl exits non-zero when the config file does not exist."""
        result = _crabctl("--config", str(tmp_path / "nonexistent.yaml"), "build")
        assert result.returncode != 0


class TestPKICLI:
    """Integration tests for crabctl ca / cert commands."""

    def test_ca_init_creates_files(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        result = _crabctl("-q", "ca", "init", ca_dir, "--name", "Integration Test CA")
        assert result.returncode == 0, result.stderr
        assert os.path.isfile(os.path.join(ca_dir, "ca-cert.pem"))
        assert os.path.isfile(os.path.join(ca_dir, "ca-key.pem"))
        assert os.path.isdir(os.path.join(ca_dir, "issued"))

    def test_ca_init_key_mode(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        import stat
        mode = stat.S_IMODE(os.stat(os.path.join(ca_dir, "ca-key.pem")).st_mode)
        assert mode == 0o600

    def test_ca_show_text(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir, "--name", "Show Test CA")
        result = _crabctl("-q", "ca", "show", ca_dir)
        assert result.returncode == 0, result.stderr
        assert "Show Test CA" in result.stdout
        assert "RSA-2048" in result.stdout
        assert "Issued certs  : 0" in result.stdout

    def test_ca_show_json(self, tmp_path):
        import json
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir, "--name", "JSON CA")
        result = _crabctl("-q", "ca", "show", ca_dir, "--json")
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["key_type"] == "RSA-2048"
        assert data["issued_count"] == 0

    def test_ca_init_ed25519(self, tmp_path):
        ca_dir = str(tmp_path / "ed-ca")
        result = _crabctl("-q", "ca", "init", ca_dir, "--key-type", "ed25519")
        assert result.returncode == 0, result.stderr
        info = _crabctl("-q", "ca", "show", ca_dir, "--json")
        import json
        assert json.loads(info.stdout)["key_type"] == "Ed25519"

    def test_ca_init_rejects_existing(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        result = _crabctl("-q", "ca", "init", ca_dir)
        assert result.returncode != 0
        assert "already exists" in result.stderr

    def test_ca_init_force(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir, "--name", "CA1")
        result = _crabctl("-q", "ca", "init", ca_dir, "--name", "CA2", "--force")
        assert result.returncode == 0, result.stderr

    def test_cert_issue_server(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        result = _crabctl("-q", "cert", "issue", "--ca", ca_dir, "--cn", "host.example.com")
        assert result.returncode == 0, result.stderr
        cert_path = os.path.join(ca_dir, "issued", "host.example.com-cert.pem")
        assert os.path.isfile(cert_path)

    def test_cert_issue_wildcard(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        result = _crabctl("-q", "cert", "issue",
                          "--ca", ca_dir,
                          "--cn", "*.example.com",
                          "--san", "DNS:example.com")
        assert result.returncode == 0, result.stderr
        # Verify SANs with openssl
        cert_path = os.path.join(ca_dir, "issued", "_.example.com-cert.pem")
        assert os.path.isfile(cert_path)
        verify = subprocess.run(
            ["openssl", "verify", "-CAfile", os.path.join(ca_dir, "ca-cert.pem"), cert_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert verify.returncode == 0, verify.stderr.decode()

    def test_cert_issue_grid_host(self, tmp_path):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        result = _crabctl("-q", "cert", "issue",
                          "--ca", ca_dir,
                          "--cn", "xrootd.example.com",
                          "--profile", "grid-host")
        assert result.returncode == 0, result.stderr
        cert_path = os.path.join(ca_dir, "issued", "xrootd.example.com-cert.pem")
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        eku = list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    def test_cert_list_and_revoke(self, tmp_path):
        import json
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        _crabctl("-q", "cert", "issue", "--ca", ca_dir, "--cn", "host.example.com")

        list_result = _crabctl("-q", "cert", "list", "--ca", ca_dir, "--json")
        assert list_result.returncode == 0
        records = json.loads(list_result.stdout)
        assert len(records) == 1
        assert records[0]["revoked"] is False

        cert_path = os.path.join(ca_dir, "issued", "host.example.com-cert.pem")
        revoke_result = _crabctl("-q", "cert", "revoke",
                                 "--ca", ca_dir, cert_path,
                                 "--reason", "superseded")
        assert revoke_result.returncode == 0, revoke_result.stderr
        assert os.path.isfile(os.path.join(ca_dir, "crl.pem"))

        list_after = _crabctl("-q", "cert", "list", "--ca", ca_dir, "--json")
        records_after = json.loads(list_after.stdout)
        assert records_after[0]["revoked"] is True
        assert records_after[0]["revoke_reason"] == "superseded"

    def test_cert_revoke_double_raises(self, tmp_path):
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir)
        _crabctl("-q", "cert", "issue", "--ca", ca_dir, "--cn", "host.example.com")
        cert_path = os.path.join(ca_dir, "issued", "host.example.com-cert.pem")
        _crabctl("-q", "cert", "revoke", "--ca", ca_dir, cert_path)
        result = _crabctl("-q", "cert", "revoke", "--ca", ca_dir, cert_path)
        assert result.returncode != 0
        assert "already revoked" in result.stderr


class TestPKIPipelineRoundTrip:
    """
    Full round-trip: generate a test CA with crab-pki, add its cert as a
    local source in a crab.yaml config, build a CApath directory, and
    validate that the CA cert appears in the output.
    """

    def test_ca_cert_appears_in_capath_build(self, tmp_path):
        """
        A CA created with 'crabctl ca init' can be added as a local source
        and will appear in the built CApath directory.
        """
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir, "--name", "Round-trip Test CA")

        ca_cert_path = os.path.join(ca_dir, "ca-cert.pem")
        output_dir = str(tmp_path / "output")
        staging_dir = str(tmp_path / "staging")
        config_path = str(tmp_path / "crab.yaml")

        _write_config(config_path, ca_dir, output_dir, staging_dir)

        build = _crabctl("--config", config_path, "-q", "build")
        assert build.returncode == 0, "build failed:\n" + build.stderr

        hash_files = [f for f in os.listdir(output_dir)
                      if len(f) == 10 and f.endswith(".0")]
        assert len(hash_files) == 1, \
            "expected 1 hashed cert in output; got: {}".format(hash_files)

        validate = _crabctl("--config", config_path, "-q",
                            "validate", "--no-openssl")
        assert validate.returncode == 0, "validate failed:\n" + validate.stderr

    def test_issued_cert_verifies_against_capath(self, tmp_path):
        """
        A cert issued by the test CA can be verified with openssl verify
        using the built CApath directory.
        """
        ca_dir = str(tmp_path / "my-ca")
        _crabctl("-q", "ca", "init", ca_dir, "--name", "Verify Test CA")
        _crabctl("-q", "cert", "issue", "--ca", ca_dir, "--cn", "host.example.com")

        output_dir = str(tmp_path / "output")
        config_path = str(tmp_path / "crab.yaml")
        _write_config(config_path, ca_dir, output_dir, str(tmp_path / "staging"))

        build = _crabctl("--config", config_path, "-q", "build")
        assert build.returncode == 0, build.stderr

        cert_path = os.path.join(ca_dir, "issued", "host.example.com-cert.pem")
        verify = subprocess.run(
            ["openssl", "verify", "-CApath", output_dir, cert_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert verify.returncode == 0, \
            "openssl verify failed: " + verify.stderr.decode()
