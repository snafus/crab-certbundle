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

import contextlib
import datetime
import http.server
import os
import socketserver
import subprocess
import sys
import textwrap
import threading

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


class TestFetchCRLsIntegration:
    """
    End-to-end integration tests for 'crabctl fetch-crls'.

    A real HTTP server (socketserver.TCPServer on port 0) serves CRL bytes from
    memory.  CA certificates are generated with a CRLDistributionPoints extension
    pointing at the local server so the full fetch-crls pipeline can be exercised
    without any external network access.
    """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_ca_with_cdp(port, path="/ca.crl"):
        """
        Generate a self-signed CA cert + key + empty CRL, with the cert
        containing a CRLDistributionPoints extension pointing at
        ``http://127.0.0.1:<port><path>``.

        Returns ``(ca_pem_bytes, ca_key, crl_der_bytes)``.
        """
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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CRL Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CRL Test CA {}".format(path)),
        ])
        cdp_url = "http://127.0.0.1:{}{}".format(port, path)
        now = datetime.datetime.now(datetime.timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        ca_pem = cert.public_bytes(serialization.Encoding.PEM)

        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(name)
            .last_update(now - datetime.timedelta(seconds=1))
            .next_update(now + datetime.timedelta(days=7))
            .sign(key, hashes.SHA256(), default_backend())
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)

        return ca_pem, key, crl_der

    @staticmethod
    @contextlib.contextmanager
    def _http_server():
        """
        Start a local HTTP server on a random port; yield ``(port, crl_map)``
        where ``crl_map`` is a ``dict`` mapping URL paths to ``bytes`` that the
        caller populates before (or after) starting the server.
        """
        crl_map = {}

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                data = crl_map.get(self.path)
                if data is not None:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pkix-crl")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, fmt, *args):
                pass  # suppress HTTP access log noise

        server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()
        try:
            yield port, crl_map
        finally:
            server.shutdown()
            t.join(timeout=5)

    @staticmethod
    def _write_crl_config(config_path, source_dir, output_dir, staging_dir,
                          max_workers=1):
        """Write a crab.yaml with ``include_crls: true`` for *source_dir*."""
        with open(str(config_path), "w") as fh:
            fh.write(textwrap.dedent("""\
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
                    output_format: capath
                    output_path: {output_dir}
                    staging_path: {staging_dir}
                    atomic: true
                    rehash: builtin
                    include_igtf_meta: false
                    include_crls: true
                    policy:
                      reject_expired: false
                      require_ca_flag: true
                    crl:
                      fetch: true
                      verify_tls: false
                      max_workers: {max_workers}
                      timeout_seconds: 10
            """).format(
                source_dir=source_dir,
                output_dir=output_dir,
                staging_dir=staging_dir,
                max_workers=max_workers,
            ))

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_fetch_crls_dry_run(self, tmp_path):
        """
        ``--dry-run`` exits 0, logs the CDP URL, and writes no ``.r0`` file.
        """
        with self._http_server() as (port, _crl_map):
            ca_pem, _, _ = self._make_ca_with_cdp(port)
            source_dir = tmp_path / "source"
            source_dir.mkdir()
            (source_dir / "ca.pem").write_bytes(ca_pem)

            output_dir = tmp_path / "output"
            config = tmp_path / "crab.yaml"
            self._write_crl_config(
                config, str(source_dir), str(output_dir),
                str(tmp_path / "staging"),
            )

            result = _crabctl(
                "--config", str(config), "fetch-crls", "--dry-run", "test"
            )

        assert result.returncode == 0, "fetch-crls --dry-run failed:\n" + result.stderr
        # The CDP URL must appear in the INFO-level log written to stderr
        assert "127.0.0.1:{}".format(port) in result.stderr
        # No CRL file should have been written
        assert not output_dir.exists() or not any(
            f.endswith(".r0") for f in os.listdir(str(output_dir))
        )

    def test_fetch_crls_live(self, tmp_path):
        """
        A CRL is downloaded from the local HTTP server and the ``.r0`` file
        is written to the output directory.
        """
        with self._http_server() as (port, crl_map):
            ca_pem, _, crl_der = self._make_ca_with_cdp(port)
            crl_map["/ca.crl"] = crl_der

            source_dir = tmp_path / "source"
            source_dir.mkdir()
            (source_dir / "ca.pem").write_bytes(ca_pem)

            output_dir = tmp_path / "output"
            output_dir.mkdir()
            config = tmp_path / "crab.yaml"
            self._write_crl_config(
                config, str(source_dir), str(output_dir),
                str(tmp_path / "staging"),
            )

            result = _crabctl("--config", str(config), "fetch-crls", "test")

        assert result.returncode == 0, "fetch-crls failed:\n" + result.stderr
        r0_files = [f for f in os.listdir(str(output_dir)) if f.endswith(".r0")]
        assert len(r0_files) == 1, \
            "expected 1 .r0 CRL file in output; got: {}".format(r0_files)

    def test_fetch_crls_live_pem_format(self, tmp_path):
        """
        The written ``.r0`` file is in PEM format (openssl DER→PEM conversion ran).
        """
        with self._http_server() as (port, crl_map):
            ca_pem, _, crl_der = self._make_ca_with_cdp(port)
            crl_map["/ca.crl"] = crl_der

            source_dir = tmp_path / "source"
            source_dir.mkdir()
            (source_dir / "ca.pem").write_bytes(ca_pem)

            output_dir = tmp_path / "output"
            output_dir.mkdir()
            config = tmp_path / "crab.yaml"
            self._write_crl_config(
                config, str(source_dir), str(output_dir),
                str(tmp_path / "staging"),
            )

            _crabctl("--config", str(config), "fetch-crls", "test")

        r0_files = [f for f in os.listdir(str(output_dir)) if f.endswith(".r0")]
        assert r0_files, "no .r0 file written"
        content = (output_dir / r0_files[0]).read_bytes()
        assert content.lstrip().startswith(b"-----BEGIN X509 CRL-----"), \
            "expected PEM-format CRL; got: {!r}".format(content[:40])

    def test_fetch_crls_parallel(self, tmp_path):
        """
        Multiple CA certs are processed concurrently; all ``.r0`` files land
        in the output directory.
        """
        N = 4
        with self._http_server() as (port, crl_map):
            source_dir = tmp_path / "source"
            source_dir.mkdir()
            for i in range(N):
                path = "/ca{}.crl".format(i)
                ca_pem, _, crl_der = self._make_ca_with_cdp(port, path=path)
                crl_map[path] = crl_der
                (source_dir / "ca{}.pem".format(i)).write_bytes(ca_pem)

            output_dir = tmp_path / "output"
            output_dir.mkdir()
            config = tmp_path / "crab.yaml"
            self._write_crl_config(
                config, str(source_dir), str(output_dir),
                str(tmp_path / "staging"),
                max_workers=N,
            )

            result = _crabctl("--config", str(config), "fetch-crls", "test")

        assert result.returncode == 0, "fetch-crls failed:\n" + result.stderr
        r0_files = [f for f in os.listdir(str(output_dir)) if f.endswith(".r0")]
        assert len(r0_files) == N, \
            "expected {} .r0 CRL files; got: {}".format(N, r0_files)

    def test_fetch_crls_missing_url(self, tmp_path):
        """
        A CA cert without a CDP extension reports 'No URL' but exits 0.
        """
        # Use ca_pem from conftest — no CDP extension
        from tests.conftest import _make_ca_cert
        ca_pem, _, _ = _make_ca_cert(subject_cn="No-CDP CA")

        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "ca.pem").write_bytes(ca_pem)

        output_dir = tmp_path / "output"
        output_dir.mkdir()
        config = tmp_path / "crab.yaml"
        self._write_crl_config(
            config, str(source_dir), str(output_dir), str(tmp_path / "staging")
        )

        result = _crabctl("--config", str(config), "fetch-crls", "test")

        assert result.returncode == 0, result.stderr
        # CLI summary line should report 1 missing URL, 0 updated
        assert "No URL: 1" in result.stdout

    def test_fetch_crls_server_down(self, tmp_path):
        """
        When the CRL server is unreachable, fetch-crls exits 0 but reports
        a failure (no .r0 file written, error logged).
        """
        # Grab a port, let the server start, then shut it down before fetching
        with self._http_server() as (port, crl_map):
            ca_pem, _, crl_der = self._make_ca_with_cdp(port)
            crl_map["/ca.crl"] = crl_der
            source_dir = tmp_path / "source"
            source_dir.mkdir()
            (source_dir / "ca.pem").write_bytes(ca_pem)
            output_dir = tmp_path / "output"
            output_dir.mkdir()
            config = tmp_path / "crab.yaml"
            self._write_crl_config(
                config, str(source_dir), str(output_dir),
                str(tmp_path / "staging"),
            )
        # Server is now shut down — fetch will fail

        result = _crabctl("--config", str(config), "fetch-crls", "test")

        assert result.returncode == 0, \
            "fetch-crls should exit 0 even on fetch failure:\n" + result.stderr
        r0_files = [f for f in os.listdir(str(output_dir)) if f.endswith(".r0")]
        assert len(r0_files) == 0, "no .r0 file should be written on failure"
