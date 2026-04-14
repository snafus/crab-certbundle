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
