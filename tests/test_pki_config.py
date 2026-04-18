"""
Tests for crab.pki_config — declarative PKI hierarchy builder.
"""

import os
import textwrap

import pytest
import yaml

from crab.pki_config import (
    PKIConfigError,
    BuildResult,
    load_pki_config,
    build_pki_hierarchy,
)
from crab.pki import CADirectory
from crab.cli import main
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    return CliRunner()


def _write_config(tmp_path, content):
    """Write a pki.yaml string to a temp file and return its path."""
    p = tmp_path / "pki.yaml"
    p.write_text(textwrap.dedent(content))
    return str(p)


# ---------------------------------------------------------------------------
# load_pki_config
# ---------------------------------------------------------------------------

class TestLoadPkiConfig:
    def test_minimal_valid(self, tmp_path):
        cfg_path = _write_config(tmp_path, """
            version: 1
            root:
              dir: ./pki/root
              cn: Test Root CA
        """)
        cfg = load_pki_config(cfg_path)
        assert cfg["root"]["cn"] == "Test Root CA"

    def test_missing_root_key(self, tmp_path):
        cfg_path = _write_config(tmp_path, "version: 1\n")
        with pytest.raises(PKIConfigError, match="'root'"):
            load_pki_config(cfg_path)

    def test_missing_version(self, tmp_path):
        cfg_path = _write_config(tmp_path, "root:\n  dir: x\n  cn: y\n")
        with pytest.raises(PKIConfigError, match="version"):
            load_pki_config(cfg_path)

    def test_wrong_version(self, tmp_path):
        cfg_path = _write_config(tmp_path, "version: 99\nroot:\n  dir: x\n  cn: y\n")
        with pytest.raises(PKIConfigError, match="version"):
            load_pki_config(cfg_path)

    def test_missing_required_cn(self, tmp_path):
        cfg_path = _write_config(tmp_path, "version: 1\nroot:\n  dir: ./x\n")
        with pytest.raises(PKIConfigError, match="cn"):
            load_pki_config(cfg_path)

    def test_missing_required_dir(self, tmp_path):
        cfg_path = _write_config(tmp_path, "version: 1\nroot:\n  cn: Root\n")
        with pytest.raises(PKIConfigError, match="dir"):
            load_pki_config(cfg_path)

    def test_file_not_found(self, tmp_path):
        with pytest.raises(PKIConfigError, match="Cannot read"):
            load_pki_config(str(tmp_path / "nonexistent.yaml"))

    def test_invalid_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("{{invalid: yaml: :")
        with pytest.raises(PKIConfigError, match="YAML parse error"):
            load_pki_config(str(p))


# ---------------------------------------------------------------------------
# build_pki_hierarchy — root CA only
# ---------------------------------------------------------------------------

class TestBuildRootOnly:
    def test_creates_root_ca(self, tmp_path):
        root_dir = str(tmp_path / "root")
        cfg_path = _write_config(tmp_path, """
            version: 1
            root:
              dir: {root}
              cn: Test Root CA
              key_type: ecdsa-p256
              days: 365
        """.format(root=root_dir))
        result = build_pki_hierarchy(cfg_path)
        assert result.ok
        assert "Test Root CA" in result.cas_created
        assert CADirectory(root_dir).exists()

    def test_skips_existing_root(self, tmp_path):
        from crab.pki import init_ca
        root_dir = str(tmp_path / "root")
        init_ca(root_dir, cn="Pre-existing Root", key_type="ecdsa-p256", days=365)
        cfg_path = _write_config(tmp_path, """
            version: 1
            root:
              dir: {root}
              cn: Pre-existing Root
              days: 365
        """.format(root=root_dir))
        result = build_pki_hierarchy(cfg_path)
        assert result.ok
        assert "Pre-existing Root" in result.cas_skipped
        assert result.cas_created == []

    def test_dry_run_does_not_create_ca(self, tmp_path):
        root_dir = str(tmp_path / "root")
        cfg_path = _write_config(tmp_path, """
            version: 1
            root:
              dir: {root}
              cn: Dry Run Root
              key_type: ecdsa-p256
              days: 365
        """.format(root=root_dir))
        result = build_pki_hierarchy(cfg_path, dry_run=True)
        assert result.ok
        assert "Dry Run Root" in result.cas_created  # counted but not written
        assert not os.path.exists(root_dir)


# ---------------------------------------------------------------------------
# build_pki_hierarchy — with intermediate and certs
# ---------------------------------------------------------------------------

class TestBuildHierarchy:
    @pytest.fixture
    def full_config(self, tmp_path):
        root_dir  = str(tmp_path / "root")
        inter_dir = str(tmp_path / "issuing")
        cfg_path = _write_config(tmp_path, """
            version: 1
            root:
              dir: {root}
              cn: Test Root CA
              key_type: ecdsa-p256
              days: 365
              intermediates:
                - dir: {inter}
                  cn: Test Issuing CA
                  key_type: ecdsa-p256
                  days: 365
                  path_length: 0
                  certs:
                    - cn: host.example.com
                      profile: server
                      days: 90
                      san:
                        - DNS:host.example.com
                    - cn: alice
                      profile: client
                      days: 90
                      san:
                        - EMAIL:alice@example.com
        """.format(root=root_dir, inter=inter_dir))
        return cfg_path, root_dir, inter_dir

    def test_creates_full_hierarchy(self, full_config):
        cfg_path, root_dir, inter_dir = full_config
        result = build_pki_hierarchy(cfg_path)
        assert result.ok
        assert "Test Root CA" in result.cas_created
        assert "Test Issuing CA" in result.cas_created
        assert "host.example.com" in result.certs_issued
        assert "alice" in result.certs_issued
        assert CADirectory(root_dir).exists()
        assert CADirectory(inter_dir).exists()
        assert os.path.isfile(
            os.path.join(inter_dir, "issued", "host.example.com-cert.pem")
        )
        assert os.path.isfile(
            os.path.join(inter_dir, "issued", "alice-cert.pem")
        )

    def test_idempotent_second_run(self, full_config):
        cfg_path, root_dir, inter_dir = full_config
        build_pki_hierarchy(cfg_path)
        result = build_pki_hierarchy(cfg_path)
        assert result.ok
        assert result.cas_created == []
        assert result.certs_issued == []
        assert "Test Root CA" in result.cas_skipped
        assert "Test Issuing CA" in result.cas_skipped
        assert "host.example.com" in result.certs_skipped
        assert "alice" in result.certs_skipped

    def test_force_certs_reissues(self, full_config):
        cfg_path, root_dir, inter_dir = full_config
        build_pki_hierarchy(cfg_path)
        result = build_pki_hierarchy(cfg_path, force_certs=True)
        assert result.ok
        assert "host.example.com" in result.certs_issued
        assert "alice" in result.certs_issued
        assert result.cas_created == []   # CAs never regenerated

    def test_fullchain_written_for_intermediate_certs(self, full_config):
        cfg_path, root_dir, inter_dir = full_config
        build_pki_hierarchy(cfg_path)
        assert os.path.isfile(
            os.path.join(inter_dir, "issued", "host.example.com-fullchain.pem")
        )

    def test_root_certs_issued_directly(self, tmp_path):
        root_dir = str(tmp_path / "root")
        cfg_path = _write_config(tmp_path, """
            version: 1
            root:
              dir: {root}
              cn: Test Root CA
              key_type: ecdsa-p256
              days: 365
              certs:
                - cn: direct.example.com
                  profile: server
                  days: 90
        """.format(root=root_dir))
        result = build_pki_hierarchy(cfg_path)
        assert result.ok
        assert "direct.example.com" in result.certs_issued
        assert os.path.isfile(
            os.path.join(root_dir, "issued", "direct.example.com-cert.pem")
        )

    def test_dry_run_no_files_written(self, full_config):
        cfg_path, root_dir, inter_dir = full_config
        result = build_pki_hierarchy(cfg_path, dry_run=True)
        assert result.ok
        assert not os.path.exists(root_dir)
        assert not os.path.exists(inter_dir)
        assert "Test Root CA" in result.cas_created
        assert "host.example.com" in result.certs_issued


# ---------------------------------------------------------------------------
# CLI — pki build
# ---------------------------------------------------------------------------

class TestPkiBuildCLI:
    def test_build_prints_summary(self, runner, tmp_path):
        root_dir = str(tmp_path / "root")
        cfg = tmp_path / "pki.yaml"
        cfg.write_text(
            "version: 1\nroot:\n  dir: {}\n  cn: CLI Root\n"
            "  key_type: ecdsa-p256\n  days: 365\n".format(root_dir)
        )
        result = runner.invoke(main, ["pki", "build", str(cfg)])
        assert result.exit_code == 0
        assert "Created CA" in result.output
        assert "CLI Root" in result.output

    def test_dry_run_flag(self, runner, tmp_path):
        root_dir = str(tmp_path / "root")
        cfg = tmp_path / "pki.yaml"
        cfg.write_text(
            "version: 1\nroot:\n  dir: {}\n  cn: Dry Root\n"
            "  key_type: ecdsa-p256\n  days: 365\n".format(root_dir)
        )
        result = runner.invoke(main, ["pki", "build", "--dry-run", str(cfg)])
        assert result.exit_code == 0
        assert "dry-run" in result.output.lower()
        assert not os.path.exists(root_dir)

    def test_bad_config_exits_1(self, runner, tmp_path):
        cfg = tmp_path / "bad.yaml"
        cfg.write_text("version: 1\n")
        result = runner.invoke(main, ["pki", "build", str(cfg)])
        assert result.exit_code == 1
        assert "ERROR" in result.output


# ---------------------------------------------------------------------------
# CLI — pki init-config
# ---------------------------------------------------------------------------

class TestPkiInitConfigCLI:
    def test_stdout(self, runner):
        result = runner.invoke(main, ["pki", "init-config"])
        assert result.exit_code == 0
        assert "version: 1" in result.output
        assert "root:" in result.output
        assert "intermediates:" in result.output
        assert "certs:" in result.output

    def test_write_to_file(self, runner, tmp_path):
        out = str(tmp_path / "pki.yaml")
        result = runner.invoke(main, ["pki", "init-config", "-o", out])
        assert result.exit_code == 0
        assert os.path.isfile(out)
        parsed = yaml.safe_load(open(out).read().split("\n", 20)[-1])  # skip comments
        assert "version: 1" in open(out).read()

    def test_refuses_overwrite(self, runner, tmp_path):
        out = str(tmp_path / "pki.yaml")
        open(out, "w").write("existing")
        result = runner.invoke(main, ["pki", "init-config", "-o", out])
        assert result.exit_code == 1
        assert "already exists" in result.output
        assert open(out).read() == "existing"

    def test_force_overwrites(self, runner, tmp_path):
        out = str(tmp_path / "pki.yaml")
        open(out, "w").write("old")
        result = runner.invoke(main, ["pki", "init-config", "-o", out, "--force"])
        assert result.exit_code == 0
        assert "version: 1" in open(out).read()
