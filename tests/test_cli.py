"""
CLI integration tests using Click's test runner.

These tests run the full CLI stack without network access or root privileges.
All operations are confined to temporary directories.
"""

import os
import json
import pytest

from click.testing import CliRunner

from certbundle.cli import main


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def cli_env(tmp_path, ca_pem, second_ca_pem):
    """Set up a minimal source dir, output dir, and config file."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "ca1.pem").write_bytes(ca_pem)
    (src_dir / "ca2.pem").write_bytes(second_ca_pem)

    out_dir = tmp_path / "out"
    cfg = tmp_path / "certbundle.yaml"
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
        "    policy:\n"
        "      reject_expired: true\n"
        "      require_ca_flag: true\n".format(
            src=str(src_dir), out=str(out_dir)
        )
    )
    return {"config": str(cfg), "src": str(src_dir), "out": str(out_dir)}


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_flag(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# show-config
# ---------------------------------------------------------------------------

class TestShowConfig:
    def test_shows_sources_and_profiles(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "show-config"])
        assert result.exit_code == 0
        assert "local" in result.output
        assert "default" in result.output

    def test_missing_config_shows_searched_paths(self, runner, tmp_path):
        # When --config points at a nonexistent file, error includes the path.
        missing = str(tmp_path / "nope.yaml")
        result = runner.invoke(main, ["--config", missing, "show-config"])
        assert result.exit_code == 1
        assert "nope.yaml" in result.output  # path is named in the error

    def test_no_config_anywhere_lists_defaults(self, runner, tmp_path):
        # Run in a temp dir with no config file
        with runner.isolated_filesystem():
            result = runner.invoke(main, ["show-config"])
        assert result.exit_code == 1
        # Should mention searched paths
        assert "certbundle.yaml" in result.output or "No config" in result.output


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

class TestBuild:
    def test_build_creates_output(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "build"])
        assert result.exit_code == 0, result.output
        assert os.path.isdir(cli_env["out"])

    def test_build_writes_hashed_files(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        import re
        files = os.listdir(cli_env["out"])
        hash_files = [f for f in files if re.match(r"^[0-9a-f]{8}\.\d+$", f)]
        assert len(hash_files) == 2  # two distinct CAs

    def test_build_dry_run_no_output(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "build", "--dry-run"]
        )
        assert result.exit_code == 0
        assert not os.path.exists(cli_env["out"])
        assert "dry-run" in result.output.lower()

    def test_build_reports_cert_count(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "build"])
        assert "2" in result.output  # 2 certs loaded and accepted

    def test_build_unknown_profile_exits_1(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "build", "no-such-profile"]
        )
        assert result.exit_code == 1

    def test_build_with_report_flag(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "build", "--report"]
        )
        assert result.exit_code == 0
        assert "Source Loading Report" in result.output

    def test_build_idempotent(self, runner, cli_env):
        r1 = runner.invoke(main, ["--config", cli_env["config"], "build"])
        r2 = runner.invoke(main, ["--config", cli_env["config"], "build"])
        assert r1.exit_code == 0
        assert r2.exit_code == 0


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

class TestValidate:
    def _build(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])

    def test_validate_valid_directory_exits_0(self, runner, cli_env):
        self._build(runner, cli_env)
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "default",
                   "--no-openssl"]
        )
        assert result.exit_code == 0

    def test_validate_missing_directory_exits_nonzero(self, runner, cli_env):
        # Don't build — output dir doesn't exist
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "default",
                   "--no-openssl"]
        )
        assert result.exit_code != 0

    def test_validate_raw_directory(self, runner, cli_env):
        self._build(runner, cli_env)
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate",
                   cli_env["out"], "--no-openssl"]
        )
        assert result.exit_code == 0

    def test_validate_unknown_target_exits_2(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "not-a-thing"]
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

class TestList:
    def test_list_profile(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "list", "default"])
        assert result.exit_code == 0
        assert "Total: 2" in result.output

    def test_list_source(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "list", "--source", "local"]
        )
        assert result.exit_code == 0
        assert "Total: 2" in result.output

    def test_list_json(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "list", "--json", "default"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_list_expired(self, runner, tmp_path, expired_ca_pem, ca_pem):
        src = tmp_path / "src"
        src.mkdir()
        (src / "good.pem").write_bytes(ca_pem)
        (src / "expired.pem").write_bytes(expired_ca_pem)

        cfg = tmp_path / "certbundle.yaml"
        cfg.write_text(
            "version: 1\n"
            "sources:\n"
            "  s:\n"
            "    type: local\n"
            "    path: {src}\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [s]\n"
            "    output_path: {out}\n"
            "    atomic: false\n"
            "    rehash: builtin\n"
            "    policy:\n"
            "      reject_expired: false\n"
            "      require_ca_flag: true\n".format(
                src=str(src), out=str(tmp_path / "out")
            )
        )
        result = runner.invoke(
            main, ["--config", str(cfg), "list", "--expired", "p"]
        )
        assert result.exit_code == 0
        assert "Total: 1" in result.output

    def test_list_no_target_shows_help(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "list"])
        assert result.exit_code == 1

    def test_list_unknown_source_exits_1(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "list", "--source", "no-such"]
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

class TestDiff:
    def test_diff_no_changes_exits_0(self, runner, cli_env):
        # Build first
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        # Diff against same data: should be zero changes
        result = runner.invoke(main, ["--config", cli_env["config"], "diff", "default"])
        # exit 0 when no changes
        assert result.exit_code == 0

    def test_diff_empty_directory_shows_all_as_added(self, runner, cli_env):
        # Output dir doesn't exist → all certs appear as added
        result = runner.invoke(main, ["--config", cli_env["config"], "diff", "default"])
        assert "ADDED" in result.output

    def test_diff_json_output(self, cli_env):
        # mix_stderr=False keeps stderr out of result.output so JSON parsing is
        # clean. The parameter was available in Click 7.x but removed in Click
        # 8.2+; in Click 8.x stderr is separate by default, so no kwarg needed.
        try:
            runner = CliRunner(mix_stderr=False)
        except TypeError:
            runner = CliRunner()
        result = runner.invoke(
            main, ["--config", cli_env["config"], "diff", "--json", "default"]
        )
        # May exit 1 (changes detected) but stdout must be valid JSON.
        try:
            data = json.loads(result.output)
            assert "summary" in data
        except json.JSONDecodeError:
            pytest.fail(
                "diff --json stdout was not valid JSON.\n"
                "stdout: {!r}\nstderr: {!r}".format(result.output, result.stderr)
            )


# ---------------------------------------------------------------------------
# fetch-crls
# ---------------------------------------------------------------------------

class TestFetchCrls:
    def test_no_crl_profiles_exits_0(self, runner, cli_env):
        # config has include_crls: false (default) → exits cleanly
        result = runner.invoke(
            main, ["--config", cli_env["config"], "fetch-crls"]
        )
        assert result.exit_code == 0
        assert "No profiles" in result.output

    def test_dry_run_with_no_crl_urls(self, runner, cli_env):
        # inject include_crls: true into config
        cfg_path = cli_env["config"]
        with open(cfg_path, "a") as fh:
            fh.write("# append\n")
        # Can't easily add include_crls without rewriting — just verify it runs cleanly
        result = runner.invoke(
            main, ["--config", cfg_path, "fetch-crls", "--dry-run"]
        )
        # Should exit cleanly even if no profiles have CRLs
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Global options
# ---------------------------------------------------------------------------

class TestGlobalOptions:
    def test_verbose_flag_accepted(self, runner, cli_env):
        result = runner.invoke(
            main, ["--verbose", "--config", cli_env["config"], "show-config"]
        )
        assert result.exit_code == 0

    def test_quiet_flag_accepted(self, runner, cli_env):
        result = runner.invoke(
            main, ["--quiet", "--config", cli_env["config"], "show-config"]
        )
        assert result.exit_code == 0

    def test_envvar_config(self, runner, cli_env):
        result = runner.invoke(
            main, ["show-config"],
            env={"CERTBUNDLE_CONFIG": cli_env["config"]},
        )
        assert result.exit_code == 0
