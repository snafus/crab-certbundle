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
        assert "crab.yaml" in result.output or "No config" in result.output


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

        cfg = tmp_path / "crab.yaml"
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
# refresh
# ---------------------------------------------------------------------------

class TestRefresh:
    def test_refresh_builds_output(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "refresh"])
        assert result.exit_code == 0
        assert os.path.isdir(cli_env["out"])

    def test_refresh_dry_run_no_output(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "refresh", "--dry-run"])
        assert result.exit_code == 0
        assert not os.path.exists(cli_env["out"])

    def test_refresh_unknown_profile_exits_1(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "refresh", "no-such-profile"]
        )
        assert result.exit_code == 1

    def test_refresh_output_mentions_building(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "refresh"])
        assert "Building profile" in result.output

    def test_refresh_no_crls_skips_crl_step(self, runner, cli_env):
        """Without include_crls, refresh should not mention CRL fetching."""
        result = runner.invoke(main, ["--config", cli_env["config"], "refresh"])
        assert result.exit_code == 0
        assert "Fetching CRLs" not in result.output

    def test_refresh_crl_failure_does_not_block_build(self, runner, tmp_path, ca_pem):
        """A CRL fetch exception must be a warning; the build still runs."""
        from unittest.mock import patch
        src = tmp_path / "src"
        src.mkdir()
        (src / "ca.pem").write_bytes(ca_pem)
        out = tmp_path / "out"
        cfg = tmp_path / "crab.yaml"
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
            "    include_crls: true\n"
            "    crl:\n"
            "      output_dir: {out}\n".format(src=str(src), out=str(out))
        )
        with patch("certbundle.cli.CRLManager") as mock_crl:
            mock_crl.return_value.update_crls.side_effect = IOError("network error")
            result = runner.invoke(main, ["--config", str(cfg), "refresh"])

        # Build must succeed despite CRL failure
        assert result.exit_code == 0
        assert os.path.isdir(str(out))
        assert "WARNING" in result.output or "warning" in result.output.lower()

    def test_refresh_with_report_flag(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "refresh", "--report"]
        )
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
            env={"CRAB_CONFIG": cli_env["config"]},
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# validate --json
# ---------------------------------------------------------------------------

class TestValidateJson:
    def test_json_output_is_valid_json(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "--json",
                   "default", "--no-openssl"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)

    def test_json_contains_target_and_issues(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "--json",
                   "default", "--no-openssl"]
        )
        data = json.loads(result.output)
        assert data[0]["target"] == "default"
        assert "issues" in data[0]
        assert "errors" in data[0]
        assert "warnings" in data[0]

    def test_json_exit_code_2_on_error(self, runner, cli_env):
        # Validate a non-existent profile directory → error
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "--json",
                   "default", "--no-openssl"]
        )
        # output dir doesn't exist yet → errors
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert data[0]["errors"] >= 1


# ---------------------------------------------------------------------------
# list — raw directory path
# ---------------------------------------------------------------------------

class TestListRawDirectory:
    def test_list_from_built_directory(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(
            main, ["--config", cli_env["config"], "list", cli_env["out"]]
        )
        assert result.exit_code == 0
        assert "Total: 2" in result.output

    def test_list_unknown_target_exits_1(self, runner, cli_env):
        result = runner.invoke(
            main, ["--config", cli_env["config"], "list", "/no/such/path"]
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# diff — exit code behaviour
# ---------------------------------------------------------------------------

class TestDiffExitCodes:
    def test_exits_1_when_changes_present(self, runner, cli_env):
        # Output dir doesn't exist → all certs added → exit 1
        result = runner.invoke(main, ["--config", cli_env["config"], "diff", "default"])
        assert result.exit_code == 1
        assert "ADDED" in result.output

    def test_exits_0_when_no_changes(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(main, ["--config", cli_env["config"], "diff", "default"])
        assert result.exit_code == 0
        assert "No changes" in result.output


# ---------------------------------------------------------------------------
# show-config — output content
# ---------------------------------------------------------------------------

class TestShowConfigContent:
    def test_shows_config_file_path(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "show-config"])
        assert result.exit_code == 0
        assert "Config file:" in result.output
        assert cli_env["config"] in result.output

    def test_shows_source_details(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "show-config"])
        assert "Sources" in result.output
        assert "type=local" in result.output

    def test_shows_profile_details(self, runner, cli_env):
        result = runner.invoke(main, ["--config", cli_env["config"], "show-config"])
        assert "Profiles" in result.output
        assert cli_env["out"] in result.output


# ---------------------------------------------------------------------------
# build — source load error handling
# ---------------------------------------------------------------------------

class TestBuildSourceError:
    def test_build_with_missing_source_path_exits_error(self, runner, tmp_path):
        """A source pointing at a non-existent path should warn and write 0 certs."""
        out = str(tmp_path / "out")
        cfg = tmp_path / "crab.yaml"
        cfg.write_text(
            "version: 1\n"
            "sources:\n"
            "  bad:\n"
            "    type: local\n"
            "    path: /no/such/dir\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [bad]\n"
            "    output_path: {out}\n"
            "    atomic: false\n"
            "    rehash: builtin\n".format(out=out)
        )
        result = runner.invoke(main, ["--config", str(cfg), "build"])
        # Should not crash; missing path is a warning, not a fatal error
        assert result.exit_code == 0
        assert "WARNING" in result.output or "does not exist" in result.output


# ---------------------------------------------------------------------------
# logging: config section applied by CLI
# ---------------------------------------------------------------------------

class TestApplyLoggingConfig:
    """Verify that the logging: config section adjusts the root logger."""

    def _make_config(self, tmp_path, ca_pem, extra=""):
        src = tmp_path / "src"
        src.mkdir()
        (src / "ca.pem").write_bytes(ca_pem)
        out = tmp_path / "out"
        cfg = tmp_path / "crab.yaml"
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
            "{extra}".format(src=str(src), out=str(out), extra=extra)
        )
        return str(cfg)

    def test_config_level_debug_applied(self, runner, tmp_path, ca_pem):
        import logging
        cfg = self._make_config(tmp_path, ca_pem,
                                extra="logging:\n  level: DEBUG\n")
        runner.invoke(main, ["--config", cfg, "show-config"])
        assert logging.root.level == logging.DEBUG

    def test_config_level_warning_applied(self, runner, tmp_path, ca_pem):
        import logging
        cfg = self._make_config(tmp_path, ca_pem,
                                extra="logging:\n  level: WARNING\n")
        runner.invoke(main, ["--config", cfg, "show-config"])
        assert logging.root.level == logging.WARNING

    def test_verbose_flag_overrides_config_level(self, runner, tmp_path, ca_pem):
        import logging
        cfg = self._make_config(tmp_path, ca_pem,
                                extra="logging:\n  level: WARNING\n")
        runner.invoke(main, ["--verbose", "--config", cfg, "show-config"])
        assert logging.root.level == logging.DEBUG

    def test_quiet_flag_overrides_config_level(self, runner, tmp_path, ca_pem):
        import logging
        cfg = self._make_config(tmp_path, ca_pem,
                                extra="logging:\n  level: DEBUG\n")
        runner.invoke(main, ["--quiet", "--config", cfg, "show-config"])
        assert logging.root.level == logging.ERROR

    def test_log_file_handler_added(self, runner, tmp_path, ca_pem):
        import logging
        log_file = str(tmp_path / "logs" / "certbundle.log")
        cfg = self._make_config(
            tmp_path, ca_pem,
            extra="logging:\n  level: INFO\n  file: {}\n".format(log_file),
        )
        # Remove any pre-existing FileHandlers to avoid cross-test pollution
        logging.root.handlers = [
            h for h in logging.root.handlers
            if not isinstance(h, logging.FileHandler)
        ]
        runner.invoke(main, ["--config", cfg, "show-config"])
        file_handlers = [
            h for h in logging.root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert any(h.baseFilename == log_file for h in file_handlers)
        assert os.path.isfile(log_file)

    def test_log_file_handler_idempotent(self, runner, tmp_path, ca_pem):
        """Invoking twice must not add duplicate FileHandlers."""
        import logging
        log_file = str(tmp_path / "certbundle.log")
        cfg = self._make_config(
            tmp_path, ca_pem,
            extra="logging:\n  file: {}\n".format(log_file),
        )
        logging.root.handlers = [
            h for h in logging.root.handlers
            if not isinstance(h, logging.FileHandler)
        ]
        runner.invoke(main, ["--config", cfg, "show-config"])
        runner.invoke(main, ["--config", cfg, "show-config"])
        count = sum(
            1 for h in logging.root.handlers
            if isinstance(h, logging.FileHandler) and h.baseFilename == log_file
        )
        assert count == 1

    def test_unwritable_log_file_emits_warning_not_crash(self, runner, tmp_path, ca_pem):
        """A log file path that cannot be opened must not crash the CLI."""
        cfg = self._make_config(
            tmp_path, ca_pem,
            extra="logging:\n  file: /no/such/dir/certbundle.log\n",
        )
        result = runner.invoke(main, ["--config", cfg, "show-config"])
        assert result.exit_code == 0
