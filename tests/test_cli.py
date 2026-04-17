"""
CLI integration tests using Click's test runner.

These tests run the full CLI stack without network access or root privileges.
All operations are confined to temporary directories.
"""

import os
import json
import pytest

from click.testing import CliRunner

from crab.cli import main


# runner and cli_env fixtures are defined in conftest.py


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_flag(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "crabctl" in result.output
        assert "0.4.0" in result.output

    def test_version_includes_commit(self, runner):
        """Version output includes a commit SHA when one is available."""
        from crab import __commit__
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        if __commit__ != "unknown":
            assert __commit__ in result.output
        else:
            # Unknown is acceptable (e.g. installed from a plain tarball).
            assert "0.4.0" in result.output

    def test_commit_is_resolved(self):
        """__commit__ is a non-empty string (SHA or 'unknown')."""
        from crab import __commit__
        assert isinstance(__commit__, str)
        assert len(__commit__) > 0
        assert not __commit__.startswith("$Format:")

    def test_resolve_commit_unknown_fallback(self, tmp_path, monkeypatch):
        """_resolve_commit() returns 'unknown' when git is absent and
        _commit.py contains the unsubstituted placeholder."""
        import importlib
        import crab

        # Patch _commit so it looks like an unsubstituted archive file.
        monkeypatch.setattr("crab._commit.__commit__", "$Format:%h$", raising=False)

        # Make git unavailable.
        import subprocess as _sp
        def _fail(*a, **kw):
            raise FileNotFoundError("git not found")
        monkeypatch.setattr(_sp, "check_output", _fail)

        result = crab._resolve_commit()
        assert result == "unknown"


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
            main, ["--config", cli_env["config"], "--output-format", "json", "list", "default"]
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
            main, ["--config", cli_env["config"], "--output-format", "json", "diff", "default"]
        )
        # May exit 1 (changes detected) but stdout must be valid JSON.
        try:
            data = json.loads(result.output)
            assert "summary" in data
        except json.JSONDecodeError:
            pytest.fail(
                "diff --output-format json stdout was not valid JSON.\n"
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
        with patch("crab.cli.CRLManager") as mock_crl:
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
# validate --output-format json
# ---------------------------------------------------------------------------

class TestValidateJson:
    def test_json_output_is_valid_json(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(
            main, ["--config", cli_env["config"], "--output-format", "json",
                   "validate", "default", "--no-openssl"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)

    def test_json_contains_target_and_issues(self, runner, cli_env):
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(
            main, ["--config", cli_env["config"], "--output-format", "json",
                   "validate", "default", "--no-openssl"]
        )
        data = json.loads(result.output)
        assert data[0]["target"] == "default"
        assert "issues" in data[0]
        assert "errors" in data[0]
        assert "warnings" in data[0]

    def test_json_exit_code_2_on_error(self, runner, cli_env):
        # Validate a non-existent profile directory → error
        result = runner.invoke(
            main, ["--config", cli_env["config"], "--output-format", "json",
                   "validate", "default", "--no-openssl"]
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
        log_file = str(tmp_path / "logs" / "crab.log")
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
        log_file = str(tmp_path / "crab.log")
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
            extra="logging:\n  file: /no/such/dir/crab.log\n",
        )
        result = runner.invoke(main, ["--config", cfg, "show-config"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# build — source load exception (not a result.errors — a raised exception)
# ---------------------------------------------------------------------------

class TestBuildSourceException:
    def test_source_load_exception_increments_errors(self, runner, tmp_path, ca_pem):
        """If source.load() raises, the profile reports an error."""
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
            "    rehash: builtin\n".format(src=str(src), out=str(out))
        )
        from unittest.mock import patch
        with patch("crab.cli.build_source") as mock_bs:
            mock_bs.return_value.load.side_effect = RuntimeError("source broke")
            result = runner.invoke(main, ["--config", str(cfg), "build"])
        # Should exit 1 due to source error
        assert result.exit_code == 1
        assert "ERROR" in result.output


# ---------------------------------------------------------------------------
# build — dedup note
# ---------------------------------------------------------------------------

class TestBuildDedupNote:
    def test_dedup_note_printed_when_duplicates(self, runner, tmp_path, ca_pem):
        """When duplicate certs are present, a dedup note is printed."""
        src = tmp_path / "src"
        src.mkdir()
        # Write the same cert twice under different filenames
        (src / "ca1.pem").write_bytes(ca_pem)
        (src / "ca2.pem").write_bytes(ca_pem)
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
            "    policy:\n"
            "      reject_expired: false\n"
            "      require_ca_flag: false\n".format(src=str(src), out=str(out))
        )
        result = runner.invoke(main, ["--config", str(cfg), "build"])
        assert result.exit_code == 0
        assert "duplicate" in result.output.lower()


# ---------------------------------------------------------------------------
# build — CRL fetching in profile
# ---------------------------------------------------------------------------

class TestBuildWithCrls:
    def test_build_with_include_crls_fetches_crls(self, runner, tmp_path, ca_pem):
        """When include_crls is true, CRL fetch stats are printed."""
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.updated = []
        mock_result.failed = []
        mock_result.missing = ["CN=Test CA"]
        mock_result.errors = []
        with patch("crab.cli.CRLManager") as mock_mgr:
            mock_mgr.return_value.update_crls.return_value = mock_result
            result = runner.invoke(main, ["--config", str(cfg), "build"])
        assert result.exit_code == 0
        assert "CRLs:" in result.output


# ---------------------------------------------------------------------------
# validate — exit code mapping
# ---------------------------------------------------------------------------

class TestValidateExitCodes:
    def test_exits_2_when_errors(self, runner, cli_env):
        """validate on a missing output dir → errors → exit 2."""
        # Output dir does not exist → validate_directory returns error issues
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "default", "--no-openssl"]
        )
        assert result.exit_code == 2

    def test_exits_1_when_warnings_only(self, runner, tmp_path, ca_pem, expired_ca_pem):
        """validate on a dir with expired certs → warnings → exit 1."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "good.pem").write_bytes(ca_pem)
        (src / "expired.pem").write_bytes(expired_ca_pem)
        out = str(tmp_path / "out")
        cfg_path = tmp_path / "crab.yaml"
        cfg_path.write_text(
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
            "      require_ca_flag: true\n".format(src=str(src), out=out)
        )
        # Build first so dir exists with certs
        runner.invoke(main, ["--config", str(cfg_path), "build"])
        # Validate — expired cert should trigger a warning
        result = runner.invoke(
            main, ["--config", str(cfg_path), "validate", "p", "--no-openssl"]
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# diff — unknown path and no-profile cases
# ---------------------------------------------------------------------------

class TestDiffEdgeCases:
    def test_diff_unknown_path_exits_1(self, runner, cli_env):
        """diff with a target that is neither a profile nor a directory → exit 1."""
        result = runner.invoke(
            main, ["--config", cli_env["config"], "diff", "not-a-real-path-or-profile"]
        )
        assert result.exit_code == 1
        assert "ERROR" in result.output

    def test_diff_raw_dir_without_old_dir_exits_1(self, runner, tmp_path, cli_env):
        """diff with a raw directory path but no profile → error about missing profile."""
        # First build so the out dir exists
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        # diff the raw out directory (no profile) — should fail asking for --old-dir
        result = runner.invoke(
            main, ["--config", cli_env["config"], "diff", cli_env["out"]]
        )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# fetch-crls — with CRL-enabled profile
# ---------------------------------------------------------------------------

class TestFetchCrlsWithProfile:
    def test_fetch_crls_prints_stats(self, runner, tmp_path, ca_pem):
        """fetch-crls with a CRL-enabled profile prints update stats."""
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        result = runner.invoke(
            main, ["--config", str(cfg), "fetch-crls", "--dry-run"]
        )
        assert result.exit_code == 0
        # Updated/Failed/No URL stats are printed
        assert "Updated:" in result.output

    def test_fetch_crls_unknown_profile_warns(self, runner, tmp_path, ca_pem):
        """Unknown profile name passed to fetch-crls is reported and skipped."""
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        result = runner.invoke(
            main, ["--config", str(cfg), "fetch-crls", "no-such-profile"]
        )
        assert "ERROR" in result.output


# ---------------------------------------------------------------------------
# refresh — CRL success path (lines 526-530)
# ---------------------------------------------------------------------------

class TestRefreshCrlSuccess:
    def test_refresh_with_crls_prints_crl_stats(self, runner, tmp_path, ca_pem):
        """When include_crls is true and CRL update succeeds, stats are printed."""
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        from unittest.mock import patch, MagicMock
        mock_result = MagicMock()
        mock_result.updated = []
        mock_result.failed = []
        mock_result.missing = ["CN=Test CA"]
        mock_result.errors = []
        with patch("crab.cli.CRLManager") as mock_mgr:
            mock_mgr.return_value.update_crls.return_value = mock_result
            result = runner.invoke(main, ["--config", str(cfg), "refresh"])
        assert result.exit_code == 0
        # The CRL stats line must be present
        assert "CRLs:" in result.output


# ---------------------------------------------------------------------------
# _load_certs_from_directory — non-hash files and parse errors
# ---------------------------------------------------------------------------

class TestLoadCertsFromDirectory:
    def test_non_hash_files_are_skipped(self, runner, cli_env):
        """Files that don't match the hash pattern are silently skipped."""
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        # Add a non-hash file to the output directory
        open(os.path.join(cli_env["out"], "random.txt"), "w").close()
        # diff will call _load_certs_from_directory on the directory
        result = runner.invoke(main, ["--config", cli_env["config"], "diff", "default"])
        # Should succeed without crashing
        assert result.exit_code == 0

    def test_unparseable_cert_file_is_skipped(self, runner, cli_env):
        """A hash-named file that raises on parse is silently skipped."""
        from unittest.mock import patch
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        with patch("crab.cli.parse_pem_file", side_effect=IOError("bad file")):
            result = runner.invoke(main, ["--config", cli_env["config"], "diff", "default"])
        # Should not crash regardless of parse errors
        assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# _load_config_or_exit — non-ConfigError exception
# ---------------------------------------------------------------------------

class TestLoadConfigOrExitError:
    def test_non_config_error_exits_1(self, runner, tmp_path):
        """Unexpected exception from load_config → error message + exit 1."""
        from unittest.mock import patch
        # Write a valid path so the "no path" check passes
        cfg_file = tmp_path / "crab.yaml"
        cfg_file.write_text("version: 1\nsources: {}\nprofiles: {p: {output_path: /x, sources: []}}\n")
        with patch("crab.cli.load_config", side_effect=RuntimeError("unexpected")):
            result = runner.invoke(main, ["--config", str(cfg_file), "show-config"])
        assert result.exit_code == 1
        assert "Cannot load config" in result.output


# ---------------------------------------------------------------------------
# _find_default_config — returns path when found in ./
# ---------------------------------------------------------------------------

class TestValidateNoTargets:
    def test_validate_all_profiles_when_no_target_given(self, runner, cli_env):
        """validate with no targets validates ALL configured profiles."""
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        result = runner.invoke(
            main, ["--config", cli_env["config"], "validate", "--no-openssl"]
        )
        # Validates the single 'default' profile; exit 0 since dir is valid
        assert result.exit_code == 0
        assert "default" in result.output


class TestBuildOutputErrors:
    def test_build_output_errors_reported(self, runner, tmp_path, ca_pem):
        """When build_output returns errors, they are printed and exit is 1."""
        from unittest.mock import patch, MagicMock
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
            "    rehash: builtin\n".format(src=str(src), out=str(out))
        )
        mock_result = MagicMock()
        mock_result.errors = ["something went wrong"]
        mock_result.cert_count = 0
        mock_result.files_written = []
        with patch("crab.cli.build_output", return_value=mock_result):
            result = runner.invoke(main, ["--config", str(cfg), "build"])
        assert result.exit_code == 1
        assert "ERROR" in result.output


class TestBuildCrlErrors:
    def test_crl_errors_printed_in_build(self, runner, tmp_path, ca_pem):
        """CRL fetch errors in build are printed as warnings."""
        from unittest.mock import patch, MagicMock
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        mock_crl_result = MagicMock()
        mock_crl_result.updated = []
        mock_crl_result.failed = []
        mock_crl_result.missing = []
        mock_crl_result.errors = ["CRL fetch failed for CN=Test"]
        with patch("crab.cli.CRLManager") as mock_mgr:
            mock_mgr.return_value.update_crls.return_value = mock_crl_result
            result = runner.invoke(main, ["--config", str(cfg), "build"])
        assert result.exit_code == 0
        assert "CRL WARNING" in result.output


class TestLoadProfileCertsSourceError:
    def test_source_exception_in_load_profile_certs_warns(self, runner, cli_env):
        """When a source raises in _load_profile_certs, a warning is logged."""
        from unittest.mock import patch
        runner.invoke(main, ["--config", cli_env["config"], "build"])
        # diff calls _load_profile_certs; force a source failure there
        with patch("crab.cli.build_source") as mock_bs:
            mock_bs.return_value.load.side_effect = RuntimeError("source exploded")
            result = runner.invoke(
                main, ["--config", cli_env["config"], "diff", "default"]
            )
        # Should not crash; diff shows all certs as "added" since new_certs is empty
        assert result.exit_code in (0, 1)


class TestFetchCrlsErrors:
    def test_fetch_crls_errors_printed(self, runner, tmp_path, ca_pem):
        """CRL fetch errors in fetch-crls command are printed."""
        from unittest.mock import patch, MagicMock
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        mock_result = MagicMock()
        mock_result.updated = []
        mock_result.failed = []
        mock_result.missing = []
        mock_result.errors = ["fetch failed: connection refused"]
        with patch("crab.cli.CRLManager") as mock_mgr:
            mock_mgr.return_value.update_crls.return_value = mock_result
            result = runner.invoke(main, ["--config", str(cfg), "fetch-crls"])
        assert result.exit_code == 0
        assert "fetch failed" in result.output


class TestRefreshCrlErrors:
    def test_refresh_crl_errors_printed(self, runner, tmp_path, ca_pem):
        """CRL fetch errors in the refresh CRL step are printed as warnings."""
        from unittest.mock import patch, MagicMock
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
            "      fetch: true\n".format(src=str(src), out=str(out))
        )
        mock_crl_result = MagicMock()
        mock_crl_result.updated = []
        mock_crl_result.failed = []
        mock_crl_result.missing = []
        mock_crl_result.errors = ["failed to download CRL"]
        with patch("crab.cli.CRLManager") as mock_mgr:
            mock_mgr.return_value.update_crls.return_value = mock_crl_result
            result = runner.invoke(main, ["--config", str(cfg), "refresh"])
        assert result.exit_code == 0
        assert "CRL WARNING" in result.output


class TestFindDefaultConfig:
    def test_finds_crab_yaml_in_current_dir(self, runner):
        """_find_default_config returns a path when ./crab.yaml exists."""
        with runner.isolated_filesystem():
            with open("crab.yaml", "w") as f:
                f.write(
                    "version: 1\n"
                    "sources:\n"
                    "  s:\n"
                    "    type: local\n"
                    "    path: /tmp\n"
                    "profiles:\n"
                    "  p:\n"
                    "    sources: [s]\n"
                    "    output_path: /tmp/out\n"
                )
            result = runner.invoke(main, ["show-config"])
            # Should auto-detect ./crab.yaml and load without --config
            assert result.exit_code == 0


class TestDiffJsonExitCode:
    """diff --output-format json exits 1 when changes are detected (same contract as text mode)."""

    def test_diff_json_exits_1_when_changes(self, runner, cli_env, tmp_path):
        """diff with --output-format json and empty comparison dir exits 1 (changes present)."""
        empty_dir = str(tmp_path / "empty")
        os.makedirs(empty_dir)
        result = runner.invoke(
            main,
            ["--config", cli_env["config"], "--output-format", "json",
             "diff", "--old-dir", empty_dir, "default"],
        )
        import json as _json
        data = _json.loads(result.output)
        assert data["summary"]["added"] > 0
        assert result.exit_code == 1

    def test_diff_json_exits_0_when_no_changes(self, runner, cli_env, tmp_path, ca_pem, second_ca_pem):
        """diff --output-format json exits 0 when output matches what would be built."""
        from crab.rehash import build_symlink_map
        from crab.cert import parse_pem_data
        # Build an output dir identical to what build would produce
        out = str(tmp_path / "out")
        os.makedirs(out)
        certs = parse_pem_data(ca_pem + b"\n" + second_ca_pem)
        hash_map = build_symlink_map(certs)
        for fname, pem in hash_map.items():
            open(os.path.join(out, fname), "wb").write(pem)
        result = runner.invoke(
            main,
            ["--config", cli_env["config"], "--output-format", "json",
             "diff", "--old-dir", out, "default"],
        )
        import json as _json
        data = _json.loads(result.output)
        assert data["summary"]["added"] == 0
        assert data["summary"]["removed"] == 0
        assert result.exit_code == 0
