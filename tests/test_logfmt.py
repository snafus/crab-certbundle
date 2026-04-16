"""
Tests for crab.logfmt — JSON formatter and make_formatter factory.
"""

import json
import logging

import pytest

from crab.logfmt import JsonFormatter, make_formatter, TEXT_FORMAT


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------

class TestJsonFormatter:

    def _make_record(self, msg="hello", level=logging.INFO, name="crab.test",
                     exc_info=None):
        record = logging.LogRecord(
            name=name,
            level=level,
            pathname="",
            lineno=0,
            msg=msg,
            args=(),
            exc_info=exc_info,
        )
        return record

    def test_output_is_valid_json(self):
        fmt = JsonFormatter()
        line = fmt.format(self._make_record())
        obj = json.loads(line)
        assert isinstance(obj, dict)

    def test_required_fields(self):
        fmt = JsonFormatter()
        obj = json.loads(fmt.format(self._make_record("hi", level=logging.WARNING)))
        assert obj["level"] == "WARNING"
        assert obj["logger"] == "crab.test"
        assert obj["message"] == "hi"
        assert "timestamp" in obj

    def test_timestamp_format(self):
        fmt = JsonFormatter()
        obj = json.loads(fmt.format(self._make_record()))
        ts = obj["timestamp"]
        # e.g. "2026-04-16T04:00:01.234Z"
        assert ts.endswith("Z")
        assert "T" in ts
        assert len(ts) == 24  # YYYY-MM-DDTHH:MM:SS.mmmZ

    def test_no_exception_field_by_default(self):
        fmt = JsonFormatter()
        obj = json.loads(fmt.format(self._make_record()))
        assert "exception" not in obj

    def test_exception_field_present_on_exc_info(self):
        fmt = JsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            ei = sys.exc_info()
        record = self._make_record(exc_info=ei)
        obj = json.loads(fmt.format(record))
        assert "exception" in obj
        assert "ValueError" in obj["exception"]
        assert "boom" in obj["exception"]

    def test_message_with_args(self):
        record = logging.LogRecord(
            name="crab", level=logging.INFO, pathname="", lineno=0,
            msg="count=%d", args=(42,), exc_info=None,
        )
        fmt = JsonFormatter()
        obj = json.loads(fmt.format(record))
        assert obj["message"] == "count=42"

    def test_non_ascii_message(self):
        fmt = JsonFormatter()
        record = self._make_record(msg=u"caf\xe9")
        line = fmt.format(record)
        obj = json.loads(line)
        assert obj["message"] == u"caf\xe9"

    def test_single_line_output(self):
        """JSON output must be a single line (no embedded newlines)."""
        fmt = JsonFormatter()
        line = fmt.format(self._make_record("line one\nline two"))
        assert "\n" not in line


# ---------------------------------------------------------------------------
# make_formatter
# ---------------------------------------------------------------------------

class TestMakeFormatter:

    def test_text_returns_standard_formatter(self):
        fmt = make_formatter("text")
        assert isinstance(fmt, logging.Formatter)
        assert not isinstance(fmt, JsonFormatter)

    def test_json_returns_json_formatter(self):
        fmt = make_formatter("json")
        assert isinstance(fmt, JsonFormatter)

    def test_text_with_time(self):
        fmt = make_formatter("text", with_time=True)
        assert isinstance(fmt, logging.Formatter)
        assert "%(asctime)s" in fmt._fmt

    def test_json_with_time_still_json(self):
        """with_time is ignored for JSON (JSON always has a timestamp)."""
        fmt = make_formatter("json", with_time=True)
        assert isinstance(fmt, JsonFormatter)


# ---------------------------------------------------------------------------
# CLI --log-format integration
# ---------------------------------------------------------------------------

class TestCLILogFormat:
    """Verify the --log-format flag is wired up correctly."""

    def test_json_flag_accepted(self, runner, cli_env):
        """``--log-format json`` is accepted and the build exits 0."""
        from crab.cli import main
        result = runner.invoke(
            main, ["--log-format", "json", "--config", cli_env["config"], "build"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    def test_text_flag_accepted(self, runner, cli_env):
        """``--log-format text`` is accepted and the build exits 0."""
        from crab.cli import main
        result = runner.invoke(
            main, ["--log-format", "text", "--config", cli_env["config"], "build"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    def test_invalid_format_rejected(self, runner, cli_env):
        """An unknown format value is rejected by Click before anything runs."""
        from crab.cli import main
        result = runner.invoke(
            main, ["--log-format", "yaml", "--config", cli_env["config"], "build"],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestConfigLoggingFormat:

    def test_valid_format_text(self, tmp_path, pem_dir):
        from crab.config import load_config
        cfg_path = str(tmp_path / "crab.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "version: 1\n"
                "logging:\n"
                "  format: text\n"
                "sources:\n"
                "  local:\n"
                "    type: local\n"
                "    path: {}\n"
                "profiles:\n"
                "  default:\n"
                "    sources: [local]\n"
                "    output_path: /tmp/out\n".format(pem_dir)
            )
        cfg = load_config(cfg_path)
        assert cfg.logging_config.get("format") == "text"

    def test_valid_format_json(self, tmp_path, pem_dir):
        from crab.config import load_config
        cfg_path = str(tmp_path / "crab.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "version: 1\n"
                "logging:\n"
                "  format: json\n"
                "sources:\n"
                "  local:\n"
                "    type: local\n"
                "    path: {}\n"
                "profiles:\n"
                "  default:\n"
                "    sources: [local]\n"
                "    output_path: /tmp/out\n".format(pem_dir)
            )
        cfg = load_config(cfg_path)
        assert cfg.logging_config.get("format") == "json"

    def test_invalid_format_rejected(self, tmp_path, pem_dir):
        from crab.config import load_config, ConfigError
        cfg_path = str(tmp_path / "crab.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "version: 1\n"
                "logging:\n"
                "  format: yaml\n"
                "sources:\n"
                "  local:\n"
                "    type: local\n"
                "    path: {}\n"
                "profiles:\n"
                "  default:\n"
                "    sources: [local]\n"
                "    output_path: /tmp/out\n".format(pem_dir)
            )
        with pytest.raises(ConfigError, match="logging.format"):
            load_config(cfg_path)
