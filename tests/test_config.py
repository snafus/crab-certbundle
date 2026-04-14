"""Tests for crab.config — YAML loading and validation."""

import os
import unittest.mock as mock
import pytest

from crab.config import load_config, Config, ConfigError, _nearest_existing_dir


class TestLoadConfig:
    def test_loads_minimal_config(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        assert isinstance(cfg, Config)

    def test_raises_on_missing_file(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_raises_on_empty_file(self, tmp_path):
        path = str(tmp_path / "empty.yaml")
        with open(path, "w") as fh:
            fh.write("")
        with pytest.raises(ConfigError):
            load_config(path)

    def test_raises_on_unsupported_version(self, tmp_path):
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write("version: 99\nsources: {}\nprofiles: {}\n")
        with pytest.raises(ConfigError, match="version"):
            load_config(path)

    def test_raises_on_unknown_source_type(self, tmp_path):
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: unknown\n"
                "    path: /tmp\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [s]\n"
                "    output_path: /tmp/out\n"
            )
        with pytest.raises(ConfigError, match="unsupported type"):
            load_config(path)

    def test_raises_on_profile_missing_output_path(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: local\n"
                "    path: {}\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [s]\n".format(pem_dir)
            )
        with pytest.raises(ConfigError, match="output_path"):
            load_config(path)

    def test_raises_on_unknown_source_in_profile(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: local\n"
                "    path: {}\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [does-not-exist]\n"
                "    output_path: /tmp/out\n".format(pem_dir)
            )
        with pytest.raises(ConfigError, match="unknown source"):
            load_config(path)


class TestConfig:
    def test_source_names(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        assert "local-test" in cfg.sources

    def test_profile_names(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        assert "default" in cfg.profiles

    def test_get_source(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        src = cfg.get_source("local-test")
        assert src.type == "local"

    def test_get_profile(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        prof = cfg.get_profile("default")
        assert "local-test" in prof.sources

    def test_get_unknown_source_raises(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        with pytest.raises(KeyError):
            cfg.get_source("no-such-source")

    def test_profile_output_path(self, minimal_config_file):
        cfg = load_config(minimal_config_file)
        prof = cfg.get_profile("default")
        assert prof.output_path


class TestProfileDefaults:
    def test_atomic_default_true(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: local\n"
                "    path: {pem_dir}\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [s]\n"
                "    output_path: /tmp/out\n".format(pem_dir=pem_dir)
            )
        cfg = load_config(path)
        assert cfg.profiles["p"].atomic is True

    def test_rehash_default_auto(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: local\n"
                "    path: {pem_dir}\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [s]\n"
                "    output_path: /tmp/out\n".format(pem_dir=pem_dir)
            )
        cfg = load_config(path)
        assert cfg.profiles["p"].rehash == "auto"


class TestStagingDeviceCheck:
    def _write_cfg(self, tmp_path, pem_dir, output_path, staging_path=None):
        staging_line = (
            "    staging_path: {}\n".format(staging_path) if staging_path else ""
        )
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: local\n"
                "    path: {pem_dir}\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [s]\n"
                "    output_path: {out}\n"
                "{staging}"
                "    atomic: true\n".format(
                    pem_dir=pem_dir, out=output_path, staging=staging_line
                )
            )
        return path

    def test_same_device_no_warning(self, tmp_path, pem_dir, caplog):
        """output and staging on the same filesystem → no warning."""
        import logging
        out = str(tmp_path / "out")
        stg = str(tmp_path / "out.staging")
        path = self._write_cfg(tmp_path, pem_dir, out, stg)
        with caplog.at_level(logging.WARNING, logger="crab.config"):
            load_config(path)
        assert "different filesystem" not in caplog.text

    def test_cross_device_emits_warning(self, caplog):
        """output and staging resolving to different st_dev → warning logged."""
        import logging
        from crab.config import _check_staging_device

        # Patch _nearest_existing_dir so os.stat is only called with known paths,
        # then return different st_dev values to simulate a cross-device config.
        fake_out_dir = "/fake/out_anchor"
        fake_stg_dir = "/fake/stg_anchor"
        stat_map = {
            fake_out_dir: mock.Mock(st_dev=100),
            fake_stg_dir: mock.Mock(st_dev=200),
        }

        with mock.patch(
            "crab.config._nearest_existing_dir",
            side_effect=[fake_out_dir, fake_stg_dir],
        ):
            with mock.patch(
                "crab.config.os.stat",
                side_effect=lambda p: stat_map[p],
            ):
                with caplog.at_level(logging.WARNING, logger="crab.config"):
                    _check_staging_device("/fake/out", "/fake/staging", "myprofile")

        assert "different filesystem" in caplog.text

    def test_nearest_existing_dir_finds_root(self, tmp_path):
        deep = str(tmp_path / "a" / "b" / "c" / "d")
        result = _nearest_existing_dir(deep)
        assert os.path.isdir(result)
        assert str(tmp_path) in result

    def test_atomic_false_skips_check(self, tmp_path, pem_dir):
        """When atomic: false, _check_staging_device must never be called."""
        path = str(tmp_path / "config.yaml")
        with open(path, "w") as fh:
            fh.write(
                "version: 1\n"
                "sources:\n"
                "  s:\n"
                "    type: local\n"
                "    path: {pem_dir}\n"
                "profiles:\n"
                "  p:\n"
                "    sources: [s]\n"
                "    output_path: {out}\n"
                "    atomic: false\n".format(
                    pem_dir=pem_dir, out=str(tmp_path / "out")
                )
            )
        with mock.patch("crab.config._check_staging_device") as mock_check:
            load_config(path)
        mock_check.assert_not_called()


# ---------------------------------------------------------------------------
# logging: section validation
# ---------------------------------------------------------------------------

def _write_config(path, pem_dir, out_dir, extra=""):
    """Write a minimal valid config with optional extra top-level YAML."""
    with open(path, "w") as fh:
        fh.write(
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
            "{extra}".format(src=pem_dir, out=out_dir, extra=extra)
        )


class TestLoggingConfig:
    def test_no_logging_section_accepted(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"))
        cfg = load_config(path)
        assert cfg.logging_config == {}

    def test_valid_level_accepted(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"),
                      extra="logging:\n  level: DEBUG\n")
        cfg = load_config(path)
        assert cfg.logging_config["level"] == "DEBUG"

    def test_all_valid_levels_accepted(self, tmp_path, pem_dir):
        for lvl in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            path = str(tmp_path / "config_{}.yaml".format(lvl))
            _write_config(path, pem_dir, str(tmp_path / "out"),
                          extra="logging:\n  level: {}\n".format(lvl))
            cfg = load_config(path)
            assert cfg.logging_config["level"] == lvl

    def test_invalid_level_raises(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"),
                      extra="logging:\n  level: VERBOSE\n")
        with pytest.raises(ConfigError, match="logging.level"):
            load_config(path)

    def test_numeric_level_raises(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"),
                      extra="logging:\n  level: 10\n")
        with pytest.raises(ConfigError, match="logging.level"):
            load_config(path)

    def test_file_key_accepted(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"),
                      extra="logging:\n  file: /var/log/crab.log\n")
        cfg = load_config(path)
        assert cfg.logging_config["file"] == "/var/log/crab.log"

    def test_file_non_string_raises(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"),
                      extra="logging:\n  file: 42\n")
        with pytest.raises(ConfigError, match="logging.file"):
            load_config(path)

    def test_logging_not_a_mapping_raises(self, tmp_path, pem_dir):
        path = str(tmp_path / "config.yaml")
        _write_config(path, pem_dir, str(tmp_path / "out"),
                      extra="logging: INFO\n")
        with pytest.raises(ConfigError, match="logging"):
            load_config(path)


# ---------------------------------------------------------------------------
# Environment variable interpolation
# ---------------------------------------------------------------------------

from crab.config import _expand_env_vars


class TestExpandEnvVars:
    def test_plain_string_unchanged(self):
        assert _expand_env_vars("hello") == "hello"

    def test_non_string_unchanged(self):
        assert _expand_env_vars(42) == 42
        assert _expand_env_vars(True) is True
        assert _expand_env_vars(None) is None

    def test_expands_set_variable(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "/some/path")
        assert _expand_env_vars("${MY_VAR}") == "/some/path"

    def test_expands_variable_mid_string(self, monkeypatch):
        monkeypatch.setenv("PREFIX", "/var/cache")
        result = _expand_env_vars("${PREFIX}/crab")
        assert result == "/var/cache/crab"

    def test_expands_multiple_vars(self, monkeypatch):
        monkeypatch.setenv("A", "foo")
        monkeypatch.setenv("B", "bar")
        assert _expand_env_vars("${A}-${B}") == "foo-bar"

    def test_default_used_when_var_unset(self, monkeypatch):
        monkeypatch.delenv("CERTBUNDLE_CACHE_DIR", raising=False)
        result = _expand_env_vars("${CERTBUNDLE_CACHE_DIR:-/var/cache/crab}")
        assert result == "/var/cache/crab"

    def test_default_not_used_when_var_set(self, monkeypatch):
        monkeypatch.setenv("CERTBUNDLE_CACHE_DIR", "/custom/path")
        result = _expand_env_vars("${CERTBUNDLE_CACHE_DIR:-/var/cache/crab}")
        assert result == "/custom/path"

    def test_empty_default_is_valid(self, monkeypatch):
        monkeypatch.delenv("OPTIONAL_VAR", raising=False)
        assert _expand_env_vars("${OPTIONAL_VAR:-}") == ""

    def test_raises_config_error_for_unset_required_var(self, monkeypatch):
        monkeypatch.delenv("REQUIRED_VAR", raising=False)
        from crab.config import ConfigError
        with pytest.raises(ConfigError, match="REQUIRED_VAR"):
            _expand_env_vars("${REQUIRED_VAR}")

    def test_double_dollar_escapes_literal(self, monkeypatch):
        monkeypatch.delenv("VAR", raising=False)
        assert _expand_env_vars("$$") == "$"
        assert _expand_env_vars("$${VAR}") == "${VAR}"

    def test_recurses_into_dict(self, monkeypatch):
        monkeypatch.setenv("MY_PATH", "/tmp/certs")
        result = _expand_env_vars({"path": "${MY_PATH}", "count": 5})
        assert result == {"path": "/tmp/certs", "count": 5}

    def test_recurses_into_list(self, monkeypatch):
        monkeypatch.setenv("HOST", "example.com")
        result = _expand_env_vars(["${HOST}", 42, None])
        assert result == ["example.com", 42, None]

    def test_dict_keys_not_expanded(self, monkeypatch):
        monkeypatch.setenv("KEY", "expanded")
        result = _expand_env_vars({"${KEY}": "value"})
        # Keys are never expanded — only values
        assert "${KEY}" in result

    def test_nested_dict_list_expansion(self, monkeypatch):
        monkeypatch.setenv("OUT", "/output")
        raw = {"profiles": {"grid": {"output_path": "${OUT}/grid"}}}
        result = _expand_env_vars(raw)
        assert result["profiles"]["grid"]["output_path"] == "/output/grid"

    def test_multiple_missing_vars_all_named(self, monkeypatch):
        monkeypatch.delenv("MISSING_A", raising=False)
        monkeypatch.delenv("MISSING_B", raising=False)
        from crab.config import ConfigError
        with pytest.raises(ConfigError) as exc_info:
            _expand_env_vars("${MISSING_A} and ${MISSING_B}")
        msg = str(exc_info.value)
        assert "MISSING_A" in msg
        assert "MISSING_B" in msg


class TestLoadConfigEnvVars:
    """Integration: load_config() expands env vars before validation."""

    def _write(self, path, content):
        with open(path, "w") as fh:
            fh.write(content)

    def test_env_var_in_path_expanded(self, tmp_path, pem_dir, monkeypatch):
        monkeypatch.setenv("MY_SRC", pem_dir)
        monkeypatch.setenv("MY_OUT", str(tmp_path / "out"))
        cfg_path = str(tmp_path / "crab.yaml")
        self._write(cfg_path,
            "version: 1\n"
            "sources:\n"
            "  s:\n"
            "    type: local\n"
            "    path: ${MY_SRC}\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [s]\n"
            "    output_path: ${MY_OUT}\n"
        )
        cfg = load_config(cfg_path)
        assert cfg.sources["s"].raw["path"] == pem_dir
        assert cfg.profiles["p"].output_path == str(tmp_path / "out")

    def test_default_used_in_loaded_config(self, tmp_path, pem_dir, monkeypatch):
        monkeypatch.delenv("CACHE_DIR", raising=False)
        cfg_path = str(tmp_path / "crab.yaml")
        self._write(cfg_path,
            "version: 1\n"
            "sources:\n"
            "  s:\n"
            "    type: local\n"
            "    path: {pem_dir}\n"
            "    cache_dir: ${{CACHE_DIR:-/var/cache/crab}}\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [s]\n"
            "    output_path: {out}\n".format(
                pem_dir=pem_dir, out=str(tmp_path / "out")
            )
        )
        cfg = load_config(cfg_path)
        assert cfg.sources["s"].raw.get("cache_dir") == "/var/cache/crab"

    def test_missing_required_var_raises_config_error(self, tmp_path, pem_dir, monkeypatch):
        monkeypatch.delenv("REQUIRED_OUT", raising=False)
        cfg_path = str(tmp_path / "crab.yaml")
        self._write(cfg_path,
            "version: 1\n"
            "sources:\n"
            "  s:\n"
            "    type: local\n"
            "    path: {pem_dir}\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [s]\n"
            "    output_path: ${{REQUIRED_OUT}}\n".format(pem_dir=pem_dir)
        )
        from crab.config import ConfigError
        with pytest.raises(ConfigError, match="REQUIRED_OUT"):
            load_config(cfg_path)


# ---------------------------------------------------------------------------
# PKCS#12 config support
# ---------------------------------------------------------------------------

class TestPkcs12Config:
    """ProfileConfig correctly parses pkcs12-related fields."""

    def _write(self, path, content):
        with open(path, "w") as f:
            f.write(content)

    def _cfg(self, tmp_path, pem_dir, extra_profile_lines=""):
        cfg_path = str(tmp_path / "crab.yaml")
        self._write(cfg_path,
            "version: 1\n"
            "sources:\n"
            "  s:\n"
            "    type: local\n"
            "    path: {pem_dir}\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [s]\n"
            "    output_format: pkcs12\n"
            "    output_path: {out}\n"
            "{extra}\n".format(
                pem_dir=pem_dir,
                out=str(tmp_path / "bundle.p12"),
                extra=extra_profile_lines,
            )
        )
        return load_config(cfg_path)

    def test_pkcs12_format_accepted(self, tmp_path, pem_dir):
        cfg = self._cfg(tmp_path, pem_dir)
        assert cfg.profiles["p"].output_format == "pkcs12"

    def test_default_password_is_empty_string(self, tmp_path, pem_dir):
        cfg = self._cfg(tmp_path, pem_dir)
        assert cfg.profiles["p"].pkcs12_password == ""

    def test_password_stored(self, tmp_path, pem_dir):
        cfg = self._cfg(tmp_path, pem_dir, "    pkcs12_password: 'mySecret'\n")
        assert cfg.profiles["p"].pkcs12_password == "mySecret"

    def test_non_string_password_raises(self, tmp_path, pem_dir):
        # YAML integer value for pkcs12_password
        cfg_path = str(tmp_path / "crab.yaml")
        self._write(cfg_path,
            "version: 1\n"
            "sources:\n"
            "  s:\n"
            "    type: local\n"
            "    path: {pem_dir}\n"
            "profiles:\n"
            "  p:\n"
            "    sources: [s]\n"
            "    output_format: pkcs12\n"
            "    output_path: {out}\n"
            "    pkcs12_password: 12345\n".format(
                pem_dir=pem_dir,
                out=str(tmp_path / "bundle.p12"),
            )
        )
        with pytest.raises(ConfigError, match="pkcs12_password.*string"):
            load_config(cfg_path)

    def test_as_output_profile_dict_includes_password(self, tmp_path, pem_dir):
        cfg = self._cfg(tmp_path, pem_dir, "    pkcs12_password: 's3cr3t'\n")
        d = cfg.profiles["p"].as_output_profile_dict()
        assert d["output_format"] == "pkcs12"
        assert d["pkcs12_password"] == "s3cr3t"
