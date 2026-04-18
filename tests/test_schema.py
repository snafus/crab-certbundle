"""
Tests for crab/schema/crab.yaml.json.

Validates that:
  1. The schema file is valid JSON and has the expected top-level structure.
  2. All three example config files validate successfully against the schema.
  3. A selection of known-bad configs are correctly rejected.

jsonschema is only available in the dev extras (pip install crabctl[dev]).
These tests are skipped if it is not installed so the core test suite still
passes in minimal environments.
"""

import json
import os

import pytest
import yaml

SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "crab", "schema", "crab.yaml.json"
)
EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_schema():
    with open(SCHEMA_PATH) as fh:
        return json.load(fh)


def _load_yaml(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


try:
    import jsonschema
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False

requires_jsonschema = pytest.mark.skipif(
    not _JSONSCHEMA_AVAILABLE, reason="jsonschema not installed"
)


# ---------------------------------------------------------------------------
# Schema structure
# ---------------------------------------------------------------------------

def test_schema_is_valid_json():
    schema = _load_schema()
    assert isinstance(schema, dict)
    assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
    assert "properties" in schema
    assert "definitions" in schema


def test_schema_has_required_top_level_properties():
    schema = _load_schema()
    props = schema["properties"]
    for key in ("version", "sources", "profiles", "logging", "refresh"):
        assert key in props, "Top-level property '{}' missing from schema".format(key)


def test_schema_definitions_cover_all_source_types():
    schema = _load_schema()
    defs = schema["definitions"]
    for src_type in ("source_igtf", "source_local", "source_system"):
        assert src_type in defs, "Source definition '{}' missing".format(src_type)


def test_schema_definitions_cover_profile_and_policy():
    schema = _load_schema()
    defs = schema["definitions"]
    for name in ("profile", "policy", "policy_rule", "crl_config"):
        assert name in defs, "Definition '{}' missing".format(name)


# ---------------------------------------------------------------------------
# Example configs validate against the schema
# ---------------------------------------------------------------------------

@requires_jsonschema
@pytest.mark.parametrize("filename", [
    "config-minimal.yaml",
    "config-full.yaml",
    "config-grid.yaml",
])
def test_example_config_validates(filename):
    schema = _load_schema()
    config_path = os.path.join(EXAMPLES_DIR, filename)
    assert os.path.isfile(config_path), "Example config not found: {}".format(config_path)
    instance = _load_yaml(config_path)
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    messages = [
        "{}: {}".format(" > ".join(str(p) for p in e.absolute_path), e.message)
        for e in errors
    ]
    assert not errors, "Schema validation failed for {}:\n{}".format(
        filename, "\n".join(messages)
    )


# ---------------------------------------------------------------------------
# Invalid configs are rejected
# ---------------------------------------------------------------------------

@requires_jsonschema
def test_rejects_missing_sources():
    schema = _load_schema()
    instance = {
        "version": 1,
        "profiles": {
            "grid": {
                "sources": ["igtf"],
                "output_path": "/tmp/out",
            }
        }
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert any("sources" in e.message or "required" in e.message for e in errors), \
        "Expected a 'sources' required error; got: {}".format(errors)


@requires_jsonschema
def test_rejects_missing_profiles():
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {
            "igtf": {"type": "igtf", "path": "/etc/grid-security/certificates"}
        }
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert any("profiles" in e.message or "required" in e.message for e in errors), \
        "Expected a 'profiles' required error; got: {}".format(errors)


@requires_jsonschema
def test_rejects_unknown_source_type():
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {
            "bad": {"type": "nonexistent"}
        },
        "profiles": {
            "grid": {"sources": ["bad"], "output_path": "/tmp/out"}
        }
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert errors, "Expected validation errors for unknown source type"


@requires_jsonschema
def test_rejects_unknown_output_format():
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {
            "igtf": {"type": "igtf", "path": "/etc/grid-security/certificates"}
        },
        "profiles": {
            "grid": {
                "sources": ["igtf"],
                "output_path": "/tmp/out",
                "output_format": "tarball",
            }
        }
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert any("tarball" in e.message or "enum" in e.message or "output_format" in str(e.absolute_path) for e in errors), \
        "Expected an output_format enum error; got: {}".format(errors)


@requires_jsonschema
def test_rejects_bad_log_level():
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {"s": {"type": "system"}},
        "profiles": {"p": {"sources": ["s"], "output_path": "/tmp/out"}},
        "logging": {"level": "VERBOSE"},
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert errors, "Expected validation error for invalid log level"


@requires_jsonschema
def test_rejects_unsupported_version():
    schema = _load_schema()
    instance = {
        "version": 99,
        "sources": {"s": {"type": "system"}},
        "profiles": {"p": {"sources": ["s"], "output_path": "/tmp/out"}},
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert errors, "Expected validation error for version=99"


@requires_jsonschema
def test_rejects_igtf_policy_typo():
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {
            "igtf": {
                "type": "igtf",
                "path": "/etc/grid-security/certificates",
                "policies": ["Classic"],  # wrong case
            }
        },
        "profiles": {"p": {"sources": ["igtf"], "output_path": "/tmp/out"}},
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert errors, "Expected validation error for policy tag 'Classic' (must be lowercase)"


@requires_jsonschema
def test_accepts_string_file_mode():
    """file_mode: '0o644' (string) must be accepted by the schema."""
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {"s": {"type": "system"}},
        "profiles": {
            "p": {
                "sources": ["s"],
                "output_path": "/tmp/out",
                "file_mode": "0o644",
                "dir_mode": "0o755",
            }
        },
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert not errors, "String file_mode should be valid; got: {}".format(errors)


@requires_jsonschema
def test_accepts_integer_file_mode():
    """file_mode: 420 (decimal 0o644) must be accepted by the schema."""
    schema = _load_schema()
    instance = {
        "version": 1,
        "sources": {"s": {"type": "system"}},
        "profiles": {
            "p": {
                "sources": ["s"],
                "output_path": "/tmp/out",
                "file_mode": 420,
                "dir_mode": 493,
            }
        },
    }
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(instance))
    assert not errors, "Integer file_mode should be valid; got: {}".format(errors)
