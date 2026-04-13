"""Tests for certbundle.policy — PolicyEngine."""

import pytest

from certbundle.cert import parse_pem_data
from certbundle.policy import PolicyEngine, PolicyDecision


def _get_ca(pem):
    return parse_pem_data(pem)[0]


class TestPolicyEngineDefaults:
    def test_accepts_valid_ca(self, ca_pem):
        engine = PolicyEngine()
        decision = engine.evaluate(_get_ca(ca_pem))
        assert decision.accepted is True

    def test_rejects_expired_by_default(self, expired_ca_pem):
        engine = PolicyEngine()
        decision = engine.evaluate(_get_ca(expired_ca_pem))
        assert decision.accepted is False
        assert "expired" in decision.reason.lower()

    def test_rejects_non_ca_by_default(self, leaf_pem):
        engine = PolicyEngine()
        decision = engine.evaluate(parse_pem_data(leaf_pem)[0])
        assert decision.accepted is False
        assert "not a CA" in decision.reason or "BasicConstraints" in decision.reason

    def test_decision_is_truthy(self, ca_pem):
        engine = PolicyEngine()
        d = engine.evaluate(_get_ca(ca_pem))
        assert bool(d) is True

    def test_decision_repr(self, ca_pem):
        engine = PolicyEngine()
        d = engine.evaluate(_get_ca(ca_pem))
        assert "accepted" in repr(d).lower()


class TestPolicyEngineExpiry:
    def test_allow_expired_when_flag_off(self, expired_ca_pem):
        engine = PolicyEngine({"reject_expired": False})
        decision = engine.evaluate(_get_ca(expired_ca_pem))
        assert decision.accepted is True


class TestPolicyEngineCAFlag:
    def test_allow_non_ca_when_flag_off(self, leaf_pem):
        engine = PolicyEngine({"require_ca_flag": False})
        decision = engine.evaluate(parse_pem_data(leaf_pem)[0])
        assert decision.accepted is True


class TestPolicyEngineInclude:
    def test_include_by_subject_regex(self, ca_pem):
        engine = PolicyEngine({"include": [{"subject_regex": "Test CA"}]})
        assert engine.evaluate(_get_ca(ca_pem)).accepted is True

    def test_include_regex_rejects_non_match(self, ca_pem):
        engine = PolicyEngine({"include": [{"subject_regex": "DoesNotExist"}]})
        assert engine.evaluate(_get_ca(ca_pem)).accepted is False

    def test_include_by_fingerprint_sha256(self, ca_pem):
        ci = _get_ca(ca_pem)
        engine = PolicyEngine({"include": [{"fingerprint_sha256": ci.fingerprint_sha256}]})
        assert engine.evaluate(ci).accepted is True

    def test_include_wrong_fingerprint(self, ca_pem):
        engine = PolicyEngine({"include": [{"fingerprint_sha256": "AA:BB:CC"}]})
        assert engine.evaluate(_get_ca(ca_pem)).accepted is False


class TestPolicyEngineExclude:
    def test_exclude_by_subject_regex(self, ca_pem):
        engine = PolicyEngine({"exclude": [{"subject_regex": "Test CA"}]})
        assert engine.evaluate(_get_ca(ca_pem)).accepted is False

    def test_exclude_by_fingerprint(self, ca_pem):
        ci = _get_ca(ca_pem)
        engine = PolicyEngine({"exclude": [{"fingerprint_sha256": ci.fingerprint_sha256}]})
        assert engine.evaluate(ci).accepted is False

    def test_exclude_non_matching_source(self, ca_pem):
        ci = _get_ca(ca_pem)
        ci.source_name = "igtf"
        engine = PolicyEngine({"exclude": [{"source": "other-source"}]})
        assert engine.evaluate(ci).accepted is True

    def test_exclude_matching_source(self, ca_pem):
        ci = _get_ca(ca_pem)
        ci.source_name = "bad-source"
        engine = PolicyEngine({"exclude": [{"source": "bad-source"}]})
        assert engine.evaluate(ci).accepted is False


class TestPolicyEngineFilter:
    def test_filter_list(self, ca_pem, expired_ca_pem, leaf_pem):
        certs = (
            parse_pem_data(ca_pem)
            + parse_pem_data(expired_ca_pem)
            + parse_pem_data(leaf_pem)
        )
        engine = PolicyEngine()
        accepted = engine.filter(certs)
        assert len(accepted) == 1
        assert accepted[0].subject == parse_pem_data(ca_pem)[0].subject

    def test_filter_empty_list(self):
        engine = PolicyEngine()
        assert engine.filter([]) == []


class TestPolicyEngineIgtfPolicy:
    def test_igtf_policy_include(self, ca_pem):
        ci = _get_ca(ca_pem)
        ci.igtf_info = {"policy": "classic"}
        engine = PolicyEngine({"include": [{"igtf_policy": "classic"}]})
        assert engine.evaluate(ci).accepted is True

    def test_igtf_policy_exclude(self, ca_pem):
        ci = _get_ca(ca_pem)
        ci.igtf_info = {"policy": "slcs"}
        engine = PolicyEngine({"exclude": [{"igtf_policy": "slcs"}]})
        assert engine.evaluate(ci).accepted is False
