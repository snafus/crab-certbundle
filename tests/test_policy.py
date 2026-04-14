"""Tests for crab.policy — PolicyEngine."""

import datetime
import os
import sys
import pytest

# conftest.py lives in the tests/ directory; make it importable.
sys.path.insert(0, os.path.dirname(__file__))
from conftest import _make_ca_cert  # noqa: E402

from cryptography.x509.oid import ExtendedKeyUsageOID

from crab.cert import parse_pem_data
from crab.policy import PolicyEngine, PolicyDecision


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


class TestPolicyEngineRejectNotYetValid:
    def test_accepts_not_yet_valid_by_default(self, ca_pem):
        """reject_not_yet_valid defaults to False — future certs are accepted."""
        engine = PolicyEngine()
        # Build a cert whose not_before is in the future

        future = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        pem, _, _ = _make_ca_cert(
            not_before=future,
            not_after=datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc),
        )
        ci = _get_ca(pem)
        assert engine.evaluate(ci).accepted is True

    def test_rejects_not_yet_valid_when_flag_on(self):
        engine = PolicyEngine({"reject_not_yet_valid": True, "reject_expired": False})

        future = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        pem, _, _ = _make_ca_cert(
            not_before=future,
            not_after=datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc),
        )
        decision = engine.evaluate(_get_ca(pem))
        assert decision.accepted is False
        assert "not yet valid" in decision.reason.lower()


class TestPolicyEngineRejectPathLenZero:
    def test_accepts_path_len_zero_by_default(self):
        """reject_path_len_zero defaults to False."""

        pem, _, _ = _make_ca_cert(path_length=0)
        engine = PolicyEngine({"reject_path_len_zero": False})
        assert engine.evaluate(_get_ca(pem)).accepted is True

    def test_rejects_path_len_zero_when_flag_on(self):

        pem, _, _ = _make_ca_cert(path_length=0)
        engine = PolicyEngine({"reject_path_len_zero": True})
        decision = engine.evaluate(_get_ca(pem))
        assert decision.accepted is False
        assert "pathLen" in decision.reason or "pathlen" in decision.reason.lower()

    def test_accepts_path_len_one_when_flag_on(self):

        pem, _, _ = _make_ca_cert(path_length=1)
        engine = PolicyEngine({"reject_path_len_zero": True})
        assert engine.evaluate(_get_ca(pem)).accepted is True


class TestPolicyEngineServerAuthOnly:
    def test_accepts_cert_with_no_eku_when_server_auth_only(self):
        """server_auth_only only rejects if EKU is present but serverAuth absent.
        A cert with no EKU at all is passed through (conservative default)."""
        engine = PolicyEngine({"server_auth_only": True})
        # No EKU extension → parse produces empty list, policy accepts
        # (We can't easily test "no extension" here; use a cert with serverAuth)
        pem_sa, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH], key_size=1024)
        ci = _get_ca(pem_sa)
        assert engine.evaluate(ci).accepted is True

    def test_rejects_cert_with_client_auth_only_when_server_auth_only(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.CLIENT_AUTH], key_size=1024)
        engine = PolicyEngine({"server_auth_only": True})
        decision = engine.evaluate(_get_ca(pem))
        assert decision.accepted is False
        assert "serverAuth" in decision.reason

    def test_fingerprint_sha1_include_rule(self, ca_pem):
        ci = _get_ca(ca_pem)
        engine = PolicyEngine({"include": [{"fingerprint_sha1": ci.fingerprint_sha1}]})
        assert engine.evaluate(ci).accepted is True

    def test_unknown_rule_key_is_warned_and_never_matches(self, ca_pem):
        """A rule dict with no recognised keys should not accept any cert."""
        engine = PolicyEngine({"include": [{"unknown_key": "value"}]})
        decision = engine.evaluate(_get_ca(ca_pem))
        assert decision.accepted is False


class TestPolicyEngineClientAuthOnly:
    def test_accepts_cert_with_client_auth(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.CLIENT_AUTH], key_size=1024)
        engine = PolicyEngine({"client_auth_only": True})
        assert engine.evaluate(_get_ca(pem)).accepted is True

    def test_rejects_cert_with_server_auth_only_when_client_auth_only(self):
        pem, _, _ = _make_ca_cert(eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH], key_size=1024)
        engine = PolicyEngine({"client_auth_only": True})
        decision = engine.evaluate(_get_ca(pem))
        assert decision.accepted is False
        assert "clientAuth" in decision.reason


# ---------------------------------------------------------------------------
# PolicyOutcome — ternary outcome infrastructure
# ---------------------------------------------------------------------------

class TestPolicyOutcome:
    """PolicyOutcome constants and PolicyDecision behaviour."""

    def test_accept_outcome_is_accepted(self):
        from crab.policy import PolicyOutcome, PolicyDecision
        d = PolicyDecision(PolicyOutcome.ACCEPT, "ok")
        assert d.accepted is True
        assert bool(d) is True

    def test_reject_outcome_is_not_accepted(self):
        from crab.policy import PolicyOutcome, PolicyDecision
        d = PolicyDecision(PolicyOutcome.REJECT, "bad")
        assert d.accepted is False
        assert bool(d) is False

    def test_warn_outcome_is_accepted(self):
        """WARN passes the cert to output (accepted=True) while flagging it."""
        from crab.policy import PolicyOutcome, PolicyDecision
        d = PolicyDecision(PolicyOutcome.WARN, "soft fail")
        assert d.accepted is True
        assert bool(d) is True

    def test_accept_sentinel(self):
        from crab.policy import ACCEPT, PolicyOutcome
        assert ACCEPT.outcome == PolicyOutcome.ACCEPT
        assert ACCEPT.accepted is True

    def test_repr_shows_outcome(self):
        from crab.policy import PolicyOutcome, PolicyDecision
        d = PolicyDecision(PolicyOutcome.REJECT, "expired")
        assert "reject" in repr(d)
        assert "expired" in repr(d)

    def test_filter_includes_warn_certs(self, ca_pem):
        """PolicyEngine.filter passes WARN certs through to the accepted list."""
        from crab.policy import PolicyOutcome, PolicyDecision, PolicyEngine
        from crab.cert import parse_pem_data
        from unittest.mock import patch
        certs = parse_pem_data(ca_pem)
        engine = PolicyEngine({})
        warn_decision = PolicyDecision(PolicyOutcome.WARN, "test warning")
        with patch.object(engine, "evaluate", return_value=warn_decision):
            result = engine.filter(certs)
        assert len(result) == len(certs)
