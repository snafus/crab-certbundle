"""
Policy engine — filters and classifies certificates for an output profile.

A :class:`PolicyEngine` is constructed from the ``policy`` section of a
profile config block and exposes a single method :meth:`evaluate` that
returns a :class:`PolicyDecision` for each :class:`CertificateInfo`.

Policy rules are evaluated in order:

1. Structural checks (non-CA, v3 path-len 0 leaf, …)
2. Validity window checks (expired, not-yet-valid)
3. Explicit *include* rules — if any are defined, the certificate must match
   at least one to continue.
4. Explicit *exclude* rules — if any match the certificate is rejected.

If a certificate passes all checks it is accepted.
"""

import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from certbundle.cert import CertificateInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Decision object
# ---------------------------------------------------------------------------

class PolicyDecision:
    """Outcome of evaluating one certificate against a policy."""

    __slots__ = ("accepted", "reason")

    def __init__(self, accepted, reason=""):
        # type: (bool, str) -> None
        self.accepted = accepted
        self.reason = reason

    def __bool__(self):
        return self.accepted

    def __repr__(self):
        return "PolicyDecision(accepted={}, reason={!r})".format(
            self.accepted, self.reason
        )


ACCEPT = PolicyDecision(True, "accepted")


def _reject(reason):
    return PolicyDecision(False, reason)


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluate certificates against a policy configuration block.

    Typical config block (from profile → policy in YAML)::

        policy:
          reject_expired: true
          reject_not_yet_valid: false
          require_ca_flag: true       # must have BasicConstraints: CA=TRUE
          reject_path_len_zero: false # reject end-entity certs with pathLen=0
          server_auth_only: false     # only include certs with serverAuth EKU
          client_auth_only: false     # only include certs with clientAuth EKU
          include:
            - subject_regex: ".*"
            - fingerprint_sha256: "AA:BB:..."
          exclude:
            - subject_regex: "CN=Revoked CA.*"
            - fingerprint_sha256: "CC:DD:..."
            - source: "some-source-name"
    """

    def __init__(self, policy_config=None):
        # type: (Optional[dict]) -> None
        cfg = policy_config or {}

        self.reject_expired = bool(cfg.get("reject_expired", True))
        self.reject_not_yet_valid = bool(cfg.get("reject_not_yet_valid", False))
        self.require_ca_flag = bool(cfg.get("require_ca_flag", True))
        self.reject_path_len_zero = bool(cfg.get("reject_path_len_zero", False))
        self.server_auth_only = bool(cfg.get("server_auth_only", False))
        self.client_auth_only = bool(cfg.get("client_auth_only", False))

        raw_include = cfg.get("include", [])
        raw_exclude = cfg.get("exclude", [])

        self._include_rules = [_compile_rule(r) for r in raw_include]
        self._exclude_rules = [_compile_rule(r) for r in raw_exclude]

    def evaluate(self, cert_info):
        # type: (CertificateInfo) -> PolicyDecision
        """Return a :class:`PolicyDecision` for *cert_info*."""
        now = datetime.now(timezone.utc)

        # 1. Structural checks
        if self.require_ca_flag and not cert_info.is_ca:
            return _reject("not a CA certificate (BasicConstraints CA=FALSE or absent)")

        if self.reject_path_len_zero and cert_info.path_len == 0:
            # pathLen=0 means the cert can sign end-entity certs only; it is
            # an intermediate, not a root trust anchor.
            return _reject("pathLen=0 (intermediate CA, not a root)")

        # 2. Validity checks
        if self.reject_expired and cert_info.not_after < now:
            return _reject("certificate expired ({})".format(
                cert_info.not_after.strftime("%Y-%m-%d")
            ))

        if self.reject_not_yet_valid and cert_info.not_before > now:
            return _reject("certificate not yet valid ({})".format(
                cert_info.not_before.strftime("%Y-%m-%d")
            ))

        # 3. EKU filters
        if self.server_auth_only and cert_info.extended_key_usage:
            if not cert_info.has_server_auth_eku():
                return _reject("server_auth_only: serverAuth EKU absent")

        if self.client_auth_only and cert_info.extended_key_usage:
            if not cert_info.has_client_auth_eku():
                return _reject("client_auth_only: clientAuth EKU absent")

        # 4. Include rules (if defined, cert must match at least one)
        if self._include_rules:
            if not any(rule(cert_info) for rule in self._include_rules):
                return _reject("no include rule matched")

        # 5. Exclude rules
        for rule in self._exclude_rules:
            if rule(cert_info):
                return _reject("matched exclude rule")

        return ACCEPT

    def filter(self, cert_infos):
        # type: (List[CertificateInfo]) -> List[CertificateInfo]
        """
        Filter *cert_infos* using this policy.

        Returns the accepted subset; logs a DEBUG line for each rejection.
        """
        accepted = []
        rejected = []
        for ci in cert_infos:
            decision = self.evaluate(ci)
            if decision.accepted:
                accepted.append(ci)
            else:
                rejected.append((ci, decision.reason))
                logger.debug(
                    "Policy rejected %s [%s]: %s",
                    ci.subject, ci.source_name or "?", decision.reason,
                )

        if rejected:
            # Summarise rejections at INFO so operators understand filtering.
            reason_counts = {}  # type: dict
            for _, reason in rejected:
                key = reason.split("(")[0].strip()  # drop per-cert details
                reason_counts[key] = reason_counts.get(key, 0) + 1
            summary = "; ".join(
                "{} × {}".format(n, r) for r, n in sorted(reason_counts.items())
            )
            logger.info(
                "Policy rejected %d/%d certificate(s): %s",
                len(rejected), len(cert_infos), summary,
            )

        return accepted


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------

def _compile_rule(rule_dict):
    # type: (dict) -> callable
    """
    Compile one rule dict into a callable ``(CertificateInfo) → bool``.

    Supported keys:
        subject_regex      Regex matched against full subject string.
        fingerprint_sha256 Exact SHA-256 fingerprint (colon-delimited).
        fingerprint_sha1   Exact SHA-1 fingerprint.
        source             Exact source_name string.
        igtf_policy        Exact IGTF policy tag (from .info file).
    """
    predicates = []

    if "subject_regex" in rule_dict:
        pat = re.compile(rule_dict["subject_regex"], re.IGNORECASE)
        predicates.append(lambda ci, p=pat: bool(p.search(ci.subject)))

    if "fingerprint_sha256" in rule_dict:
        fp = rule_dict["fingerprint_sha256"].upper().replace("-", ":").strip()
        predicates.append(lambda ci, f=fp: ci.fingerprint_sha256.upper() == f)

    if "fingerprint_sha1" in rule_dict:
        fp = rule_dict["fingerprint_sha1"].upper().replace("-", ":").strip()
        predicates.append(lambda ci, f=fp: ci.fingerprint_sha1.upper() == f)

    if "source" in rule_dict:
        src = rule_dict["source"]
        predicates.append(lambda ci, s=src: ci.source_name == s)

    if "igtf_policy" in rule_dict:
        pol = rule_dict["igtf_policy"].lower()
        predicates.append(
            lambda ci, p=pol: ci.igtf_info.get("policy", "").lower() == p
        )

    if not predicates:
        logger.warning("Policy rule has no recognised keys: %s", rule_dict)
        return lambda ci: False

    # All predicates within one rule must match (AND semantics)
    def combined(ci, preds=predicates):
        return all(pred(ci) for pred in preds)

    return combined
