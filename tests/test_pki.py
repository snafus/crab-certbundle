"""
Tests for crab/pki.py — CA initialisation, cert issuance, revocation, CRL.
"""

import json
import os
import stat

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as _ec, ed25519 as _ed25519, rsa as _rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from crab.pki import (
    CADirectory,
    PKIError,
    SerialDB,
    generate_crl,
    init_ca,
    init_intermediate_ca,
    issue_cert,
    list_issued,
    renew_cert,
    revoke_cert,
    show_ca_info,
    _cdp_url_from_cert,
    _days_from_cert,
    _key_type_from_public_key,
    _profile_from_cert,
    _sans_from_cert,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ca_dir(tmp_path):
    """A freshly initialised RSA-2048 CA directory."""
    init_ca(str(tmp_path), cn="Test CA", days=30)
    return str(tmp_path)


@pytest.fixture
def ca_dir_ed25519(tmp_path):
    """A freshly initialised Ed25519 CA directory."""
    init_ca(str(tmp_path), cn="Ed25519 Test CA", key_type="ed25519", days=30)
    return str(tmp_path)


@pytest.fixture
def issued_cert(ca_dir, tmp_path):
    """A server cert already issued by ca_dir."""
    out = str(tmp_path / "issued")
    cert_path, key_path = issue_cert(
        ca_dir, cn="host.example.com", out_dir=out
    )
    return cert_path, key_path


# ---------------------------------------------------------------------------
# CA initialisation
# ---------------------------------------------------------------------------

class TestInitCA:
    def test_creates_cert_and_key(self, tmp_path):
        cert_path, key_path = init_ca(str(tmp_path), cn="My CA")
        assert os.path.isfile(cert_path)
        assert os.path.isfile(key_path)

    def test_creates_issued_directory(self, tmp_path):
        init_ca(str(tmp_path), cn="My CA")
        assert os.path.isdir(os.path.join(str(tmp_path), "issued"))

    def test_key_mode_is_0600(self, tmp_path):
        _, key_path = init_ca(str(tmp_path), cn="My CA")
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600

    def test_cert_is_pem(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA")
        with open(cert_path, "rb") as fh:
            data = fh.read()
        assert data.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_cert_is_self_signed(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA")
        cert = _load_cert(cert_path)
        assert cert.subject == cert.issuer

    def test_basic_constraints_ca_true(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA")
        cert = _load_cert(cert_path)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True
        assert bc.value.path_length is None

    def test_key_usage_cert_sign_and_crl_sign(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA")
        cert = _load_cert(cert_path)
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku_ext.critical is True
        assert ku_ext.value.key_cert_sign is True
        assert ku_ext.value.crl_sign is True

    def test_has_subject_key_identifier(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA")
        cert = _load_cert(cert_path)
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)  # no exception

    def test_common_name(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My Test CA")
        cert = _load_cert(cert_path)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "My Test CA"

    def test_org_name(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA", org="ACME Ltd")
        cert = _load_cert(cert_path)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        assert org == "ACME Ltd"

    def test_rsa2048_key(self, tmp_path):
        _, key_path = init_ca(str(tmp_path), cn="My CA", key_type="rsa2048")
        cert_path = os.path.join(str(tmp_path), "ca-cert.pem")
        cert = _load_cert(cert_path)
        assert isinstance(cert.public_key(), _rsa.RSAPublicKey)
        assert cert.public_key().key_size == 2048

    def test_rsa4096_key(self, tmp_path):
        init_ca(str(tmp_path), cn="My CA", key_type="rsa4096")
        cert_path = os.path.join(str(tmp_path), "ca-cert.pem")
        cert = _load_cert(cert_path)
        assert cert.public_key().key_size == 4096

    def test_ed25519_key(self, tmp_path):
        init_ca(str(tmp_path), cn="My CA", key_type="ed25519")
        cert_path = os.path.join(str(tmp_path), "ca-cert.pem")
        cert = _load_cert(cert_path)
        assert isinstance(cert.public_key(), _ed25519.Ed25519PublicKey)

    def test_rejects_existing_ca(self, tmp_path):
        init_ca(str(tmp_path), cn="CA1")
        with pytest.raises(PKIError, match="already exists"):
            init_ca(str(tmp_path), cn="CA2")

    def test_force_overwrites_existing(self, tmp_path):
        init_ca(str(tmp_path), cn="CA1")
        # Should not raise
        init_ca(str(tmp_path), cn="CA2", force=True)
        cert = _load_cert(os.path.join(str(tmp_path), "ca-cert.pem"))
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "CA2"

    def test_rejects_unknown_key_type(self, tmp_path):
        with pytest.raises(PKIError, match="Unknown key type"):
            init_ca(str(tmp_path), cn="My CA", key_type="dsa1024")

    def test_validity_period(self, tmp_path):
        cert_path, _ = init_ca(str(tmp_path), cn="My CA", days=90)
        cert = _load_cert(cert_path)
        delta = cert.not_valid_after - cert.not_valid_before
        # Allow ±1 day to account for second-level rounding
        assert 89 <= delta.days <= 90


# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------

class TestIssueCert:
    def test_creates_cert_and_key(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, key_path = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        assert os.path.isfile(cert_path)
        assert os.path.isfile(key_path)

    def test_key_mode_is_0600(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        _, key_path = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600

    def test_issuer_matches_ca(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        ca_cert = CADirectory(ca_dir).load_cert()
        assert cert.issuer == ca_cert.subject

    def test_not_ca_cert(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        assert bc.critical is True

    def test_cn_added_as_dns_san(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        assert "host.example.com" in dns_names

    def test_explicit_san_dns(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com",
            sans=["DNS:alt.example.com"],
            out_dir=out,
        )
        cert = _load_cert(cert_path)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        assert "alt.example.com" in dns_names

    def test_explicit_san_ip(self, ca_dir, tmp_path):
        import ipaddress
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com",
            sans=["IP:10.0.0.1"],
            out_dir=out,
        )
        cert = _load_cert(cert_path)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ips = san.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("10.0.0.1") in ips

    def test_san_auto_detect_ip(self, ca_dir, tmp_path):
        import ipaddress
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com",
            sans=["192.168.1.1"],
            out_dir=out,
        )
        cert = _load_cert(cert_path)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ips = san.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("192.168.1.1") in ips

    # --- Profile: server ---

    def test_server_profile_server_auth_eku(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com",
                                  profile="server", out_dir=out)
        eku = _get_eku(cert_path)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku
        assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku

    def test_server_profile_key_usage(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com",
                                  profile="server", out_dir=out)
        cert = _load_cert(cert_path)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature is True
        assert ku.key_encipherment is True  # RSA key
        assert ku.key_cert_sign is False

    # --- Profile: client ---

    def test_client_profile_client_auth_eku(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        # Client certs typically use an email SAN; CN alone without a dot
        # needs an explicit SAN.
        cert_path, _ = issue_cert(
            ca_dir, cn="alice", profile="client",
            sans=["EMAIL:alice@example.com"], out_dir=out,
        )
        eku = _get_eku(cert_path)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku

    # --- Profile: grid-host ---

    def test_grid_host_profile_has_both_eku(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="xrootd.example.com",
                                  profile="grid-host", out_dir=out)
        eku = _get_eku(cert_path)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    # --- Ed25519 CA issues certs ---

    def test_issue_from_ed25519_ca(self, ca_dir_ed25519, tmp_path):
        out = str(tmp_path / "out")
        cert_path, key_path = issue_cert(
            ca_dir_ed25519, cn="host.example.com", out_dir=out
        )
        assert os.path.isfile(cert_path)
        # Issued cert has RSA key (default), CA has Ed25519
        cert = _load_cert(cert_path)
        assert isinstance(cert.public_key(), _rsa.RSAPublicKey)

    def test_ed25519_issued_cert_no_key_encipherment(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com", key_type="ed25519", out_dir=out
        )
        cert = _load_cert(cert_path)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_encipherment is False
        assert ku.digital_signature is True

    def test_ecdsa_p256_key(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com", key_type="ecdsa-p256", out_dir=out
        )
        cert = _load_cert(cert_path)
        pub = cert.public_key()
        assert isinstance(pub, _ec.EllipticCurvePublicKey)
        assert isinstance(pub.curve, _ec.SECP256R1)

    def test_ecdsa_p384_key(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com", key_type="ecdsa-p384", out_dir=out
        )
        cert = _load_cert(cert_path)
        pub = cert.public_key()
        assert isinstance(pub, _ec.EllipticCurvePublicKey)
        assert isinstance(pub.curve, _ec.SECP384R1)

    def test_ecdsa_no_key_encipherment(self, ca_dir, tmp_path):
        """ECDSA keys must not have keyEncipherment — EC uses ECDH, not RSA key exchange."""
        for kt in ("ecdsa-p256", "ecdsa-p384"):
            out = str(tmp_path / kt)
            cert_path, _ = issue_cert(
                ca_dir, cn="host.example.com", key_type=kt, out_dir=out
            )
            cert = _load_cert(cert_path)
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            assert ku.key_encipherment is False, "{} should not have keyEncipherment".format(kt)
            assert ku.digital_signature is True

    def test_p384_ca_signs_with_sha384(self, tmp_path):
        """A P-384 CA uses SHA-384 signatures — matching the curve's security level."""
        ca_p384 = str(tmp_path / "p384-ca")
        init_ca(ca_p384, cn="P384 CA", key_type="ecdsa-p384")
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_p384, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)

    def test_p256_ca_signs_with_sha256(self, tmp_path):
        """A P-256 CA uses SHA-256 signatures."""
        ca_p256 = str(tmp_path / "p256-ca")
        init_ca(ca_p256, cn="P256 CA", key_type="ecdsa-p256")
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_p256, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)

    def test_key_type_label_p256(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        init_ca(str(tmp_path / "p256-ca"), cn="P256 CA", key_type="ecdsa-p256")
        info = show_ca_info(str(tmp_path / "p256-ca"))
        assert info["key_type"] == "ECDSA-SECP256R1"

    def test_key_type_label_p384(self, tmp_path):
        init_ca(str(tmp_path / "p384-ca"), cn="P384 CA", key_type="ecdsa-p384")
        info = show_ca_info(str(tmp_path / "p384-ca"))
        assert info["key_type"] == "ECDSA-SECP384R1"

    # --- Serial numbers ---

    def test_serials_increment(self, ca_dir, tmp_path):
        out1, out2 = str(tmp_path / "o1"), str(tmp_path / "o2")
        cert1, _ = issue_cert(ca_dir, cn="h1.example.com", out_dir=out1)
        cert2, _ = issue_cert(ca_dir, cn="h2.example.com", out_dir=out2)
        c1 = _load_cert(cert1)
        c2 = _load_cert(cert2)
        assert c2.serial_number == c1.serial_number + 1

    def test_first_serial_is_one(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        assert cert.serial_number == 1

    # --- Serial DB ---

    def test_record_written_to_db(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        records = CADirectory(ca_dir).serial_db.records()
        assert len(records) == 1
        r = records[0]
        assert r["cn"] == "host.example.com"
        assert r["serial"] == 1
        assert r["revoked"] is False
        assert r["profile"] == "server"

    # --- CDP URL ---

    def test_cdp_url_embedded(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="host.example.com",
            cdp_url="http://crl.example.com/ca.crl",
            out_dir=out,
        )
        cert = _load_cert(cert_path)
        cdp_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        urls = [dp.full_name[0].value for dp in cdp_ext.value]
        assert "http://crl.example.com/ca.crl" in urls

    def test_no_cdp_when_not_specified(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(ca_dir, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)

    # --- Error cases ---

    def test_missing_ca_raises(self, tmp_path):
        with pytest.raises(PKIError, match="No CA found"):
            issue_cert(str(tmp_path / "noexist"), cn="host.example.com")

    def test_unknown_profile_raises(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        with pytest.raises(PKIError, match="Unknown profile"):
            issue_cert(ca_dir, cn="host.example.com", profile="bogus", out_dir=out)

    def test_cn_without_dot_requires_explicit_san(self, ca_dir, tmp_path):
        """CN without a dot is not auto-added as DNS SAN; must supply --san."""
        out = str(tmp_path / "out")
        with pytest.raises(PKIError, match="No Subject Alternative Names"):
            issue_cert(ca_dir, cn="justahostname", out_dir=out)

    def test_cn_without_dot_with_san_ok(self, ca_dir, tmp_path):
        """CN without a dot is fine if an explicit SAN is provided."""
        out = str(tmp_path / "out")
        cert_path, _ = issue_cert(
            ca_dir, cn="server", sans=["DNS:server.example.com"], out_dir=out
        )
        assert os.path.isfile(cert_path)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoke_marks_record(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        records = CADirectory(ca_dir).serial_db.records()
        assert records[0]["revoked"] is True
        assert records[0]["revoked_at"] is not None

    def test_revoke_generates_crl(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        assert os.path.isfile(CADirectory(ca_dir).crl_path)

    def test_crl_is_pem(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        with open(CADirectory(ca_dir).crl_path, "rb") as fh:
            data = fh.read()
        assert data.startswith(b"-----BEGIN X509 CRL-----")

    def test_crl_contains_revoked_serial(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        cert = _load_cert(cert_path)
        serial = cert.serial_number
        revoke_cert(ca_dir, cert_path)
        crl = _load_crl(CADirectory(ca_dir).crl_path)
        revoked_serials = [r.serial_number for r in crl]
        assert serial in revoked_serials

    def test_crl_signed_by_ca(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        ca = CADirectory(ca_dir)
        crl = _load_crl(ca.crl_path)
        ca_cert = ca.load_cert()
        assert crl.issuer == ca_cert.subject

    def test_double_revoke_raises(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        with pytest.raises(PKIError, match="already revoked"):
            revoke_cert(ca_dir, cert_path)

    def test_revoke_cert_from_other_ca_raises(self, ca_dir, tmp_path):
        """Cert not in this CA's serial DB should raise PKIError."""
        other_dir = str(tmp_path / "other-ca")
        init_ca(other_dir, cn="Other CA")
        out = str(tmp_path / "other-out")
        cert_path, _ = issue_cert(other_dir, cn="host.example.com", out_dir=out)
        with pytest.raises(PKIError):
            revoke_cert(ca_dir, cert_path)

    def test_revoke_with_reason(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path, reason="keyCompromise")
        records = CADirectory(ca_dir).serial_db.records()
        assert records[0]["revoke_reason"] == "keyCompromise"

    def test_crl_reason_in_crl(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        cert = _load_cert(cert_path)
        serial = cert.serial_number
        revoke_cert(ca_dir, cert_path, reason="superseded")
        crl = _load_crl(CADirectory(ca_dir).crl_path)
        for rev in crl:
            if rev.serial_number == serial:
                reason_ext = rev.extensions.get_extension_for_class(x509.CRLReason)
                assert reason_ext.value.reason == x509.ReasonFlags.superseded
                break
        else:
            pytest.fail("Revoked serial not found in CRL")

    def test_invalid_reason_raises(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        with pytest.raises(PKIError, match="Unknown revocation reason"):
            revoke_cert(ca_dir, cert_path, reason="badReason")

    def test_revoke_missing_ca_raises(self, tmp_path, issued_cert):
        cert_path, _ = issued_cert
        with pytest.raises(PKIError, match="No CA found"):
            revoke_cert(str(tmp_path / "noexist"), cert_path)


# ---------------------------------------------------------------------------
# CRL generation (standalone)
# ---------------------------------------------------------------------------

class TestGenerateCRL:
    def test_generate_crl_empty(self, ca_dir):
        crl_path = generate_crl(ca_dir)
        assert os.path.isfile(crl_path)
        crl = _load_crl(crl_path)
        assert len(list(crl)) == 0

    def test_generate_crl_missing_ca_raises(self, tmp_path):
        with pytest.raises(PKIError, match="No CA found"):
            generate_crl(str(tmp_path / "noexist"))


# ---------------------------------------------------------------------------
# show_ca_info
# ---------------------------------------------------------------------------

class TestShowCAInfo:
    def test_returns_expected_keys(self, ca_dir):
        info = show_ca_info(ca_dir)
        for key in ("subject", "issuer", "is_root", "fingerprint_sha256",
                    "not_before", "not_after", "key_type", "path_length",
                    "issued_count", "revoked_count", "crl_exists", "chain_exists"):
            assert key in info, "Missing key: {}".format(key)

    def test_root_ca_is_root(self, ca_dir):
        assert show_ca_info(ca_dir)["is_root"] is True

    def test_root_ca_path_length_is_none(self, ca_dir):
        """Root CAs are initialised without a pathLen constraint."""
        assert show_ca_info(ca_dir)["path_length"] is None

    def test_root_ca_chain_does_not_exist(self, ca_dir):
        assert show_ca_info(ca_dir)["chain_exists"] is False

    def test_issued_count_zero_initially(self, ca_dir):
        assert show_ca_info(ca_dir)["issued_count"] == 0

    def test_issued_count_increments(self, ca_dir, tmp_path):
        out = str(tmp_path / "out")
        issue_cert(ca_dir, cn="h1.example.com", out_dir=out)
        issue_cert(ca_dir, cn="h2.example.com", out_dir=out)
        info = show_ca_info(ca_dir)
        assert info["issued_count"] == 2
        assert info["revoked_count"] == 0

    def test_revoked_count(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        info = show_ca_info(ca_dir)
        assert info["revoked_count"] == 1

    def test_key_type_label(self, tmp_path):
        init_ca(str(tmp_path), cn="My CA", key_type="rsa2048")
        assert show_ca_info(str(tmp_path))["key_type"] == "RSA-2048"

    def test_key_type_label_ed25519(self, ca_dir_ed25519):
        assert show_ca_info(ca_dir_ed25519)["key_type"] == "Ed25519"

    def test_crl_exists_false_initially(self, ca_dir):
        assert show_ca_info(ca_dir)["crl_exists"] is False

    def test_crl_exists_true_after_revoke(self, ca_dir, issued_cert):
        cert_path, _ = issued_cert
        revoke_cert(ca_dir, cert_path)
        assert show_ca_info(ca_dir)["crl_exists"] is True

    def test_missing_ca_raises(self, tmp_path):
        with pytest.raises(PKIError, match="No CA found"):
            show_ca_info(str(tmp_path / "noexist"))


# ---------------------------------------------------------------------------
# list_issued
# ---------------------------------------------------------------------------

class TestListIssued:
    def test_empty_initially(self, ca_dir):
        assert list_issued(ca_dir) == []

    def test_lists_one(self, ca_dir, issued_cert):
        records = list_issued(ca_dir)
        assert len(records) == 1
        assert records[0]["cn"] == "host.example.com"

    def test_missing_ca_raises(self, tmp_path):
        with pytest.raises(PKIError, match="No CA found"):
            list_issued(str(tmp_path / "noexist"))


# ---------------------------------------------------------------------------
# SerialDB
# ---------------------------------------------------------------------------

class TestSerialDB:
    def test_next_serial_when_empty(self, tmp_path):
        db = SerialDB(str(tmp_path / "serial.db"))
        assert db.next_serial() == 1

    def test_next_serial_increments(self, tmp_path):
        db = SerialDB(str(tmp_path / "serial.db"))
        db.append({"serial": 1, "fingerprint_sha256": "AA"})
        db.append({"serial": 2, "fingerprint_sha256": "BB"})
        assert db.next_serial() == 3

    def test_records_returns_all(self, tmp_path):
        db = SerialDB(str(tmp_path / "serial.db"))
        db.append({"serial": 1, "x": "a"})
        db.append({"serial": 2, "x": "b"})
        recs = db.records()
        assert len(recs) == 2

    def test_revoke_updates_record(self, tmp_path):
        db = SerialDB(str(tmp_path / "serial.db"))
        db.append({
            "serial": 1,
            "fingerprint_sha256": "AA:BB",
            "revoked": False,
            "revoked_at": None,
            "revoke_reason": None,
        })
        db.revoke("AA:BB", "2026-01-01T00:00:00Z", "unspecified")
        recs = db.records()
        assert recs[0]["revoked"] is True
        assert recs[0]["revoked_at"] == "2026-01-01T00:00:00Z"

    def test_revoke_unknown_fingerprint_raises(self, tmp_path):
        db = SerialDB(str(tmp_path / "serial.db"))
        db.append({"serial": 1, "fingerprint_sha256": "AA", "revoked": False})
        with pytest.raises(PKIError, match="not found"):
            db.revoke("ZZ", "2026-01-01T00:00:00Z")

    def test_revoke_already_revoked_raises(self, tmp_path):
        db = SerialDB(str(tmp_path / "serial.db"))
        db.append({"serial": 1, "fingerprint_sha256": "AA", "revoked": True})
        with pytest.raises(PKIError, match="already revoked"):
            db.revoke("AA", "2026-01-01T00:00:00Z")


# ---------------------------------------------------------------------------
# Intermediate CA
# ---------------------------------------------------------------------------

class TestIntermediateCA:
    """Tests for init_intermediate_ca."""

    def test_creates_directory_structure(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        assert os.path.isfile(os.path.join(sub, "ca-cert.pem"))
        assert os.path.isfile(os.path.join(sub, "ca-key.pem"))
        assert os.path.isfile(os.path.join(sub, "ca-chain.pem"))

    def test_ca_cert_is_signed_by_parent(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        root_cert = _load_cert(os.path.join(root, "ca-cert.pem"))
        sub_cert  = _load_cert(os.path.join(sub,  "ca-cert.pem"))
        # Issuer of sub should equal subject of root
        assert sub_cert.issuer == root_cert.subject

    def test_basic_constraints_ca_true(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True

    def test_path_length_default_zero(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.path_length == 0

    def test_path_length_none_when_unconstrained(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA", path_length=None)
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.path_length is None

    def test_path_length_custom(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA", path_length=1)
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.path_length == 1

    def test_chain_file_contains_both_certs(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        with open(os.path.join(sub, "ca-chain.pem"), "rb") as fh:
            chain_pem = fh.read()
        # Should contain both PEM blocks
        assert chain_pem.count(b"-----BEGIN CERTIFICATE-----") == 2
        # First cert in chain is the intermediate
        certs = [x509.load_pem_x509_certificate(b"-----BEGIN CERTIFICATE-----" + p)
                 for p in chain_pem.split(b"-----BEGIN CERTIFICATE-----")[1:]]
        assert len(certs) == 2
        assert certs[0].subject.rfc4514_string() == "CN=Sub CA"
        assert certs[1].subject.rfc4514_string() == "CN=Root CA"

    def test_chain_file_three_levels(self, tmp_path):
        """Three-level chain: root → intermediate → leaf-ca; chain has 3 certs."""
        root = str(tmp_path / "root")
        mid  = str(tmp_path / "mid")
        leaf = str(tmp_path / "leaf")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(mid, root, cn="Mid CA", path_length=1)
        init_intermediate_ca(leaf, mid, cn="Leaf CA", path_length=0)
        with open(os.path.join(leaf, "ca-chain.pem"), "rb") as fh:
            chain_pem = fh.read()
        assert chain_pem.count(b"-----BEGIN CERTIFICATE-----") == 3

    def test_issuance_recorded_in_parent_db(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        records = list_issued(root)
        assert len(records) == 1
        assert records[0]["cn"] == "Sub CA"
        assert records[0]["profile"] == "intermediate-ca"

    def test_intermediate_can_issue_end_entity_certs(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        out  = str(tmp_path / "certs")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        cert_path, _ = issue_cert(sub, cn="host.example.com", out_dir=out)
        cert = _load_cert(cert_path)
        sub_cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        assert cert.issuer == sub_cert.subject

    def test_fullchain_written_for_intermediate_signed_cert(self, tmp_path):
        """issue_cert writes a fullchain file when CA is an intermediate."""
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        out  = str(tmp_path / "certs")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        cert_path, _ = issue_cert(sub, cn="host.example.com", out_dir=out)
        fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
        assert os.path.isfile(fullchain_path), "fullchain file not written"

    def test_fullchain_contains_leaf_and_intermediate_not_root(self, tmp_path):
        """fullchain = leaf cert + intermediate CA cert; root excluded."""
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        out  = str(tmp_path / "certs")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        cert_path, _ = issue_cert(sub, cn="host.example.com", out_dir=out)
        fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
        with open(fullchain_path, "rb") as fh:
            fullchain_pem = fh.read()
        # Should have exactly 2 certs: leaf + intermediate
        assert fullchain_pem.count(b"-----BEGIN CERTIFICATE-----") == 2
        # First cert is the leaf
        blocks = fullchain_pem.split(b"-----BEGIN CERTIFICATE-----")[1:]
        certs = [x509.load_pem_x509_certificate(
            b"-----BEGIN CERTIFICATE-----" + b) for b in blocks]
        assert certs[0].subject.rfc4514_string() == "CN=host.example.com"
        assert certs[1].subject.rfc4514_string() == "CN=Sub CA"
        # Root must NOT be present
        subjects = [c.subject.rfc4514_string() for c in certs]
        assert "CN=Root CA" not in subjects

    def test_fullchain_three_level_contains_two_intermediates(self, tmp_path):
        """Three-level chain: fullchain has leaf + 2 intermediates, no root."""
        root = str(tmp_path / "root")
        mid  = str(tmp_path / "mid")
        leaf = str(tmp_path / "leaf")
        out  = str(tmp_path / "certs")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(mid, root, cn="Mid CA", path_length=1)
        init_intermediate_ca(leaf, mid, cn="Leaf CA", path_length=0)
        cert_path, _ = issue_cert(leaf, cn="host.example.com", out_dir=out)
        fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
        with open(fullchain_path, "rb") as fh:
            fullchain_pem = fh.read()
        assert fullchain_pem.count(b"-----BEGIN CERTIFICATE-----") == 3
        assert b"Root CA" not in fullchain_pem

    def test_no_fullchain_for_root_ca_signed_cert(self, tmp_path):
        """When the issuing CA is a root, no fullchain file is written."""
        root = str(tmp_path / "root")
        out  = str(tmp_path / "certs")
        init_ca(root, cn="Root CA")
        cert_path, _ = issue_cert(root, cn="host.example.com", out_dir=out)
        fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
        assert not os.path.isfile(fullchain_path)

    def test_show_ca_info_intermediate(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        info = show_ca_info(sub)
        assert info["is_root"] is False
        assert info["path_length"] == 0
        assert info["chain_exists"] is True
        assert "Root CA" in info["issuer"]

    def test_raises_if_parent_not_found(self, tmp_path):
        with pytest.raises(PKIError, match="No CA found"):
            init_intermediate_ca(
                str(tmp_path / "sub"),
                str(tmp_path / "nonexistent-parent"),
                cn="Sub CA",
            )

    def test_raises_if_already_exists_without_force(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA")
        with pytest.raises(PKIError, match="already exists"):
            init_intermediate_ca(sub, root, cn="Sub CA 2")

    def test_force_overwrites_existing(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA v1")
        init_intermediate_ca(sub, root, cn="Sub CA v2", force=True)
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        assert "v2" in cert.subject.rfc4514_string()

    def test_parent_path_len_zero_raises(self, tmp_path):
        """A parent with pathLen=0 must refuse to sign a CA cert."""
        root = str(tmp_path / "root")
        mid  = str(tmp_path / "mid")
        leaf = str(tmp_path / "leaf")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(mid, root, cn="Mid CA", path_length=0)
        with pytest.raises(PKIError, match="pathLen=0"):
            init_intermediate_ca(leaf, mid, cn="Leaf CA")

    def test_key_type_ed25519(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA", key_type="ed25519")
        info = show_ca_info(sub)
        assert info["key_type"] == "Ed25519"

    def test_cdp_url_embedded(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA")
        init_intermediate_ca(sub, root, cn="Sub CA",
                             cdp_url="http://crl.example.com/root.crl")
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        cdps = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
        urls = [
            p.full_name[0].value
            for p in cdps
            if p.full_name
        ]
        assert "http://crl.example.com/root.crl" in urls


class TestIntermediateCACLI:
    """CLI integration tests for crabctl ca intermediate."""

    def test_creates_intermediate_ca(self, runner, tmp_path):
        from crab.cli import main
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        runner.invoke(main, ["-q", "ca", "init", root, "--name", "Root CA"],
                      catch_exceptions=False)
        result = runner.invoke(
            main,
            ["-q", "ca", "intermediate", sub,
             "--parent", root, "--name", "Sub CA"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(sub, "ca-cert.pem"))
        assert os.path.isfile(os.path.join(sub, "ca-chain.pem"))

    def test_ca_show_indicates_intermediate(self, runner, tmp_path):
        from crab.cli import main
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        runner.invoke(main, ["-q", "ca", "init", root, "--name", "Root CA"],
                      catch_exceptions=False)
        runner.invoke(main,
                      ["-q", "ca", "intermediate", sub,
                       "--parent", root, "--name", "Sub CA"],
                      catch_exceptions=False)
        result = runner.invoke(main, ["-q", "ca", "show", sub],
                               catch_exceptions=False)
        assert "intermediate" in result.output
        assert "Chain file" in result.output

    def test_path_length_negative_means_unconstrained(self, runner, tmp_path):
        from crab.cli import main
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        runner.invoke(main, ["-q", "ca", "init", root, "--name", "Root CA"],
                      catch_exceptions=False)
        result = runner.invoke(
            main,
            ["-q", "ca", "intermediate", sub,
             "--parent", root, "--name", "Policy CA",
             "--path-length", "-1"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        cert = _load_cert(os.path.join(sub, "ca-cert.pem"))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.path_length is None

    def test_error_on_missing_parent(self, runner, tmp_path):
        from crab.cli import main
        result = runner.invoke(
            main,
            ["-q", "ca", "intermediate", str(tmp_path / "sub"),
             "--parent", str(tmp_path / "noparent"), "--name", "Sub CA"],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Cert extraction helpers (_profile_from_cert, _sans_from_cert, etc.)
# ---------------------------------------------------------------------------

class TestCertExtractionHelpers:
    """Unit tests for the private helpers that read parameters from a cert."""

    def _issue(self, ca_dir, **kw):
        out = os.path.join(ca_dir, "issued")
        os.makedirs(out, exist_ok=True)
        cert_path, _ = issue_cert(ca_dir, out_dir=out, **kw)
        with open(cert_path, "rb") as fh:
            return x509.load_pem_x509_certificate(fh.read())

    def test_profile_server(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com", profile="server")
        assert _profile_from_cert(cert) == "server"

    def test_profile_client(self, ca_dir):
        cert = self._issue(ca_dir, cn="alice", profile="client",
                           sans=["EMAIL:alice@example.com"])
        assert _profile_from_cert(cert) == "client"

    def test_profile_grid_host(self, ca_dir):
        cert = self._issue(ca_dir, cn="xrd.example.com", profile="grid-host")
        assert _profile_from_cert(cert) == "grid-host"

    def test_sans_dns(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com")
        sans = _sans_from_cert(cert)
        assert "DNS:host.example.com" in sans

    def test_sans_multiple(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com",
                           sans=["DNS:alt.example.com", "IP:10.0.0.1"])
        sans = _sans_from_cert(cert)
        assert "DNS:host.example.com" in sans
        assert "DNS:alt.example.com" in sans
        assert "IP:10.0.0.1" in sans

    def test_sans_empty_when_no_extension(self, ca_dir):
        # client cert with bare CN — CN without dot means no auto-DNS SAN,
        # so we must supply one explicitly
        cert = self._issue(ca_dir, cn="alice", profile="client",
                           sans=["EMAIL:alice@example.com"])
        sans = _sans_from_cert(cert)
        assert "EMAIL:alice@example.com" in sans

    def test_cdp_url_present(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com",
                           cdp_url="http://crl.example.com/ca.crl")
        assert _cdp_url_from_cert(cert) == "http://crl.example.com/ca.crl"

    def test_cdp_url_absent(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com")
        assert _cdp_url_from_cert(cert) is None

    def test_days_from_cert(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com", days=42)
        assert _days_from_cert(cert) == 42

    def test_key_type_rsa2048(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com", key_type="rsa2048")
        assert _key_type_from_public_key(cert.public_key()) == "rsa2048"

    def test_key_type_ecdsa_p256(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com", key_type="ecdsa-p256")
        assert _key_type_from_public_key(cert.public_key()) == "ecdsa-p256"

    def test_key_type_ecdsa_p384(self, ca_dir):
        cert = self._issue(ca_dir, cn="host.example.com", key_type="ecdsa-p384")
        assert _key_type_from_public_key(cert.public_key()) == "ecdsa-p384"

    def test_key_type_ed25519(self, ca_dir_ed25519):
        cert = self._issue(ca_dir_ed25519, cn="host.example.com",
                           key_type="ed25519")
        assert _key_type_from_public_key(cert.public_key()) == "ed25519"


# ---------------------------------------------------------------------------
# renew_cert
# ---------------------------------------------------------------------------

class TestRenewCert:
    """Tests for renew_cert — the revoke-and-reissue flow."""

    def _issue(self, ca_dir, **kw):
        out = os.path.join(ca_dir, "issued")
        os.makedirs(out, exist_ok=True)
        kw.setdefault("cn", "host.example.com")
        return issue_cert(ca_dir, out_dir=out, **kw)

    # -- basic renewal -------------------------------------------------------

    def test_returns_same_paths(self, ca_dir):
        cert_path, key_path = self._issue(ca_dir)
        new_cert, new_key = renew_cert(ca_dir, cert_path)
        assert new_cert == cert_path
        assert new_key == key_path

    def test_new_cert_is_valid_pem(self, ca_dir):
        cert_path, _ = self._issue(ca_dir)
        renew_cert(ca_dir, cert_path)
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        assert cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "host.example.com"

    def test_old_cert_revoked_in_db(self, ca_dir):
        cert_path, _ = self._issue(ca_dir)
        with open(cert_path, "rb") as fh:
            old_cert = x509.load_pem_x509_certificate(fh.read())
        old_fp = ":".join("{:02X}".format(b) for b in old_cert.fingerprint(
            __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
        ))
        renew_cert(ca_dir, cert_path)
        from crab.pki import CADirectory as _CAD
        records = _CAD(ca_dir).serial_db.records()
        revoked = [r for r in records if r.get("fingerprint_sha256") == old_fp]
        assert len(revoked) == 1
        assert revoked[0]["revoked"] is True
        assert revoked[0]["revoke_reason"] == "superseded"

    def test_new_cert_in_db(self, ca_dir):
        cert_path, _ = self._issue(ca_dir)
        renew_cert(ca_dir, cert_path)
        records = CADirectory(ca_dir).serial_db.records()
        active = [r for r in records if not r.get("revoked")]
        assert len(active) == 1
        assert active[0]["cn"] == "host.example.com"

    def test_serial_db_grows_by_one(self, ca_dir):
        cert_path, _ = self._issue(ca_dir)
        before = len(CADirectory(ca_dir).serial_db.records())
        renew_cert(ca_dir, cert_path)
        after = len(CADirectory(ca_dir).serial_db.records())
        assert after == before + 1

    def test_new_key_is_different(self, ca_dir):
        cert_path, key_path = self._issue(ca_dir, key_type="rsa2048")
        with open(key_path, "rb") as fh:
            old_key_bytes = fh.read()
        renew_cert(ca_dir, cert_path)
        with open(key_path, "rb") as fh:
            new_key_bytes = fh.read()
        assert old_key_bytes != new_key_bytes

    def test_crl_regenerated(self, ca_dir):
        cert_path, _ = self._issue(ca_dir)
        renew_cert(ca_dir, cert_path)
        crl_path = os.path.join(ca_dir, "crl.pem")
        assert os.path.isfile(crl_path)
        with open(crl_path, "rb") as fh:
            crl = x509.load_pem_x509_crl(fh.read())
        assert len(list(crl)) == 1

    # -- days ----------------------------------------------------------------

    def test_default_days_matches_original(self, ca_dir):
        cert_path, _ = self._issue(ca_dir, days=42)
        renew_cert(ca_dir, cert_path)
        with open(cert_path, "rb") as fh:
            new_cert = x509.load_pem_x509_certificate(fh.read())
        delta = (new_cert.not_valid_after - new_cert.not_valid_before).days
        assert delta == 42

    def test_override_days(self, ca_dir):
        cert_path, _ = self._issue(ca_dir, days=365)
        renew_cert(ca_dir, cert_path, days=90)
        with open(cert_path, "rb") as fh:
            new_cert = x509.load_pem_x509_certificate(fh.read())
        delta = (new_cert.not_valid_after - new_cert.not_valid_before).days
        assert delta == 90

    # -- reuse_key -----------------------------------------------------------

    def test_reuse_key_keeps_key_bytes(self, ca_dir):
        cert_path, key_path = self._issue(ca_dir)
        with open(key_path, "rb") as fh:
            original_key_bytes = fh.read()
        renew_cert(ca_dir, cert_path, reuse_key=True)
        with open(key_path, "rb") as fh:
            new_key_bytes = fh.read()
        assert original_key_bytes == new_key_bytes

    def test_reuse_key_cert_still_valid(self, ca_dir):
        cert_path, _ = self._issue(ca_dir)
        renew_cert(ca_dir, cert_path, reuse_key=True)
        with open(cert_path, "rb") as fh:
            new_cert = x509.load_pem_x509_certificate(fh.read())
        assert new_cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "host.example.com"

    def test_reuse_key_missing_key_file_raises(self, ca_dir, tmp_path):
        cert_path, key_path = self._issue(ca_dir)
        os.unlink(key_path)
        with pytest.raises(PKIError, match="no key file found"):
            renew_cert(ca_dir, cert_path, reuse_key=True)

    # -- profile and SAN preservation ----------------------------------------

    def test_preserves_profile_grid_host(self, ca_dir):
        cert_path, _ = self._issue(ca_dir, cn="xrd.example.com", profile="grid-host")
        renew_cert(ca_dir, cert_path)
        cert = _load_cert(cert_path)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        from cryptography.x509.oid import ExtendedKeyUsageOID as _EKU
        assert _EKU.SERVER_AUTH in list(eku)
        assert _EKU.CLIENT_AUTH in list(eku)

    def test_preserves_sans(self, ca_dir):
        cert_path, _ = self._issue(
            ca_dir, cn="host.example.com",
            sans=["DNS:alt.example.com", "IP:192.168.1.1"]
        )
        renew_cert(ca_dir, cert_path)
        cert = _load_cert(cert_path)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_values = {gn.value for gn in san_ext if isinstance(gn, x509.DNSName)}
        assert "host.example.com" in dns_values
        assert "alt.example.com" in dns_values

    def test_preserves_cdp_url(self, ca_dir):
        cert_path, _ = self._issue(
            ca_dir, cn="host.example.com",
            cdp_url="http://crl.example.com/ca.crl"
        )
        renew_cert(ca_dir, cert_path)
        cert = _load_cert(cert_path)
        cdp = cert.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
        uris = [
            gn.value
            for dp in cdp
            for gn in (dp.full_name or [])
            if isinstance(gn, x509.UniformResourceIdentifier)
        ]
        assert "http://crl.example.com/ca.crl" in uris

    # -- error cases ---------------------------------------------------------

    def test_missing_cert_raises(self, ca_dir, tmp_path):
        with pytest.raises(PKIError, match="not found"):
            renew_cert(ca_dir, str(tmp_path / "nonexistent.pem"))

    def test_missing_ca_raises(self, tmp_path):
        with pytest.raises(PKIError, match="No CA found"):
            renew_cert(str(tmp_path / "noca"), "/dev/null")

    # -- fullchain for intermediate CA ---------------------------------------

    def test_renew_via_intermediate_writes_fullchain(self, tmp_path):
        root = str(tmp_path / "root")
        sub  = str(tmp_path / "sub")
        init_ca(root, cn="Root CA", days=30)
        init_intermediate_ca(sub, root, cn="Sub CA", days=30)
        out = str(tmp_path / "issued")
        os.makedirs(out)
        cert_path, _ = issue_cert(sub, cn="host.example.com", out_dir=out)
        fullchain = cert_path.replace("-cert.pem", "-fullchain.pem")
        assert os.path.isfile(fullchain)

        new_cert_path, _ = renew_cert(sub, cert_path)
        assert os.path.isfile(new_cert_path.replace("-cert.pem", "-fullchain.pem"))


# ---------------------------------------------------------------------------
# cert renew CLI
# ---------------------------------------------------------------------------

class TestCertRenewCLI:
    """CLI-level tests for ``crabctl cert renew``."""

    @pytest.fixture
    def runner(self):
        from click.testing import CliRunner
        return CliRunner()

    @pytest.fixture
    def ca_and_cert(self, tmp_path):
        ca = str(tmp_path / "ca")
        init_ca(ca, cn="Test CA", days=30)
        cert_path, key_path = issue_cert(ca, cn="host.example.com")
        return ca, cert_path, key_path

    def test_renew_succeeds(self, runner, ca_and_cert):
        from crab.cli import main
        ca, cert_path, _ = ca_and_cert
        result = runner.invoke(
            main,
            ["-q", "cert", "renew", "--ca", ca, "--force", cert_path],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "renewed" in result.output.lower()

    def test_renew_shows_cert_path(self, runner, ca_and_cert):
        from crab.cli import main
        ca, cert_path, _ = ca_and_cert
        result = runner.invoke(
            main,
            ["-q", "cert", "renew", "--ca", ca, "--force", cert_path],
            catch_exceptions=False,
        )
        assert cert_path in result.output

    def test_renew_with_days_override(self, runner, ca_and_cert):
        from crab.cli import main
        ca, cert_path, _ = ca_and_cert
        result = runner.invoke(
            main,
            ["-q", "cert", "renew", "--ca", ca, "--force", "--days", "90", cert_path],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        delta = (cert.not_valid_after - cert.not_valid_before).days
        assert delta == 90

    def test_reuse_key_flag(self, runner, ca_and_cert):
        from crab.cli import main
        ca, cert_path, key_path = ca_and_cert
        with open(key_path, "rb") as fh:
            old_key_bytes = fh.read()
        result = runner.invoke(
            main,
            ["-q", "cert", "renew", "--ca", ca, "--force", "--reuse-key", cert_path],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        with open(key_path, "rb") as fh:
            new_key_bytes = fh.read()
        assert old_key_bytes == new_key_bytes

    def test_prompts_when_cert_still_valid(self, runner, ca_and_cert):
        from crab.cli import main
        ca, cert_path, _ = ca_and_cert
        # Answer "no" to the confirmation prompt — should exit 0 without renewing
        result = runner.invoke(
            main,
            ["-q", "cert", "renew", "--ca", ca, cert_path],
            input="n\n",
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # DB should still have only 1 active cert (original, not revoked)
        records = CADirectory(ca).serial_db.records()
        assert sum(1 for r in records if not r.get("revoked")) == 1

    def test_error_on_missing_cert(self, runner, tmp_path):
        from crab.cli import main
        ca = str(tmp_path / "ca")
        init_ca(ca, cn="Test CA", days=30)
        result = runner.invoke(
            main,
            ["-q", "cert", "renew", "--ca", ca, "--force",
             str(tmp_path / "nosuchcert.pem")],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_cert(path):
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


def _load_crl(path):
    with open(path, "rb") as fh:
        return x509.load_pem_x509_crl(fh.read())


def _get_eku(cert_path):
    cert = _load_cert(cert_path)
    ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    return list(ext.value)
