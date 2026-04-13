"""
Shared pytest fixtures.

Self-signed test certificates are generated on the fly using the cryptography
library so the tests have no dependency on external files or network access.
"""

import os
import datetime
import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ---------------------------------------------------------------------------
# Certificate generation helpers
# ---------------------------------------------------------------------------

def _make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


def _make_ca_cert(
    subject_cn="Test CA",
    subject_o="Test Org",
    subject_c="GB",
    issuer_key=None,
    issuer_name=None,
    not_before=None,
    not_after=None,
    path_length=None,
    key=None,
    eku_oids=None,
    key_size=2048,
):
    """Generate a self-signed (or cross-signed) CA certificate and its private key."""
    key = key or rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    if not_before is None:
        not_before = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    if not_after is None:
        not_after = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)

    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_c),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_o),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    issuer_name = issuer_name or subject_name
    signing_key = issuer_key or key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if eku_oids:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku_oids), critical=False
        )
    cert = builder.sign(signing_key, hashes.SHA256(), default_backend())
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return pem, key, cert


def _make_leaf_cert(issuer_pem, issuer_key, subject_cn="Test Leaf"):
    """Generate a leaf (non-CA) certificate signed by the issuer."""
    key = _make_key()
    issuer_cert = x509.load_pem_x509_certificate(issuer_pem, default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )
    cert = builder.sign(issuer_key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ca_pem_and_key():
    """A simple self-signed CA PEM (bytes) and its private key."""
    pem, key, _ = _make_ca_cert()
    return pem, key


@pytest.fixture(scope="session")
def ca_pem(ca_pem_and_key):
    return ca_pem_and_key[0]


@pytest.fixture(scope="session")
def ca_key(ca_pem_and_key):
    return ca_pem_and_key[1]


@pytest.fixture(scope="session")
def expired_ca_pem():
    pem, _, _ = _make_ca_cert(
        subject_cn="Expired CA",
        not_before=datetime.datetime(2010, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2015, 1, 1, tzinfo=datetime.timezone.utc),
    )
    return pem


@pytest.fixture(scope="session")
def leaf_pem(ca_pem_and_key):
    ca_pem, ca_key = ca_pem_and_key
    return _make_leaf_cert(ca_pem, ca_key)


@pytest.fixture(scope="session")
def second_ca_pem():
    pem, _, _ = _make_ca_cert(
        subject_cn="Second CA",
        subject_o="Other Org",
        subject_c="US",
    )
    return pem


@pytest.fixture()
def pem_dir(tmp_path, ca_pem, second_ca_pem):
    """A temporary directory with two CA PEM files."""
    (tmp_path / "root-ca.pem").write_bytes(ca_pem)
    (tmp_path / "second-ca.pem").write_bytes(second_ca_pem)
    return str(tmp_path)


@pytest.fixture()
def bundle_pem(ca_pem, second_ca_pem):
    """A PEM bundle (two certs concatenated)."""
    return ca_pem + b"\n" + second_ca_pem


@pytest.fixture()
def igtf_dir(tmp_path, ca_pem):
    """
    A fake IGTF directory with a .pem and .info file.
    """
    (tmp_path / "TestCA.pem").write_bytes(ca_pem)
    (tmp_path / "TestCA.info").write_text(
        "alias           = TestCA\n"
        "subjectdn       = /C=GB/O=Test Org/CN=Test CA\n"
        "issuerdn        = /C=GB/O=Test Org/CN=Test CA\n"
        "policy          = classic\n"
        "status          = operational\n"
        "crlurl          = http://example.com/TestCA.crl\n"
    )
    (tmp_path / "TestCA.signing_policy").write_text(
        'access_id_CA X509 "/C=GB/O=Test Org/CN=Test CA"\n'
        'pos_rights globus CA:sign\n'
        'cond_subjects globus \'"/C=GB/O=Test Org/*"\'\n'
    )
    return str(tmp_path)


@pytest.fixture()
def minimal_config_file(tmp_path, pem_dir):
    """Write a minimal certbundle.yaml config to tmp_path."""
    output_path = str(tmp_path / "output")
    config_path = str(tmp_path / "certbundle.yaml")
    with open(config_path, "w") as fh:
        fh.write(
            "version: 1\n"
            "sources:\n"
            "  local-test:\n"
            "    type: local\n"
            "    path: {pem_dir}\n"
            "profiles:\n"
            "  default:\n"
            "    sources: [local-test]\n"
            "    output_path: {output_path}\n"
            "    atomic: false\n"
            "    rehash: builtin\n".format(
                pem_dir=pem_dir,
                output_path=output_path,
            )
        )
    return config_path
