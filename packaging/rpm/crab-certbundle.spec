# crab-certbundle.spec
#
# Bundles all Python runtime dependencies into /usr/share/crab-certbundle/vendor
# so the package is self-contained and independent of system Python packages.
#
# Because the vendored cryptography/cffi wheels contain compiled C extensions,
# this RPM is architecture-specific (typically x86_64).
#
# Build:
#   rpmbuild -ba packaging/rpm/crab-certbundle.spec \
#     --define "_topdir $(pwd)/rpmbuild" \
#     --define "_sourcedir $(pwd)/rpmbuild/SOURCES"

Name:           crab-certbundle
Version:        0.4.2
Release:        1%{?dist}
Summary:        OpenSSL-style CA certificate directory builder for research infrastructure

License:        Apache-2.0
URL:            https://github.com/snafus/crab-certbundle
Source0:        %{name}-%{version}.tar.gz

# Vendored cryptography/cffi contain compiled C extensions → arch-specific
# BuildArch: noarch  (not set deliberately)

BuildRequires:  python3
BuildRequires:  python3-pip
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  libffi-devel
BuildRequires:  systemd-rpm-macros

# Runtime: Python 3 interpreter + openssl binary (for rehash/CRL ops)
Requires:       python3
Requires:       openssl

# Exclude the vendor tree from RPM's automatic dependency/provides scanning.
# Vendored .so files are implementation details, not system libraries.
# Using targeted globs (rather than AutoReqProv: no) preserves normal scanning
# of the wrapper script — so the python3 shebang still generates a Requires.
%global __requires_exclude_from ^%{_datadir}/%{name}/vendor/.*$
%global __provides_exclude_from ^%{_datadir}/%{name}/vendor/.*$

# Suppress debuginfo sub-package for the vendored binary extensions
%global debug_package %{nil}

# Fallback for distros where systemd-rpm-macros may not define %{_unitdir}
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

# On EL8 (Python 3.6), pin cryptography to <3.4: that is the last release
# before Rust became a build requirement.  PyYAML <6.0 is also required for
# Python 3.6 compatibility.  On EL9+ use the latest versions.
%if 0%{?rhel} == 8
%global _crypto_req cryptography>=2.8,<3.4
%global _pyyaml_req PyYAML>=5.1,<6.0
%else
%global _crypto_req cryptography>=2.8
%global _pyyaml_req PyYAML>=5.1
%endif

%description
CRAB (Certificate Root Anchor Builder) — the crabctl command.

Generates and updates OpenSSL-style CApath directories (hashed certificate
trust stores) for research infrastructure including SRCNet, WLCG, EGI,
XRootD, and dCache deployments.

Combines IGTF trust anchors and public CA roots into one or more named
output profiles, each an OpenSSL-compatible CApath directory suitable for
/etc/grid-security/certificates and any OpenSSL consumer.

Key features:
  - Atomic directory replacement via renameat2(EXCHANGE) on Linux >= 3.15,
    falling back to a two-rename approach on older kernels
  - Policy engine: CA flag, expiry, EKU, IGTF policy-tag filtering
  - CRL fetch, storage, and freshness validation
  - Diff mode and dry-run mode; JSON output for all list/diff/validate
  - Python 3.6.8+ compatible (EL8, EL9, Ubuntu 22.04/24.04)

%prep
%autosetup -n %{name}-%{version}

%build
# Pure-Python package; runtime deps are vendored during %%install.
# Nothing to compile in the package itself.

%install
# ── Vendor all runtime dependencies ──────────────────────────────────────
# pip --target installs packages (including binary wheels) into a single flat
# directory.  The entry point script adds this directory to sys.path at
# runtime, keeping the vendor tree invisible to the system Python environment.
VENDOR=%{buildroot}%{_datadir}/%{name}/vendor
install -d "${VENDOR}"

# Upgrade pip so we get a version that supports --only-binary and handles
# the cryptography wheel correctly on both EL8 and EL9.
%if 0%{?rhel} == 8
python3 -m pip install --upgrade "pip<21.4"
%else
python3 -m pip install --upgrade pip
%endif

# Step 1: install runtime deps.
# --prefer-binary: use a pre-built wheel when available, fall back to source
# only if no wheel exists for this platform.  This avoids the Rust toolchain
# requirement for cryptography>=3.4 on EL8 (pinned to <3.4 above) while still
# allowing cffi to compile from source on uncommon architectures if needed.
python3 -m pip install \
    --no-cache-dir \
    --prefer-binary \
    --target "${VENDOR}" \
    "%{_crypto_req}" \
    "%{_pyyaml_req}" \
    "click>=7.0" \
    "requests>=2.20"

# Step 2: install crab package itself (deps already above)
python3 -m pip install \
    --no-cache-dir \
    --no-deps \
    --target "${VENDOR}" \
    .

# Remove pip-generated entry point scripts from the vendor dir;
# we create our own wrapper below.
rm -rf "${VENDOR}/bin"

# ── crabctl entry point ───────────────────────────────────────────────────
install -d %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/crabctl << 'WRAPPER'
#!/usr/bin/python3
import sys
sys.path.insert(0, '/usr/share/crab-certbundle/vendor')
from crab.cli import main
main()
WRAPPER
chmod 0755 %{buildroot}%{_bindir}/crabctl

# ── systemd units ─────────────────────────────────────────────────────────
install -d %{buildroot}%{_unitdir}
install -m 0644 systemd/crab.service %{buildroot}%{_unitdir}/crabctl.service
install -m 0644 systemd/crab.timer   %{buildroot}%{_unitdir}/crabctl.timer

# ── Config skeleton ───────────────────────────────────────────────────────
# The directory is owned by the package; the config file is created by the
# administrator.  %ghost marks config.yaml as an expected but absent file so
# rpm -V doesn't warn about it being missing.
install -d %{buildroot}%{_sysconfdir}/crab
touch %{buildroot}%{_sysconfdir}/crab/config.yaml

# ── Example configs ───────────────────────────────────────────────────────
install -d %{buildroot}%{_datadir}/%{name}/examples
install -m 0644 examples/*.yaml %{buildroot}%{_datadir}/%{name}/examples/

%files
%license LICENSE
%doc README.md
%{_bindir}/crabctl
%{_datadir}/%{name}/
%dir %{_sysconfdir}/crab
%ghost %{_sysconfdir}/crab/config.yaml
%{_unitdir}/crabctl.service
%{_unitdir}/crabctl.timer

%post
%systemd_post crabctl.timer

%preun
%systemd_preun crabctl.timer

%postun
%systemd_postun_with_restart crabctl.timer

%changelog
* Sat Apr 18 2026 snafus <snafus@users.noreply.github.com> - 0.4.2-1
- crabctl pki build: declarative PKI hierarchy builder from pki.yaml
- crabctl pki init-config: generate annotated pki.yaml template
- crabctl init-config: generate crab.yaml template (--minimal or full)

* Sat Apr 18 2026 snafus <snafus@users.noreply.github.com> - 0.4.1-1
- Bug fixes: validate NotADirectoryError on bundle/pkcs12 output paths (#4)
- Bug fixes: trailing slash in output_path corrupts staging/backup paths (#5)

* Thu Apr 17 2026 snafus <snafus@users.noreply.github.com> - 0.4.0-1
- cert renew: revoke-and-reissue from existing cert parameters
- cert sign --csr: CSR-based issuance, private key never enters CRAB
- Fix: renew_cert issue-before-revoke ordering (was data-loss risk)
- Fix: cert_renew CLI datetime compat with cryptography >= 42

* Thu Apr 16 2026 snafus <snafus@users.noreply.github.com> - 0.3.0-1
- Operational observability: crabctl status, --log-format json, --strict-warnings exit code 3
- Parallel CRL fetching via ThreadPoolExecutor (max_workers configurable)
- 749 tests passing across EL8/EL9 and Ubuntu 22.04/24.04

* Wed Apr 15 2026 snafus <snafus@users.noreply.github.com> - 0.2.0-1
- CRAB-PKI: crabctl ca/cert commands (self-signed CA, host certs, revocation)
- JSON Schema for crab.yaml; ternary PolicyOutcome; CRL validation in pipeline
- Bug fixes: file_mode parsing, diff exit code, silent parse errors

* Mon Apr 13 2026 snafus <snafus@users.noreply.github.com> - 0.1.0-1
- Initial RPM release
