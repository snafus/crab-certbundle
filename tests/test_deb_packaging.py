"""
Packaging sanity tests for the Debian .deb artefacts.

These tests do NOT build a real .deb (that requires dpkg-dev/debhelper and is
reserved for CI containers).  Instead they verify that every file in
packaging/deb/debian/ is internally consistent and meets the structural
requirements that dpkg-buildpackage imposes.

A separate CI job (see packaging/deb/build-deb.sh) does the actual build
inside an Ubuntu 22.04 / 24.04 container.
"""

import configparser
import os
import re
import stat

import pytest

# Project root — two levels above this test file.
PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DEB_DIR = os.path.join(PROJECT_ROOT, "packaging", "deb")
DEBIAN_DIR = os.path.join(DEB_DIR, "debian")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(name):
    with open(os.path.join(DEBIAN_DIR, name)) as f:
        return f.read()


def _setup_cfg_version():
    c = configparser.ConfigParser()
    c.read(os.path.join(PROJECT_ROOT, "setup.cfg"))
    return c["metadata"]["version"]


# ---------------------------------------------------------------------------
# Required files exist
# ---------------------------------------------------------------------------

class TestRequiredFilesExist:
    REQUIRED = [
        "control",
        "rules",
        "changelog",
        "crabctl.wrapper",
        "postinst",
        "prerm",
        "postrm",
    ]

    @pytest.mark.parametrize("name", REQUIRED)
    def test_file_exists(self, name):
        path = os.path.join(DEBIAN_DIR, name)
        assert os.path.isfile(path), "Missing packaging/deb/debian/{}".format(name)

    def test_build_script_exists(self):
        assert os.path.isfile(os.path.join(DEB_DIR, "build-deb.sh"))

    def test_rules_is_executable(self):
        rules = os.path.join(DEBIAN_DIR, "rules")
        mode = stat.S_IMODE(os.stat(rules).st_mode)
        assert mode & 0o111, "debian/rules must be executable"

    def test_build_script_is_executable(self):
        script = os.path.join(DEB_DIR, "build-deb.sh")
        mode = stat.S_IMODE(os.stat(script).st_mode)
        assert mode & 0o111, "build-deb.sh must be executable"


# ---------------------------------------------------------------------------
# debian/control
# ---------------------------------------------------------------------------

class TestControl:
    def test_required_source_fields(self):
        control = _read("control")
        for field in ("Source:", "Section:", "Priority:", "Maintainer:",
                      "Build-Depends:", "Standards-Version:"):
            assert field in control, "control missing {}".format(field)

    def test_required_package_fields(self):
        control = _read("control")
        for field in ("Package:", "Architecture:", "Depends:", "Description:"):
            assert field in control, "control missing {}".format(field)

    def test_source_name(self):
        assert "Source: crab-certbundle" in _read("control")

    def test_package_name(self):
        assert "Package: crab-certbundle" in _read("control")

    def test_build_depends_includes_python3_pip(self):
        assert "python3-pip" in _read("control")

    def test_build_depends_includes_debhelper(self):
        assert "debhelper-compat" in _read("control")

    def test_depends_includes_python3(self):
        assert "python3" in _read("control")

    def test_depends_includes_openssl(self):
        assert "openssl" in _read("control")

    def test_architecture_is_any(self):
        # arch-specific due to compiled C extensions in vendored cryptography
        assert "Architecture: any" in _read("control")

    def test_no_trailing_whitespace_on_required_lines(self):
        for line in _read("control").splitlines():
            assert not line.endswith(" "), \
                "Trailing whitespace in control: {!r}".format(line)


# ---------------------------------------------------------------------------
# debian/changelog
# ---------------------------------------------------------------------------

class TestChangelog:
    # Debian changelog format: "package (version) suite; urgency=level"
    ENTRY_RE = re.compile(
        r'^crab-certbundle \((\S+)\) \S+; urgency=\w+$'
    )

    def test_first_entry_matches_setup_cfg_version(self):
        first_line = _read("changelog").splitlines()[0]
        m = self.ENTRY_RE.match(first_line)
        assert m, "First changelog line does not match Debian format: {!r}".format(first_line)
        # changelog version is "X.Y.Z-N" (epoch-version-revision)
        changelog_ver = m.group(1).rsplit("-", 1)[0]
        assert changelog_ver == _setup_cfg_version(), \
            "changelog version {} != setup.cfg version {}".format(
                changelog_ver, _setup_cfg_version())

    def test_maintainer_line_present(self):
        # Must contain a " -- Name <email>  Day, DD Mon YYYY HH:MM:SS +ZZZZ" line
        assert re.search(r'^ -- .+ <.+>  .+$', _read("changelog"), re.MULTILINE), \
            "No valid maintainer/date line in changelog"


# ---------------------------------------------------------------------------
# debian/rules
# ---------------------------------------------------------------------------

class TestRules:
    def test_shebang(self):
        first_line = _read("rules").splitlines()[0]
        assert first_line.startswith("#!/usr/bin/make -f"), \
            "rules must start with #!/usr/bin/make -f"

    def test_vendor_dir_defined(self):
        assert "VENDOR_DIR" in _read("rules")

    def test_pip_install_runtime_deps(self):
        rules = _read("rules")
        for pkg in ("cryptography", "PyYAML", "click", "requests"):
            assert pkg in rules, "rules does not vendor {}".format(pkg)

    def test_pip_install_crab_itself(self):
        assert "--no-deps" in _read("rules"), \
            "rules should install crab with --no-deps after vendoring deps"

    def test_excludes_vendor_from_shlibdeps(self):
        assert "-Xvendor" in _read("rules"), \
            "rules should exclude vendor dir from dh_shlibdeps"

    def test_override_installsystemd(self):
        # We manage systemd in postinst/prerm/postrm, so override must be present
        assert "override_dh_installsystemd" in _read("rules"), \
            "rules must override dh_installsystemd"

    def test_installs_wrapper(self):
        assert "crabctl.wrapper" in _read("rules")

    def test_installs_systemd_units(self):
        rules = _read("rules")
        assert "crab.service" in rules
        assert "crab.timer" in rules


# ---------------------------------------------------------------------------
# debian/crabctl.wrapper
# ---------------------------------------------------------------------------

class TestWrapper:
    def test_shebang_python3(self):
        first_line = _read("crabctl.wrapper").splitlines()[0]
        assert first_line.startswith("#!/usr/bin/python3"), \
            "wrapper shebang should be #!/usr/bin/python3"

    def test_vendor_path_inserted(self):
        assert "/usr/share/crab-certbundle/vendor" in _read("crabctl.wrapper")

    def test_imports_crab_cli(self):
        wrapper = _read("crabctl.wrapper")
        assert "from crab.cli import main" in wrapper
        assert "main()" in wrapper


# ---------------------------------------------------------------------------
# debian/postinst, prerm, postrm
# ---------------------------------------------------------------------------

class TestMaintenanceScripts:
    @pytest.mark.parametrize("script", ["postinst", "prerm", "postrm"])
    def test_sh_shebang(self, script):
        first_line = _read(script).splitlines()[0]
        assert first_line == "#!/bin/sh", \
            "{} must start with #!/bin/sh, got {!r}".format(script, first_line)

    @pytest.mark.parametrize("script", ["postinst", "prerm", "postrm"])
    def test_debhelper_token(self, script):
        assert "#DEBHELPER#" in _read(script), \
            "{} must contain #DEBHELPER# token".format(script)

    def test_postinst_enables_timer(self):
        assert "crabctl.timer" in _read("postinst")
        assert "enable" in _read("postinst")

    def test_prerm_stops_and_disables_timer(self):
        prerm = _read("prerm")
        assert "crabctl.timer" in prerm
        assert "stop" in prerm
        assert "disable" in prerm

    def test_postrm_reloads_daemon(self):
        assert "daemon-reload" in _read("postrm")


# ---------------------------------------------------------------------------
# build-deb.sh
# ---------------------------------------------------------------------------

class TestBuildScript:
    def test_reads_version_from_setup_cfg(self):
        assert "setup.cfg" in open(os.path.join(DEB_DIR, "build-deb.sh")).read()

    def test_invokes_dpkg_buildpackage(self):
        assert "dpkg-buildpackage" in open(os.path.join(DEB_DIR, "build-deb.sh")).read()

    def test_git_archive_fallback(self):
        script = open(os.path.join(DEB_DIR, "build-deb.sh")).read()
        assert "git archive" in script
        assert "rsync" in script  # fallback when not in a git repo
