"""
setup.py — build hook for crab.

Beyond the metadata in setup.cfg, this file provides one customisation:
the build_py command embeds the git commit SHA into crab/_commit.py so
that `crabctl --version` can report it.

Resolution order (see also crab/__init__.py for the runtime equivalent):
  1. git archive substitution — $Format:%h$ was already replaced when the
     source tarball was created (export-subst in .gitattributes); used by
     RPM/deb and release sdist builds.
  2. git subprocess — live git clone; used by `pip install .` and wheel builds.
  3. "unknown" fallback — no git available and no substitution occurred.

Editable installs (pip install -e .) read crab/_commit.py directly from the
source tree, where the placeholder is never overwritten.  crab/__init__.py
handles that case by falling back to a git subprocess at import time.
"""

import os
import subprocess

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


def _resolve_commit():
    """Return a short SHA string, or 'unknown'."""
    commit_src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "crab", "_commit.py")
    # Was the placeholder substituted by git archive?
    try:
        ns = {}
        with open(commit_src) as fh:
            exec(compile(fh.read(), commit_src, "exec"), ns)  # noqa: S102
        val = ns.get("__commit__", "")
        if val and not val.startswith("$Format:"):
            return val
    except Exception:
        pass

    # Live git repository.
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        ).decode().strip()
    except Exception:
        pass

    return "unknown"


def _write_commit(path, commit):
    with open(path, "w") as fh:
        fh.write("# Auto-generated at install time — do not edit.\n")
        fh.write("__commit__ = {!r}\n".format(commit))


class build_py(_build_py):
    def run(self):
        super().run()
        commit = _resolve_commit()
        # Write into the build directory only (regular installs and wheels).
        # The source tree is never modified; editable installs fall back to
        # a git subprocess in crab/__init__.py.
        built = os.path.join(self.build_lib, "crab", "_commit.py")
        if os.path.isdir(os.path.dirname(built)):
            _write_commit(built, commit)


setup(cmdclass={"build_py": build_py})
