# Populated at install time by the setup.py build_py hook.
#
# When installing from a git clone (pip install . or pip install -e .):
#   setup.py resolves the HEAD short SHA via git subprocess.
#
# When installing from a git archive tarball (RPM/deb/release sdist):
#   git export-subst (see .gitattributes) replaces $Format:%h$ with the
#   archived commit's short SHA before the tarball is created.
#
# Falls back to "unknown" if git is unavailable and no substitution occurred.
__commit__ = "$Format:%h$"
