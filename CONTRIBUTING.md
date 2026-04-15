# Contributing to CRAB

Thanks for your interest in contributing. This document covers everything
you need to get a working development environment, run the test suite, and
submit changes.

---

## Table of contents

1. [Prerequisites](#prerequisites)
2. [Development setup](#development-setup)
3. [Running tests](#running-tests)
4. [Code style](#code-style)
5. [Branch and commit conventions](#branch-and-commit-conventions)
6. [Submitting a pull request](#submitting-a-pull-request)
7. [Building packages](#building-packages)
8. [Versioning policy](#versioning-policy)

---

## Prerequisites

| Tool | Minimum version | Notes |
|---|---|---|
| Python | 3.6.8 | 3.10+ recommended for development |
| pip | 19.0 | |
| git | any | Required to run the test suite |
| openssl | any | Used by integration tests and `openssl rehash` |

Optional but useful:
- `pyOpenSSL >= 19.0` — more accurate subject-hash computation
- `tox` — run tests across multiple Python versions
- `rpmbuild`, `dpkg-buildpackage` — build distribution packages

---

## Development setup

```bash
# Clone the repo
git clone https://github.com/snafus/crab-certbundle.git
cd crab-certbundle

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with all development dependencies
pip install -e ".[dev,openssl]"
```

After the editable install, `crabctl --version` will show the current HEAD
commit (e.g. `crabctl, version 0.2.0 (abc1234)`).  The SHA is resolved at
import time via a `git rev-parse` subprocess, so it always reflects the
current branch tip without any extra steps.

---

## Running tests

```bash
# Run the full test suite
pytest -v

# Unit tests only (faster; no subprocess overhead)
pytest tests/ --ignore=tests/integration -v

# Integration tests only
pytest tests/integration/ -v

# With coverage
pytest --cov=crab --cov-report=term-missing

# Single test file
pytest tests/test_pki.py -v

# Single test class or function
pytest tests/test_pki.py::TestIssueCert::test_server_cert -v
```

### Test matrix with tox

```bash
# Run all configured Python versions (skip missing interpreters)
tox

# Single environment
tox -e py312
```

The tox matrix covers Python 3.6–3.13.  CI runs Rocky 8 (3.6.8), Rocky 9
(3.9, 3.12), Ubuntu 22.04 (3.10), and Ubuntu 24.04 (3.12) on every push to
`feature/**`, `fix/**`, `release/**`, and `main`.

### What the tests cover

| Module | Test file | Count |
|---|---|---|
| Certificate parsing | `tests/test_cert.py` | — |
| CLI commands | `tests/test_cli.py` | — |
| Configuration loading | `tests/test_config.py` | — |
| CRL management | `tests/test_crl.py` | — |
| HTTP source loader | `tests/test_http.py` | — |
| IGTF source loader | `tests/test_igtf.py` | — |
| Output formats | `tests/test_output.py` | — |
| PKI (ca/cert commands) | `tests/test_pki.py` | 78 |
| Policy engine | `tests/test_policy.py` | — |
| Rehash | `tests/test_rehash.py` | — |
| Reporting | `tests/test_reporting.py` | — |
| JSON Schema | `tests/test_schema.py` | 16 |
| Source loaders | `tests/test_sources.py` | — |
| Validation | `tests/test_validation.py` | — |
| Deb packaging structure | `tests/test_deb_packaging.py` | 45 |
| Integration (build/validate pipeline) | `tests/integration/test_pipeline.py` | 21 |

---

## Code style

- **Formatting**: no auto-formatter is enforced; follow the style of the
  surrounding code.  Lines up to 100 characters.
- **Python compatibility**: all code must run on Python 3.6.8.  This means:
  - No `dataclasses`, no walrus operator (`:=`), no `tomllib`
  - No `dict[str, str]` generic syntax — use `Dict[str, str]` from `typing`
  - No f-strings are currently used in the codebase; use `.format()` for
    consistency with the existing style
  - `typing.List`, `typing.Optional`, `typing.Dict` etc. (not the built-in
    generic forms)
- **Imports**: standard library first, then third-party, then local; each
  group separated by a blank line.
- **No speculative features**: don't add configuration options, error
  handling, or abstractions for hypothetical future requirements.

### Checking for common issues

```bash
# Flake8 (installed as part of [dev] extras)
flake8 crab/

# Quick Python 3.6 syntax check (requires a 3.6 interpreter or tox)
tox -e py36 -- -x
```

---

## Branch and commit conventions

| Branch prefix | Purpose |
|---|---|
| `feature/` | New functionality |
| `fix/` | Bug fixes |
| `release/` | Release preparation |

CI runs automatically on push to any of these prefixes and on PRs targeting
`main`.

**Commit messages** — follow the style of recent commits in `git log`:

```
area: short summary in imperative mood (≤72 chars)

Optional body explaining *why*, not *what*.  The diff shows what changed;
the message explains the motivation and any non-obvious consequences.
```

Examples of good prefixes: `feat:`, `fix:`, `docs:`, `ci:`, `packaging:`,
`tests:`, `refactor:`.

---

## Submitting a pull request

1. Fork the repository and create a branch from `main`.
2. Make your changes; add or update tests so the relevant coverage does not
   decrease.
3. Run the full test suite locally (`pytest -v`).
4. Push to your fork and open a PR targeting `main`.
5. CI must be green before merge.  Address any failures before requesting
   review.
6. PRs are squash-merged; the squash commit message is taken from the PR
   title and description, so keep them informative.

### What makes a good PR

- **Focused**: one logical change per PR.  A 50-line fix is easier to review
  than a 500-line "misc improvements" PR.
- **Tested**: new code should have new tests.  Bug fixes should include a
  test that would have caught the bug.
- **Documented**: update `README.md` if you add or change user-visible
  behaviour.  Update `ROADMAP.md` if you complete a planned milestone item.

---

## Building packages

### RPM (EL8 / EL9)

```bash
mkdir -p rpmbuild/SOURCES
VERSION=$(python3 -c "import configparser; c=configparser.ConfigParser(); \
    c.read('setup.cfg'); print(c['metadata']['version'])")
git archive --format=tar.gz --prefix=crab-certbundle-${VERSION}/ HEAD \
    > rpmbuild/SOURCES/crab-certbundle-${VERSION}.tar.gz
rpmbuild -ba packaging/rpm/crab-certbundle.spec \
    --define "_topdir $(pwd)/rpmbuild"
```

### Debian/Ubuntu (22.04 LTS, 24.04 LTS)

```bash
# Requires: dpkg-dev debhelper python3-pip gcc libssl-dev libffi-dev
bash packaging/deb/build-deb.sh
# Output: debbuild/crab-certbundle_<VERSION>_amd64.deb
```

---

## Versioning policy

CRAB follows [Semantic Versioning](https://semver.org/).  The authoritative
version lives in `setup.cfg` (`[metadata] version`).  It must be kept in
sync with:

- `crab/__init__.py` — `__version__`
- `packaging/rpm/crab-certbundle.spec` — `Version:`
- `packaging/deb/debian/changelog` — first entry version

The `crabctl --version` output is `<version> (<short-sha>)` when a commit
SHA is available, or plain `<version>` when installed from a plain archive
without git.

### Release checklist

1. Update `setup.cfg`, `crab/__init__.py`, `packaging/rpm/crab-certbundle.spec`,
   and `packaging/deb/debian/changelog` to the new version.
2. Add a `CHANGELOG.md` entry.
3. Open and merge a PR to `main`.
4. Push a version tag: `git tag v<version> && git push origin v<version>`.
5. The `release` CI workflow builds RPM EL8/EL9, `.deb`, and the container
   image, then creates a GitHub Release with all artefacts attached.
