# crabctl — containerised test and development environment
#
# Provides a Rocky Linux 8 base (mirrors EL8 / RHEL8) with Python 3.6.8
# and OpenSSL 1.1 for validating that the tool works in the target environment.
#
# Build:
#   docker build -t crab-test .
#
# Run tests:
#   docker run --rm crab-test pytest -v
#
# Interactive shell:
#   docker run --rm -it crab-test bash

FROM rockylinux:8

# Install Python 3 and OpenSSL tooling
RUN dnf -y install \
        python3 \
        python3-pip \
        python3-devel \
        openssl \
        ca-certificates \
        gcc \
        make \
        tar \
        gzip \
    && dnf clean all

# Upgrade pip (Python 3.6 ships with an older pip on EL8)
RUN python3 -m pip install --upgrade "pip<21.4"

WORKDIR /app

# Install package dependencies first (layer-cached)
COPY setup.cfg setup.py pyproject.toml ./
RUN python3 -m pip install -e ".[dev]"

# Copy the rest of the source
COPY certbundle/ certbundle/
COPY tests/ tests/
COPY examples/ examples/

# Verify the install
RUN crabctl --version

# Default command: run the test suite
CMD ["pytest", "-v", "--tb=short"]
