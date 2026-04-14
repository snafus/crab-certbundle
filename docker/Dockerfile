# =============================================================================
# crab-certbundle — production container image
#
# Multi-stage build: dependencies compiled in a builder layer; only the venv,
# the openssl binary, and ca-certificates land in the final image.
#
# Build:
#   docker build -f docker/Dockerfile -t crab-certbundle:latest .
#
# One-shot (run once then exit — use with CronJob / systemd timer):
#   docker run --rm \
#     -v /etc/certbundle/config.yaml:/etc/certbundle/config.yaml:ro \
#     -v certbundle-output:/var/lib/certbundle \
#     -v certbundle-cache:/var/cache/certbundle \
#     crab-certbundle:latest
#
# Loop (daemon — refresh every hour):
#   docker run -d \
#     -e CRABCTL_COMMANDS=refresh \
#     -e CRABCTL_LOOP_INTERVAL=3600 \
#     -v /etc/certbundle/config.yaml:/etc/certbundle/config.yaml:ro \
#     -v certbundle-output:/var/lib/certbundle \
#     -v certbundle-cache:/var/cache/certbundle \
#     crab-certbundle:latest
# =============================================================================


# -----------------------------------------------------------------------------
# Stage 1: builder
#
# Installs the package and all runtime dependencies into an isolated venv.
# gcc and libssl-dev are only needed here to compile any C extensions;
# they do not appear in the final image.
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip

# Copy packaging metadata first so the dependency install layer is cached
# independently of source edits.
COPY setup.cfg setup.py pyproject.toml ./
COPY certbundle/ certbundle/

# Install with the [openssl] extra so pyOpenSSL is available for the fastest
# and most correct rehash strategy (falls back to subprocess / pure-Python if
# not present, so this is an optimisation, not a hard requirement).
RUN pip install --no-cache-dir ".[openssl]"


# -----------------------------------------------------------------------------
# Stage 2: runtime
#
# Copies only the populated venv from the builder.  No compiler toolchain,
# no pip, no headers.
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="crab-certbundle" \
      org.opencontainers.image.description="IGTF/X.509 CA bundle builder and refresher" \
      org.opencontainers.image.source="https://github.com/snafus/crab-certbundle" \
      org.opencontainers.image.licenses="Apache-2.0"

# openssl    — required by `crabctl` for the CApath rehash step.
# ca-certificates — so HTTPS downloads (IGTF tarballs, CRLs) validate against
#               a known trust store even before the bundle is built.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Non-root user; uid/gid 999 avoids conflicts with common system accounts.
RUN groupadd -r -g 999 certbundle \
    && useradd -r -u 999 -g certbundle -s /usr/sbin/nologin \
               -d /var/lib/certbundle certbundle

# Create expected mount points.
# /etc/certbundle  — config (mounted read-only by the operator; no chown needed)
# /var/lib/certbundle — output CApath dirs / bundle files (read-write)
# /var/cache/certbundle — IGTF tarball cache + CRL cache (read-write)
RUN mkdir -p /etc/certbundle /var/lib/certbundle /var/cache/certbundle \
    && chown certbundle:certbundle /var/lib/certbundle /var/cache/certbundle

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# Declare volumes so named volumes / PVCs are created automatically.
VOLUME ["/var/lib/certbundle", "/var/cache/certbundle"]

# Defaults — all overridable at runtime (-e / environment:).
ENV CRABCTL_CONFIG=/etc/certbundle/config.yaml \
    CRABCTL_COMMANDS=refresh \
    CRABCTL_LOOP_INTERVAL=0

USER certbundle
WORKDIR /var/lib/certbundle

ENTRYPOINT ["/entrypoint.sh"]
# Docker CMD args are forwarded to every subcommand (e.g. --dry-run).
CMD []
