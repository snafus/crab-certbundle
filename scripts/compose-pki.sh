#!/usr/bin/env bash
# compose-pki.sh — manage a CRAB-PKI hierarchy for Docker Compose services
#
# Usage:
#   compose-pki.sh init                    Initialise CA and issue all service certs
#   compose-pki.sh issue   <service...>    Issue (or re-issue) certs for named services
#   compose-pki.sh revoke  <service>       Revoke a service cert and reissue a fresh one
#   compose-pki.sh status                  Show CA info and cert expiry for all services
#   compose-pki.sh clean                   Delete the entire PKI directory (destructive)
#
# Configuration — override with environment variables or edit the defaults below:
#   CRAB_PKI_DIR        Where to write the CA hierarchy         [default: ./pki]
#   CRAB_SERVICES       Space-separated list of service names   [default: see below]
#   CRAB_ROOT_CN        Root CA common name                     [default: Compose Root CA]
#   CRAB_ISSUING_CN     Intermediate CA common name             [default: Compose Issuing CA]
#   CRAB_ORG            Organisation name for CA subjects       [default: Lab]
#   CRAB_ROOT_DAYS      Root CA validity in days                [default: 3650]
#   CRAB_ISSUING_DAYS   Intermediate CA validity in days        [default: 1825]
#   CRAB_CERT_DAYS      Leaf cert validity in days              [default: 365]
#   CRAB_KEY_TYPE       Key algorithm for all certs             [default: ecdsa-p256]
#   CRAB_CERT_PROFILE   Leaf cert profile (server/client/grid-host) [default: server]
#   CRAB_USE_INTERMEDIATE  Create an intermediate issuing CA (true/false) [default: true]
#
# Extra SANs per service:
#   Set CRAB_SAN_<SERVICE> to a space-separated list of additional SAN values.
#   Example:  CRAB_SAN_api="DNS:api.internal IP:10.0.0.5"
#   The service name itself (DNS:<service>) is always added automatically.
#
# Exit codes:
#   0  success
#   1  usage error or missing dependency
#   2  PKI operation failed

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
PKI_DIR="${CRAB_PKI_DIR:-./pki}"
SERVICES="${CRAB_SERVICES:-db api worker frontend}"
ROOT_CN="${CRAB_ROOT_CN:-Compose Root CA}"
ISSUING_CN="${CRAB_ISSUING_CN:-Compose Issuing CA}"
ORG="${CRAB_ORG:-Lab}"
ROOT_DAYS="${CRAB_ROOT_DAYS:-3650}"
ISSUING_DAYS="${CRAB_ISSUING_DAYS:-1825}"
CERT_DAYS="${CRAB_CERT_DAYS:-365}"
KEY_TYPE="${CRAB_KEY_TYPE:-ecdsa-p256}"
CERT_PROFILE="${CRAB_CERT_PROFILE:-server}"
USE_INTERMEDIATE="${CRAB_USE_INTERMEDIATE:-true}"

# ── derived paths ────────────────────────────────────────────────────────────
ROOT_CA="$PKI_DIR/root-ca"
if [[ "$USE_INTERMEDIATE" == "true" ]]; then
    ISSUING_CA="$PKI_DIR/issuing-ca"
else
    ISSUING_CA="$ROOT_CA"
fi

# ── helpers ──────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 2; }
info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH"
}

# Build the --san flags for a service.
# Always includes DNS:<service>; appends anything in CRAB_SAN_<SERVICE>.
san_flags() {
    local svc="$1"
    local flags="--san DNS:${svc}"
    # Variable-name safe upper-case conversion (bash 3 compatible)
    local var="CRAB_SAN_$(echo "$svc" | tr '[:lower:]-' '[:upper:]_')"
    local extra="${!var:-}"
    for san in $extra; do
        flags="$flags --san $san"
    done
    echo "$flags"
}

# Return the issued cert path for a service.
cert_path() {
    local svc="$1"
    echo "$ISSUING_CA/issued/${svc}-cert.pem"
}

# ── commands ─────────────────────────────────────────────────────────────────

cmd_init() {
    if [[ -f "$ROOT_CA/ca-cert.pem" ]]; then
        warn "PKI already initialised at $PKI_DIR"
        warn "Run '$0 issue <service>' to add certs, or '$0 clean' then re-init."
        exit 0
    fi

    info "Creating root CA in $ROOT_CA"
    crabctl ca init "$ROOT_CA" \
        --name "$ROOT_CN" --org "$ORG" \
        --days "$ROOT_DAYS" --key-type "$KEY_TYPE"

    if [[ "$USE_INTERMEDIATE" == "true" ]]; then
        info "Creating intermediate issuing CA in $ISSUING_CA"
        crabctl ca intermediate "$ISSUING_CA" \
            --parent "$ROOT_CA" \
            --name "$ISSUING_CN" --org "$ORG" \
            --days "$ISSUING_DAYS" --key-type "$KEY_TYPE" \
            --path-length 0
    fi

    # Issue certs for all configured services
    # shellcheck disable=SC2086
    cmd_issue $SERVICES
}

cmd_issue() {
    [[ $# -gt 0 ]] || die "issue: specify at least one service name"
    [[ -f "$ISSUING_CA/ca-cert.pem" ]] || die "PKI not initialised — run '$0 init' first"

    for svc in "$@"; do
        local dest
        dest="$(cert_path "$svc")"

        if [[ -f "$dest" ]]; then
            warn "$svc: cert already exists at $dest — skipping (use 'revoke $svc' to replace)"
            continue
        fi

        info "Issuing cert for service: $svc"
        # shellcheck disable=SC2046
        crabctl cert issue \
            --ca "$ISSUING_CA" \
            --cn "$svc" \
            $(san_flags "$svc") \
            --days "$CERT_DAYS" \
            --key-type "$KEY_TYPE" \
            --profile "$CERT_PROFILE"
    done
}

cmd_revoke() {
    [[ $# -eq 1 ]] || die "revoke: specify exactly one service name"
    local svc="$1"
    local cert
    cert="$(cert_path "$svc")"

    [[ -f "$cert" ]] || die "No cert found for '$svc' at $cert"

    info "Revoking cert for $svc"
    crabctl cert revoke --ca "$ISSUING_CA" "$cert" --reason superseded

    info "Removing old cert and key for $svc"
    local base="$ISSUING_CA/issued/${svc}"
    rm -f "${base}-cert.pem" "${base}-key.pem" "${base}-fullchain.pem"

    info "Reissuing cert for $svc"
    # shellcheck disable=SC2046
    crabctl cert issue \
        --ca "$ISSUING_CA" \
        --cn "$svc" \
        $(san_flags "$svc") \
        --days "$CERT_DAYS" \
        --key-type "$KEY_TYPE" \
        --profile "$CERT_PROFILE"
}

cmd_status() {
    [[ -f "$ROOT_CA/ca-cert.pem" ]] || die "PKI not initialised — run '$0 init' first"

    info "Root CA"
    crabctl ca show "$ROOT_CA"

    if [[ "$USE_INTERMEDIATE" == "true" && -f "$ISSUING_CA/ca-cert.pem" ]]; then
        echo
        info "Issuing CA"
        crabctl ca show "$ISSUING_CA"
    fi

    echo
    info "Service certificates"
    printf "  %-20s  %-10s  %s\n" "SERVICE" "STATUS" "EXPIRES"
    printf "  %-20s  %-10s  %s\n" "-------" "------" "-------"

    for svc in $SERVICES; do
        local cert
        cert="$(cert_path "$svc")"
        if [[ ! -f "$cert" ]]; then
            printf "  %-20s  %-10s\n" "$svc" "MISSING"
            continue
        fi
        local expiry
        expiry="$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null \
                  | sed 's/notAfter=//')"
        # Warn if expiring within 30 days
        local ok
        ok="$(openssl x509 -noout -checkend 2592000 -in "$cert" 2>/dev/null \
              && echo OK || echo EXPIRING)"
        printf "  %-20s  %-10s  %s\n" "$svc" "$ok" "$expiry"
    done
}

cmd_clean() {
    [[ -d "$PKI_DIR" ]] || { warn "$PKI_DIR does not exist; nothing to do"; exit 0; }
    echo "This will permanently delete $PKI_DIR and all private keys within it."
    read -r -p "Type 'yes' to confirm: " confirm
    [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
    rm -rf "$PKI_DIR"
    info "Deleted $PKI_DIR"
}

# ── main ─────────────────────────────────────────────────────────────────────

require_cmd crabctl

case "${1:-}" in
    init)    cmd_init ;;
    issue)   shift; cmd_issue "$@" ;;
    revoke)  shift; cmd_revoke "$@" ;;
    status)  cmd_status ;;
    clean)   cmd_clean ;;
    "")      echo "Usage: $0 {init|issue|revoke|status|clean}" >&2; exit 1 ;;
    *)       die "Unknown command: $1" ;;
esac
