#!/bin/sh
#
# crab-certbundle container entrypoint
#
# Environment variables
# ---------------------
# CRABCTL_CONFIG        Path to the crab config file.
#                       Default: /etc/crab/config.yaml
#
# CRABCTL_COMMANDS      Comma-separated list of crabctl subcommands to run each
#                       cycle, in order.
#                       Default: build
#                       Example: fetch-crls,build
#
# CRABCTL_LOOP_INTERVAL Seconds to sleep between cycles.
#                       0 (default) = run once then exit (one-shot mode).
#                       Any positive integer = loop indefinitely.
#
# Docker CMD arguments (after the image name) are forwarded to every subcommand,
# useful for flags like --dry-run or --no-crls that apply to all commands.
# Note: arguments containing spaces are not supported; use simple flags only.
#

set -e

CONFIG="${CRABCTL_CONFIG:-/etc/crab/config.yaml}"
COMMANDS="${CRABCTL_COMMANDS:-build}"
INTERVAL="${CRABCTL_LOOP_INTERVAL:-0}"

# Capture CMD args before run_cycle uses set -- internally.
_passthrough="$*"

log() {
    printf '[crab] %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

# Run every command in $COMMANDS against the configured config file.
# Respects set -e: in one-shot mode the caller leaves set -e active so any
# failure exits the script immediately with that exit code.
# In loop mode the caller suspends set -e so a transient failure is logged
# and the loop continues rather than killing the container.
run_cycle() {
    # Split $COMMANDS on commas into positional parameters.
    OIFS="$IFS"; IFS=','
    # shellcheck disable=SC2086  (word-split on comma is intentional here)
    set -- $COMMANDS
    IFS="$OIFS"

    for _cmd; do
        # Strip any accidental whitespace around the command name.
        _cmd=$(printf '%s' "$_cmd" | tr -d ' \t')
        [ -z "$_cmd" ] && continue

        log "crabctl --config ${CONFIG} ${_cmd} ${_passthrough}"
        # shellcheck disable=SC2086  (deliberate split of simple flag tokens)
        crabctl --config "${CONFIG}" "${_cmd}" ${_passthrough}
    done
}

case "$INTERVAL" in
    0|"")
        # ── One-shot mode ────────────────────────────────────────────────────
        # set -e is still active: the first failing command exits immediately
        # and its exit code is propagated to the caller (CronJob, systemd, CI).
        log "One-shot mode (commands: ${COMMANDS})"
        run_cycle
        ;;

    *)
        # ── Loop mode ────────────────────────────────────────────────────────
        # Suspend set -e around each cycle so that transient errors (network
        # failures, unreachable CRL endpoints, etc.) are logged but do not
        # stop the container.  The loop always sleeps and retries.
        log "Loop mode (commands: ${COMMANDS}, interval: ${INTERVAL}s)"
        while true; do
            log "--- cycle start ---"
            set +e
            run_cycle
            _rc=$?
            set -e
            if [ "$_rc" -eq 0 ]; then
                log "Cycle complete"
            else
                log "Cycle finished with errors (rc=${_rc}); retrying in ${INTERVAL}s"
            fi
            sleep "${INTERVAL}"
        done
        ;;
esac
