"""
crabctl CLI

Commands:
  build       Build one or more output profiles from configured sources.
  validate    Validate one or more existing output directories.
  diff        Show changes between current directory and a new build.
  list        List certificates in a source, profile output, or directory.
  fetch-crls  Fetch or refresh CRLs for a profile.
  status      Show health summary for one or more profile output directories.
  show-config Dump the resolved configuration (useful for debugging).

Global options:
  --config / -c               Path to config file (default: ./crab.yaml or /etc/crab/config.yaml)
  --verbose / -v              Increase log verbosity.
  --quiet / -q                Suppress all output except errors.
  --log-format text|json      Log output format (default: text).
  --output-format text|json   Command output format (default: text).
"""

import json
import logging
import os
import re
import sys
from typing import List, Optional

import click

from crab import __version__, __commit__
from crab.logfmt import make_formatter
from crab.cert import parse_pem_file
from crab.config import load_config, ConfigError
from crab.sources import build_source
from crab.crl import CRLManager
from crab.output import OutputProfile, build_output
from crab.policy import PolicyEngine
from crab.pki import (
    init_ca, init_intermediate_ca, issue_cert, renew_cert, sign_csr,
    revoke_cert, generate_crl, show_ca_info, list_issued,
    CERT_PROFILES, KEY_TYPES, REVOKE_REASONS,
    PKIError, CADirectory,
)
from crab.rehash import CERT_HASH_FILE_RE
from crab.reporting import (
    diff_cert_sets,
    render_diff_text,
    render_diff_json,
    render_source_report,
    render_inventory,
)
from crab.validation import validate_directory, validate_crls, has_errors, has_warnings

logger = logging.getLogger(__name__)

# Default config file search path
_CONFIG_SEARCH = [
    "./crab.yaml",
    "./crab.yml",
    "/etc/crab/config.yaml",
    "/etc/crab/config.yml",
]


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

_version_string = (
    "{} ({})".format(__version__, __commit__)
    if __commit__ != "unknown"
    else __version__
)

@click.group()
@click.version_option(_version_string, prog_name="crabctl")
@click.option(
    "--config", "-c",
    default=None,
    metavar="FILE",
    help="Path to config file.",
    envvar="CRAB_CONFIG",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress informational output.",
)
@click.option(
    "--log-format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Log output format.",
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Command output format.",
)
@click.pass_context
def main(ctx, config, verbose, quiet, log_format, output_format):
    """
    crabctl — OpenSSL CApath directory generator for research infrastructure.

    Combine IGTF trust anchors and public CA roots into hashed CApath directories
    for XRootD, dCache, curl/OpenSSL, and similar middleware.
    """
    ctx.ensure_object(dict)

    # Initial logging setup — may be refined after config is loaded.
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(make_formatter(log_format))
        root.addHandler(handler)
    root.setLevel(level)

    # Record CLI flags so _apply_logging_config can honour them as overrides.
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["log_format"] = log_format
    ctx.obj["output_format"] = output_format

    # Config resolution
    if config:
        ctx.obj["config_path"] = config
    else:
        ctx.obj["config_path"] = _find_default_config()


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

@main.command()
@click.argument("profiles", nargs=-1, metavar="[PROFILE...]")
@click.option("--dry-run", is_flag=True, help="Show what would be done without writing.")
@click.option("--no-crls", is_flag=True, help="Skip CRL fetching even if configured.")
@click.option("--report", is_flag=True, help="Print a source/policy report after building.")
@click.option(
    "--strict-warnings", is_flag=True,
    help="Exit 3 when the build succeeds but policy or CRL warnings are present.",
)
@click.pass_context
def build(ctx, profiles, dry_run, no_crls, report, strict_warnings):
    """
    Build output profile(s) from configured sources.

    If no PROFILE names are given, all profiles are built.

    Exit codes: 0 = success, 1 = errors, 3 = success with warnings (--strict-warnings).

    \b
    Example:
        crabctl build grid server-auth
        crabctl build --dry-run
        crabctl build --strict-warnings
    """
    cfg = _load_config_or_exit(ctx)
    profile_names = list(profiles) or list(cfg.profiles.keys())

    total_errors = 0
    total_warned = 0
    for pname in profile_names:
        if pname not in cfg.profiles:
            click.echo("ERROR: Unknown profile '{}'. Available: {}".format(
                pname, ", ".join(cfg.profiles.keys())
            ), err=True)
            total_errors += 1
            continue

        click.echo("Building profile '{}'...".format(pname))
        errors, warned = _build_profile(
            cfg, pname, dry_run=dry_run, skip_crls=no_crls, do_report=report
        )
        total_errors += errors
        total_warned += warned

    if total_errors:
        sys.exit(1)
    if strict_warnings and total_warned:
        sys.exit(3)
    sys.exit(0)


def _build_profile(cfg, profile_name, dry_run=False, skip_crls=False, do_report=False):
    # type: (...) -> tuple
    """Build one profile.  Returns ``(errors, warned)`` counts."""
    profile_cfg = cfg.profiles[profile_name]
    source_names = profile_cfg.sources
    errors = 0
    warned = 0

    # Load sources
    source_results = []
    for sname in source_names:
        src_cfg = cfg.sources[sname]
        source = build_source(src_cfg)
        click.echo("  Loading source '{}'...".format(sname))
        try:
            result = source.load()
            source_results.append(result)
            if result.errors:
                for err in result.errors:
                    click.echo("  WARNING: {}".format(err), err=True)
            click.echo("  Loaded {} cert(s) from '{}'".format(len(result.certificates), sname))
        except Exception as exc:
            click.echo("  ERROR loading source '{}': {}".format(sname, exc), err=True)
            errors += 1
            continue

    all_certs = []
    for sr in source_results:
        all_certs.extend(sr.certificates)

    # Policy filtering
    policy = PolicyEngine(profile_cfg.policy)
    accepted = policy.filter(all_certs)
    policy_warned = policy.count_warnings(accepted)
    warned += policy_warned
    click.echo("  Policy: {}/{} certificates accepted".format(len(accepted), len(all_certs)))
    if policy_warned:
        click.echo("  Policy warnings: {}".format(policy_warned), err=True)

    # Deduplication report
    unique_fps = set(c.fingerprint_sha256 for c in accepted)
    if len(unique_fps) < len(accepted):
        click.echo("  Note: {} duplicate(s) will be deduplicated".format(
            len(accepted) - len(unique_fps)
        ))

    if do_report:
        click.echo(render_source_report(source_results, accepted))

    # Build output directory
    output_profile = OutputProfile(profile_name, profile_cfg.as_output_profile_dict())
    result = build_output(
        accepted,
        output_profile,
        source_results=source_results,
        dry_run=dry_run,
    )
    if result.errors:
        for err in result.errors:
            click.echo("  ERROR: {}".format(err), err=True)
        errors += len(result.errors)

    if dry_run:
        click.echo("  [dry-run] Would write {} files to {}".format(
            result.cert_count, profile_cfg.output_path
        ))
    else:
        click.echo("  Wrote {} files to {}".format(result.cert_count, profile_cfg.output_path))

    # CRL management
    if profile_cfg.include_crls and not skip_crls:
        crl_mgr = CRLManager(profile_cfg.crl, profile_cfg.output_path)
        click.echo("  Fetching CRLs...")
        crl_result = crl_mgr.update_crls(accepted, dry_run=dry_run)
        crl_summary = "  CRLs: {} updated, {} failed, {} no URL".format(
            len(crl_result.updated), len(crl_result.failed), len(crl_result.missing)
        )
        if crl_result.skipped:
            crl_summary += ", {} skipped (still fresh)".format(len(crl_result.skipped))
        click.echo(crl_summary)
        for err in crl_result.errors:
            click.echo("  CRL WARNING: {}".format(err), err=True)
        warned += len(crl_result.failed)

    return errors, warned


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@main.command()
@click.argument("targets", nargs=-1, metavar="[PROFILE_OR_DIR...]")
@click.option("--no-hash-check", is_flag=True, help="Skip hash filename verification.")
@click.option("--no-openssl", is_flag=True, help="Skip openssl verify smoke tests.")
@click.pass_context
def validate(ctx, targets, no_hash_check, no_openssl):
    """
    Validate one or more CApath directories.

    TARGETS may be profile names (from config) or raw directory paths.
    If no target is given, all configured profiles are validated.

    Exit code: 0 = OK, 1 = warnings, 2 = errors.
    """
    cfg = _load_config_or_exit(ctx)
    output_json = ctx.obj["output_format"] == "json"

    # Resolve targets to directories
    dirs = []
    if targets:
        for t in targets:
            if t in cfg.profiles:
                dirs.append((t, cfg.profiles[t].output_path))
            elif os.path.isdir(t):
                dirs.append((t, t))
            else:
                click.echo("ERROR: '{}' is not a known profile or directory".format(t), err=True)
                sys.exit(2)
    else:
        dirs = [(n, p.output_path) for n, p in cfg.profiles.items()]

    max_level = 0
    all_results = []

    for label, directory in dirs:
        if not output_json:
            click.echo("Validating '{}' ({})...".format(label, directory))
        issues = validate_directory(
            directory,
            check_hashes=not no_hash_check,
            run_openssl=not no_openssl,
        )

        # CRL freshness check — only when validating a named profile with CRLs enabled
        if label in cfg.profiles and cfg.profiles[label].include_crls:
            profile_cfg = cfg.profiles[label]
            crl_mgr = CRLManager(profile_cfg.crl, profile_cfg.output_path)
            cert_infos = _load_certs_from_directory(directory, label)
            issues.extend(validate_crls(crl_mgr, cert_infos))
        if output_json:
            all_results.append({
                "target": label,
                "directory": directory,
                "issues": [
                    {"level": i.level, "message": i.message, "file": i.file}
                    for i in issues
                ],
                "errors": sum(1 for i in issues if i.level == "error"),
                "warnings": sum(1 for i in issues if i.level == "warning"),
            })
        else:
            for issue in issues:
                click.echo("  {}".format(issue))
        if has_errors(issues):
            max_level = 2
        elif has_warnings(issues) and max_level < 1:
            max_level = 1

    if output_json:
        click.echo(json.dumps(all_results, indent=2))

    sys.exit(max_level)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

@main.command()
@click.argument("profile_or_dir")
@click.option("--old-dir", default=None, metavar="DIR",
              help="Compare against this directory instead of rebuilding.")
@click.pass_context
def diff(ctx, profile_or_dir, old_dir):
    """
    Show changes between the current output directory and a fresh build.

    Useful for reviewing what a ``crabctl build`` would change before
    committing to it.

    Example:
        crabctl diff grid
        crabctl diff /etc/grid-security/certificates --old-dir /backup/certs
    """
    cfg = _load_config_or_exit(ctx)
    output_json = ctx.obj["output_format"] == "json"

    # Resolve profile
    if profile_or_dir in cfg.profiles:
        profile_name = profile_or_dir
        profile_cfg = cfg.profiles[profile_name]
        current_dir = profile_cfg.output_path
    elif os.path.isdir(profile_or_dir):
        current_dir = profile_or_dir
        profile_name = None
        profile_cfg = None
    else:
        click.echo("ERROR: '{}' is not a profile name or directory".format(profile_or_dir), err=True)
        sys.exit(1)

    # Load current directory
    old_certs = []
    compare_dir = old_dir or current_dir
    if os.path.isdir(compare_dir):
        old_certs = _load_certs_from_directory(compare_dir, "existing")
    else:
        # Suppress this informational message in JSON mode so stdout is pure JSON.
        if not output_json:
            click.echo(
                "Note: current directory '{}' does not exist (treating as empty)".format(
                    compare_dir
                )
            )

    # Build new set (in memory, no disk write)
    if profile_cfg is not None:
        new_certs = _load_profile_certs(cfg, profile_name)
    else:
        click.echo("No profile specified; provide --old-dir to compare two directories.", err=True)
        sys.exit(1)

    d = diff_cert_sets(old_certs, new_certs)

    if output_json:
        click.echo(render_diff_json(d))
    else:
        click.echo(render_diff_text(d))
        if not d.has_changes:
            click.echo("No changes.")

    if d.has_changes:
        sys.exit(1)  # non-zero when changes exist, useful in scripts


def _load_profile_certs(cfg, profile_name):
    """Load and policy-filter all certs for a profile without writing output."""
    profile_cfg = cfg.profiles[profile_name]
    all_certs = []
    for sname in profile_cfg.sources:
        source = build_source(cfg.sources[sname])
        try:
            result = source.load()
            all_certs.extend(result.certificates)
        except Exception as exc:
            logger.warning("Source '%s' failed during diff: %s", sname, exc)
    policy = PolicyEngine(profile_cfg.policy)
    return policy.filter(all_certs)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@main.command(name="list")
@click.argument("target", default=None, required=False, metavar="[PROFILE_OR_DIR]")
@click.option("--source", "-s", default=None, metavar="SOURCE",
              help="List certificates in a specific source rather than a profile/directory.")
@click.option("--expired", is_flag=True, help="Show only expired certificates.")
@click.pass_context
def list_cmd(ctx, target, source, expired):
    """
    List certificates in a profile, source, or directory.

    Examples:
        crabctl list grid
        crabctl list --source igtf-classic
        crabctl list /etc/grid-security/certificates
        crabctl --output-format json list | jq '.[].subject'
    """
    cfg = _load_config_or_exit(ctx)
    output_json = ctx.obj["output_format"] == "json"
    certs = []

    if source:
        if source not in cfg.sources:
            click.echo("ERROR: Unknown source '{}'. Available: {}".format(
                source, ", ".join(cfg.sources.keys())
            ), err=True)
            sys.exit(1)
        src = build_source(cfg.sources[source])
        result = src.load()
        certs = result.certificates
    elif target and target in cfg.profiles:
        certs = _load_profile_certs(cfg, target)
    elif target and os.path.isdir(target):
        certs = _load_certs_from_directory(target, target)
    elif target is None:
        click.echo("Please specify a profile, source (--source NAME), or directory.", err=True)
        sys.exit(1)
    else:
        click.echo("ERROR: '{}' not found as a profile or directory.".format(target), err=True)
        sys.exit(1)

    if expired:
        certs = [c for c in certs if c.is_expired()]

    click.echo(render_inventory(certs, format="json" if output_json else "text"))
    if not output_json:
        click.echo("\nTotal: {} certificate(s)".format(len(certs)))


# ---------------------------------------------------------------------------
# fetch-crls
# ---------------------------------------------------------------------------

@main.command("fetch-crls")
@click.argument("profiles", nargs=-1, metavar="[PROFILE...]")
@click.option("--dry-run", is_flag=True, help="Show URLs without downloading.")
@click.pass_context
def fetch_crls(ctx, profiles, dry_run):
    """
    Fetch or refresh CRLs for one or more profiles.

    If no PROFILE is given, all profiles with CRL fetching enabled are updated.
    """
    cfg = _load_config_or_exit(ctx)
    profile_names = list(profiles) or [
        n for n, p in cfg.profiles.items() if p.include_crls
    ]
    if not profile_names:
        click.echo("No profiles with CRL fetching configured.")
        sys.exit(0)

    for pname in profile_names:
        if pname not in cfg.profiles:
            click.echo("ERROR: Unknown profile '{}'".format(pname), err=True)
            continue

        profile_cfg = cfg.profiles[pname]
        click.echo("Fetching CRLs for profile '{}'...".format(pname))
        certs = _load_profile_certs(cfg, pname)
        crl_mgr = CRLManager(profile_cfg.crl, profile_cfg.output_path)
        result = crl_mgr.update_crls(certs, dry_run=dry_run)
        summary = "  Updated: {}  Failed: {}  No URL: {}".format(
            len(result.updated), len(result.failed), len(result.missing)
        )
        if result.skipped:
            summary += "  Skipped (fresh): {}".format(len(result.skipped))
        click.echo(summary)
        for err in result.errors:
            click.echo("  {}".format(err), err=True)


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------

@main.command("refresh")
@click.argument("profiles", nargs=-1, metavar="[PROFILE...]")
@click.option("--dry-run", is_flag=True, help="Show what would be done without writing.")
@click.option("--report", is_flag=True, help="Print a source/policy report after building.")
@click.option(
    "--strict-warnings", is_flag=True,
    help="Exit 3 when the refresh succeeds but policy or CRL warnings are present.",
)
@click.pass_context
def refresh(ctx, profiles, dry_run, report, strict_warnings):
    """
    Refresh CRLs then rebuild output profile(s).

    Runs in two coordinated steps for each profile:

    \b
    1. Fetch CRLs — uses certificates already present in the output
       directory.  Failures are reported as warnings and do not prevent
       the build from running.
    2. Build — reloads all sources, applies policy, and writes the output.
       The CRL step inside build is skipped (CRLs were just refreshed).

    This is the recommended command for scheduled operation (cron, systemd
    timer, container loop).  Replacing two separate invocations of
    fetch-crls and build with a single refresh also simplifies container
    entrypoint configuration.

    Exit codes: 0 = success, 1 = errors, 3 = success with warnings (--strict-warnings).

    If no PROFILE names are given, all profiles are refreshed.

    \b
    Examples:
        crabctl refresh
        crabctl refresh grid
        crabctl refresh --dry-run
        crabctl refresh --strict-warnings
    """
    cfg = _load_config_or_exit(ctx)
    profile_names = list(profiles) or list(cfg.profiles.keys())

    total_errors = 0
    total_warned = 0
    for pname in profile_names:
        if pname not in cfg.profiles:
            click.echo("ERROR: Unknown profile '{}'. Available: {}".format(
                pname, ", ".join(cfg.profiles.keys())
            ), err=True)
            total_errors += 1
            continue

        profile_cfg = cfg.profiles[pname]

        # Step 1: CRL pre-fetch using existing output certs (best-effort)
        if profile_cfg.include_crls:
            click.echo("Fetching CRLs for profile '{}'...".format(pname))
            try:
                certs = _load_profile_certs(cfg, pname)
                crl_mgr = CRLManager(profile_cfg.crl, profile_cfg.output_path)
                crl_result = crl_mgr.update_crls(certs, dry_run=dry_run)
                crl_line = "  CRLs: {} updated, {} failed, {} no URL".format(
                    len(crl_result.updated), len(crl_result.failed), len(crl_result.missing)
                )
                if crl_result.skipped:
                    crl_line += ", {} skipped (still fresh)".format(len(crl_result.skipped))
                click.echo(crl_line)
                for err in crl_result.errors:
                    click.echo("  CRL WARNING: {}".format(err), err=True)
                total_warned += len(crl_result.failed)
            except Exception as exc:
                click.echo(
                    "  WARNING: CRL fetch failed for '{}': {} — continuing with build".format(
                        pname, exc
                    ),
                    err=True,
                )

        # Step 2: Full build; skip the internal CRL step since we just ran it.
        click.echo("Building profile '{}'...".format(pname))
        errors, warned = _build_profile(
            cfg, pname, dry_run=dry_run, skip_crls=True, do_report=report
        )
        total_errors += errors
        total_warned += warned

    if total_errors:
        sys.exit(1)
    if strict_warnings and total_warned:
        sys.exit(3)
    sys.exit(0)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@main.command("status")
@click.argument("profiles", nargs=-1, metavar="[PROFILE...]")
@click.pass_context
def status_cmd(ctx, profiles):
    """
    Show health summary for one or more profile output directories.

    Reports certificate counts, expiry dates, CRL freshness, and last-build
    time.  Exits 0 when all profiles are healthy, 1 otherwise.

    If no PROFILE names are given, all configured profiles are checked.
    """
    from crab.status import collect_status, render_status_text

    cfg = _load_config_or_exit(ctx)
    output_json = ctx.obj["output_format"] == "json"
    profile_names = list(profiles) or list(cfg.profiles.keys())

    unknown = [n for n in profile_names if n not in cfg.profiles]
    if unknown:
        for n in unknown:
            click.echo("ERROR: Unknown profile '{}'".format(n), err=True)
        sys.exit(1)

    statuses = []
    for pname in profile_names:
        profile_cfg = cfg.profiles[pname]
        # Load certs for CRL freshness check only if CRLs are configured
        cert_infos = None
        if profile_cfg.include_crls:
            try:
                cert_infos = _load_profile_certs(cfg, pname)
            except Exception as exc:
                logger.warning("Could not load certs for '%s' CRL check: %s", pname, exc)
        statuses.append(collect_status(pname, profile_cfg, cert_infos))

    if output_json:
        click.echo(json.dumps([s.to_dict() for s in statuses], indent=2))
    else:
        click.echo(render_status_text(statuses))

    if not all(s.healthy for s in statuses):
        sys.exit(1)


# ---------------------------------------------------------------------------
# show-config
# ---------------------------------------------------------------------------

@main.command("show-config")
@click.pass_context
def show_config(ctx):
    """Dump the resolved configuration (sources, profiles, paths)."""
    cfg = _load_config_or_exit(ctx)
    click.echo("Config file: {}".format(cfg.path or "(not loaded)"))
    click.echo("")
    click.echo("Sources ({})".format(len(cfg.sources)))
    click.echo("-" * 40)
    for name, src in cfg.sources.items():
        click.echo("  {:<20}  type={}".format(name, src.type))
        for k, v in src.raw.items():
            if k != "type":
                click.echo("    {}: {}".format(k, v))
    click.echo("")
    click.echo("Profiles ({})".format(len(cfg.profiles)))
    click.echo("-" * 40)
    for name, prof in cfg.profiles.items():
        desc = "  ({})".format(prof.description) if prof.description else ""
        click.echo("  {:<20}  → {}{}".format(name, prof.output_path, desc))
        click.echo("    sources: {}".format(", ".join(prof.sources)))
        click.echo("    format: {}  atomic: {}  rehash: {}  crls: {}".format(
            prof.output_format, prof.atomic, prof.rehash, prof.include_crls
        ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_certs_from_directory(directory, source_name):
    # type: (str, str) -> list
    """Read all hashed cert files from a built CApath directory."""
    certs = []
    for entry in sorted(os.listdir(directory)):
        if not CERT_HASH_FILE_RE.match(entry):
            continue
        full = os.path.join(directory, entry)
        try:
            certs.extend(parse_pem_file(full, source_name=source_name))
        except Exception as exc:
            logger.warning("Could not parse cert file %s: %s", full, exc)
    return certs


def _load_config_or_exit(ctx):
    path = ctx.obj.get("config_path")
    if not path:
        click.echo(
            "ERROR: No config file found.\n"
            "Searched: {}\n"
            "Use --config FILE or set CRAB_CONFIG env var.".format(
                ", ".join(_CONFIG_SEARCH)
            ),
            err=True,
        )
        sys.exit(1)
    try:
        cfg = load_config(path)
    except ConfigError as exc:
        click.echo("ERROR: Config error: {}".format(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo("ERROR: Cannot load config '{}': {}".format(path, exc), err=True)
        sys.exit(1)
    _apply_logging_config(cfg, ctx)
    return cfg


def _apply_logging_config(cfg, ctx):
    # type: (...) -> None
    """
    Apply the ``logging:`` section from *cfg* to the root logger.

    Priority for each setting:
      level  — CLI flag (``--verbose``/``--quiet``) > config ``logging.level``
      format — CLI flag (``--log-format``)          > config ``logging.format``
    """
    lc = cfg.logging_config

    # Resolve effective log level.
    if ctx.obj.get("verbose"):
        level = logging.DEBUG
    elif ctx.obj.get("quiet"):
        level = logging.ERROR
    else:
        level_name = lc.get("level", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)

    # Resolve effective log format: CLI flag beats config file.
    cli_fmt = ctx.obj.get("log_format", "text")
    fmt = cli_fmt if cli_fmt != "text" else lc.get("format", "text")
    formatter = make_formatter(fmt)

    logging.root.setLevel(level)
    for h in logging.root.handlers:
        h.setLevel(level)
        h.setFormatter(formatter)

    # Optional file handler — added once; idempotent on repeated calls.
    log_file = lc.get("file")
    if log_file:
        abs_path = os.path.abspath(log_file)
        for h in logging.root.handlers:
            if isinstance(h, logging.FileHandler) and h.baseFilename == abs_path:
                return  # already attached
        try:
            log_dir = os.path.dirname(abs_path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            fh = logging.FileHandler(abs_path)
            fh.setLevel(level)
            fh.setFormatter(make_formatter(fmt, with_time=True))
            logging.root.addHandler(fh)
        except OSError as exc:
            logger.warning("Could not open log file %s: %s", log_file, exc)


def _find_default_config():
    # type: () -> Optional[str]
    for path in _CONFIG_SEARCH:
        if os.path.isfile(path):
            return path
    return None


# ---------------------------------------------------------------------------
# ca — CA management commands
# ---------------------------------------------------------------------------

@main.group("ca")
def ca_group():
    """Create and inspect a local test CA.

    These commands operate on a CA directory and do not require a crab.yaml
    config file.

    \b
    Quick start:
        crabctl ca init ./my-ca
        crabctl ca show ./my-ca
        crabctl cert issue --ca ./my-ca --cn host.example.com
    """


@ca_group.command("init")
@click.argument("ca_dir", default="./ca", metavar="[CA_DIR]")
@click.option("--name", default="CRAB Test CA", show_default=True,
              help="Common Name for the CA certificate.")
@click.option("--org", default=None, metavar="TEXT",
              help="Organisation name (optional).")
@click.option("--days", default=3650, show_default=True, type=int,
              help="Validity period in days.")
@click.option("--key-type", default="rsa2048", show_default=True,
              type=click.Choice(KEY_TYPES),
              help="Key algorithm.")
@click.option("--force", is_flag=True,
              help="Overwrite an existing CA without prompting.")
@click.option("--add-to-profile", default=None, metavar="PROFILE",
              help="Print the crab.yaml snippet to add this CA as a source in PROFILE.")
@click.pass_context
def ca_init(ctx, ca_dir, name, org, days, key_type, force, add_to_profile):
    """
    Create a new self-signed root CA in CA_DIR.

    \b
    Examples:
        crabctl ca init ./my-ca --name "Lab Test CA" --org "ACME Lab"
        crabctl ca init ./my-ca --key-type ed25519 --days 730
        crabctl ca init ./my-ca --force
    """
    try:
        cert_path, key_path = init_ca(
            ca_dir, cn=name, org=org, days=days, key_type=key_type, force=force
        )
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    click.echo("CA initialised:")
    click.echo("  Certificate : {}".format(cert_path))
    click.echo("  Private key : {}  (mode 0600)".format(key_path))
    click.echo("  Name        : {}".format(name))
    click.echo("  Key type    : {}".format(key_type))
    click.echo("  Valid for   : {} days".format(days))

    if add_to_profile:
        abs_cert = os.path.abspath(cert_path)
        source_name = os.path.basename(os.path.abspath(ca_dir)).replace(" ", "-")
        click.echo("")
        click.echo(
            "To add this CA as source '{src}' to profile '{prof}', insert the\n"
            "following into the 'sources:' block in your crab.yaml, then add\n"
            "'{src}' to the profile's sources list:\n"
            "\n"
            "  {src}:\n"
            "    type: local\n"
            "    path: {cert}\n".format(src=source_name, prof=add_to_profile, cert=abs_cert)
        )


@ca_group.command("show")
@click.argument("ca_dir", default="./ca", metavar="[CA_DIR]")
@click.pass_context
def ca_show(ctx, ca_dir):
    """
    Display details about the CA in CA_DIR.

    \b
    Examples:
        crabctl ca show ./my-ca
        crabctl --output-format json ca show ./my-ca
    """
    try:
        info = show_ca_info(ca_dir)
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    output_json = (ctx.obj or {}).get("output_format", "text") == "json"
    if output_json:
        click.echo(json.dumps(info, indent=2))
        return

    click.echo("CA directory  : {}".format(info["ca_dir"]))
    click.echo("Type          : {}".format("root" if info["is_root"] else "intermediate"))
    click.echo("Subject       : {}".format(info["subject"]))
    if not info["is_root"]:
        click.echo("Issuer        : {}".format(info["issuer"]))
    path_len = info["path_length"]
    click.echo("Path length   : {}".format(
        "unconstrained" if path_len is None else str(path_len)
    ))
    click.echo("Key type      : {}".format(info["key_type"]))
    click.echo("Valid from    : {}".format(info["not_before"]))
    click.echo("Valid until   : {}".format(info["not_after"]))
    click.echo("Fingerprint   : {}".format(info["fingerprint_sha256"]))
    click.echo("Issued certs  : {}  ({} revoked)".format(
        info["issued_count"], info["revoked_count"]
    ))
    click.echo("CRL present   : {}".format("yes" if info["crl_exists"] else "no"))
    if not info["is_root"]:
        click.echo("Chain file    : {}".format("yes" if info["chain_exists"] else "no"))


@ca_group.command("intermediate")
@click.argument("ca_dir", default="./sub-ca", metavar="[CA_DIR]")
@click.option("--parent", "parent_dir", required=True, metavar="PARENT_CA_DIR",
              help="Path to the parent CA directory.")
@click.option("--name", default="CRAB Intermediate CA", show_default=True,
              help="Common Name for the intermediate CA.")
@click.option("--org", default=None, help="Organisation name.")
@click.option("--days", default=1825, show_default=True, type=int,
              help="Validity period in days.")
@click.option("--key-type", default="rsa2048", show_default=True,
              type=click.Choice(KEY_TYPES),
              help="Key algorithm.")
@click.option("--path-length", default=0, show_default=True, type=int,
              help="BasicConstraints pathLenConstraint. "
                   "0 = can only sign end-entity certs; -1 = unconstrained.")
@click.option("--cdp-url", default=None, metavar="URL",
              help="CRL Distribution Point URL to embed in the CA certificate.")
@click.option("--force", is_flag=True, help="Overwrite an existing CA.")
def ca_intermediate(ca_dir, parent_dir, name, org, days, key_type, path_length,
                    cdp_url, force):
    """
    Create an intermediate CA signed by an existing parent CA.

    The new CA directory has the same layout as a root CA and can issue
    certificates with 'crabctl cert issue'.  A ca-chain.pem file is also
    written containing this CA's cert concatenated with the parent chain,
    suitable for use as the certificate chain in TLS configurations.

    The issuance is recorded in the parent CA's serial database.

    \b
    Examples:
        # Two-level hierarchy: root → intermediate → end-entity
        crabctl ca init ./root-ca --name "My Root CA"
        crabctl ca intermediate ./sub-ca --parent ./root-ca --name "My Sub CA"
        crabctl cert issue --ca ./sub-ca --cn host.example.com

        # Unconstrained intermediate (can sign further CAs)
        crabctl ca intermediate ./policy-ca --parent ./root-ca \\
            --name "Policy CA" --path-length -1
    """
    # -1 is our sentinel for "unconstrained" since Click can't represent None
    effective_path_length = None if path_length < 0 else path_length

    try:
        cert_path, key_path = init_intermediate_ca(
            ca_dir,
            parent_dir,
            cn=name,
            org=org,
            days=days,
            key_type=key_type,
            path_length=effective_path_length,
            force=force,
            cdp_url=cdp_url,
        )
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    click.echo("Intermediate CA created:")
    click.echo("  Directory   : {}".format(os.path.abspath(ca_dir)))
    click.echo("  Certificate : {}".format(cert_path))
    click.echo("  Private key : {}  (mode 0600)".format(key_path))
    click.echo("  Chain file  : {}".format(
        os.path.join(os.path.abspath(ca_dir), "ca-chain.pem")
    ))
    click.echo("  CN          : {}".format(name))
    click.echo("  Path length : {}".format(
        "unconstrained" if effective_path_length is None
        else str(effective_path_length)
    ))
    click.echo("  Valid for   : {} days".format(days))


# ---------------------------------------------------------------------------
# cert — certificate management commands
# ---------------------------------------------------------------------------

@main.group("cert")
def cert_group():
    """Issue and manage certificates signed by a local CA.

    These commands operate on a CA directory created with ``crabctl ca init``.
    They do not require a crab.yaml config file.
    """


@cert_group.command("issue")
@click.option("--ca", "ca_dir", required=True, metavar="CA_DIR",
              help="Path to the CA directory.")
@click.option("--cn", required=True, metavar="NAME",
              help="Common Name (hostname for server/grid-host; username for client).")
@click.option("--san", "sans", multiple=True, metavar="SAN",
              help="Subject Alternative Name (repeatable).  "
                   "Prefix: DNS: IP: EMAIL:  Default: DNS.")
@click.option("--days", default=365, show_default=True, type=int,
              help="Validity period in days.")
@click.option("--profile", default="server", show_default=True,
              type=click.Choice(CERT_PROFILES),
              help="Certificate profile.")
@click.option("--key-type", default="rsa2048", show_default=True,
              type=click.Choice(KEY_TYPES),
              help="Key algorithm.")
@click.option("--out", "out_dir", default=None, metavar="DIR",
              help="Output directory (default: <ca-dir>/issued/).")
@click.option("--cdp-url", default=None, metavar="URL",
              help="CRL Distribution Point URL to embed in the certificate.")
def cert_issue(ca_dir, cn, sans, days, profile, key_type, out_dir, cdp_url):
    """
    Issue a certificate signed by the CA in CA_DIR.

    The Common Name is automatically added as a DNS SAN when it looks like
    a hostname (contains a dot).  Extra SANs can be added with --san.

    \b
    Examples:
        crabctl cert issue --ca ./my-ca --cn host.example.com
        crabctl cert issue --ca ./my-ca --cn host.example.com \\
            --san DNS:alt.example.com --san IP:10.0.0.1 --days 90
        crabctl cert issue --ca ./my-ca --cn myuser --profile client
        crabctl cert issue --ca ./my-ca --cn xrootd.example.com --profile grid-host
    """
    try:
        cert_path, key_path = issue_cert(
            ca_dir,
            cn=cn,
            sans=list(sans),
            days=days,
            profile=profile,
            key_type=key_type,
            out_dir=out_dir,
            cdp_url=cdp_url,
        )
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    click.echo("Certificate issued:")
    click.echo("  Certificate : {}".format(cert_path))
    click.echo("  Private key : {}  (mode 0600)".format(key_path))
    fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
    if os.path.isfile(fullchain_path):
        click.echo("  Full chain  : {}".format(fullchain_path))
    click.echo("  CN          : {}".format(cn))
    click.echo("  Profile     : {}".format(profile))
    click.echo("  Valid for   : {} days".format(days))


@cert_group.command("sign")
@click.option("--ca", "ca_dir", required=True, metavar="CA_DIR",
              help="Path to the CA directory.")
@click.option("--csr", "csr_path", required=True, metavar="CSR",
              type=click.Path(exists=True),
              help="Path to a PEM-format PKCS#10 Certificate Signing Request.")
@click.option("--profile", default="server", show_default=True,
              type=click.Choice(CERT_PROFILES),
              help="Certificate profile (CA policy — overrides any EKU in the CSR).")
@click.option("--days", default=365, show_default=True, type=int,
              help="Validity period in days.")
@click.option("--san", "extra_sans", multiple=True, metavar="SAN",
              help="Additional SANs to merge with those in the CSR (repeatable).  "
                   "Prefix: DNS: IP: EMAIL:")
@click.option("--cdp-url", default=None, metavar="URL",
              help="CRL Distribution Point URL to embed in the certificate.")
@click.option("--out", "out_dir", default=None, metavar="DIR",
              help="Output directory (default: <ca-dir>/issued/).")
@click.option("--cn", default=None, metavar="NAME",
              help="Override the Common Name from the CSR.")
def cert_sign(ca_dir, csr_path, profile, days, extra_sans, cdp_url, out_dir, cn):
    """
    Sign a CSR and issue a certificate.  No private key is written.

    The private key never enters CRAB — only the public key embedded in the
    CSR is used.  Profile and validity are set by CA policy (the --profile
    and --days flags), not by what the CSR requests.

    \b
    Examples:
        # Basic: sign a CSR using the CA's default policy
        crabctl cert sign --ca ./my-ca --csr host.csr

        # Override profile and validity
        crabctl cert sign --ca ./my-ca --csr host.csr \\
            --profile grid-host --days 180

        # Add extra SANs beyond those in the CSR
        crabctl cert sign --ca ./my-ca --csr host.csr \\
            --san DNS:alt.example.com --san IP:10.0.0.5

        # CSR has no CN — supply one explicitly
        crabctl cert sign --ca ./my-ca --csr service.csr --cn myservice.example.com
    """
    try:
        cert_path = sign_csr(
            ca_dir,
            csr_path,
            profile=profile,
            days=days,
            extra_sans=list(extra_sans),
            cdp_url=cdp_url,
            out_dir=out_dir,
            cn=cn,
        )
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)
    except (IOError, OSError) as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    click.echo("Certificate signed:")
    click.echo("  Certificate : {}".format(cert_path))
    fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
    if os.path.isfile(fullchain_path):
        click.echo("  Full chain  : {}".format(fullchain_path))
    click.echo("  Profile     : {}".format(profile))
    click.echo("  Valid for   : {} days".format(days))
    click.echo("  Note        : No private key written — requester retains the key.")


@cert_group.command("revoke")
@click.option("--ca", "ca_dir", required=True, metavar="CA_DIR",
              help="Path to the CA directory.")
@click.argument("cert_file", metavar="CERT")
@click.option("--reason", default="unspecified", show_default=True,
              type=click.Choice(REVOKE_REASONS),
              help="Revocation reason.")
def cert_revoke(ca_dir, cert_file, reason):
    """
    Revoke CERT and regenerate the CA's CRL.

    CERT must be a PEM file previously issued by the CA in CA_DIR.

    \b
    Examples:
        crabctl cert revoke --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem
        crabctl cert revoke --ca ./my-ca ./my-ca/issued/host-cert.pem \\
            --reason keyCompromise
    """
    try:
        revoke_cert(ca_dir, cert_file, reason=reason)
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)
    except FileNotFoundError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    ca = CADirectory(ca_dir)
    click.echo("Certificate revoked.")
    click.echo("  CRL updated : {}".format(ca.crl_path))
    click.echo("  Reason      : {}".format(reason))


@cert_group.command("renew")
@click.option("--ca", "ca_dir", required=True, metavar="CA_DIR",
              help="Path to the CA directory that issued the certificate.")
@click.argument("cert_file", metavar="CERT")
@click.option("--days", default=None, type=int,
              help="Validity period for the new cert (default: match original).")
@click.option("--reuse-key", is_flag=True, default=False,
              help="Keep the existing private key instead of generating a fresh one.")
@click.option("--force", is_flag=True, default=False,
              help="Renew without confirmation when the certificate is still valid.")
def cert_renew(ca_dir, cert_file, days, reuse_key, force):
    """
    Renew CERT, revoking the old certificate and issuing a replacement.

    CN, SANs, profile, CDP URL, and validity period are read from the
    existing certificate; no flags need to be repeated.  The new files
    are written to the same paths so consuming configurations (TLS server
    configs, volume mounts) do not need updating — only a service reload.

    \b
    Examples:
        crabctl cert renew --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem
        crabctl cert renew --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem \\
            --days 90
        crabctl cert renew --ca ./my-ca ./my-ca/issued/host.example.com-cert.pem \\
            --reuse-key --force
    """
    from cryptography import x509 as _x509
    from datetime import datetime as _datetime

    # Warn before revoking a cert that still has life left in it.
    try:
        with open(cert_file, "rb") as fh:
            old_cert = _x509.load_pem_x509_certificate(fh.read())
    except (IOError, OSError, ValueError) as exc:
        click.echo("ERROR: Cannot read certificate: {}".format(exc), err=True)
        sys.exit(1)

    now = _datetime.utcnow()
    days_remaining = (old_cert.not_valid_after - now).days
    if old_cert.not_valid_after > now and not force:
        click.echo(
            "Certificate is still valid ({} day(s) remaining).".format(days_remaining)
        )
        if not click.confirm("Revoke and renew anyway?"):
            sys.exit(0)

    try:
        cert_path, key_path = renew_cert(
            ca_dir,
            cert_file,
            days=days,
            reuse_key=reuse_key,
        )
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)
    except (IOError, OSError) as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    click.echo("Certificate renewed:")
    click.echo("  Certificate : {}".format(cert_path))
    click.echo("  Private key : {}  ({})".format(
        key_path, "reused" if reuse_key else "new, mode 0600"
    ))
    fullchain_path = cert_path.replace("-cert.pem", "-fullchain.pem")
    if os.path.isfile(fullchain_path):
        click.echo("  Full chain  : {}".format(fullchain_path))


@cert_group.command("list")
@click.option("--ca", "ca_dir", required=True, metavar="CA_DIR",
              help="Path to the CA directory.")
@click.option("--revoked", "show_revoked", is_flag=True,
              help="Show only revoked certificates.")
@click.pass_context
def cert_list(ctx, ca_dir, show_revoked):
    """
    List certificates issued by the CA in CA_DIR.

    \b
    Examples:
        crabctl cert list --ca ./my-ca
        crabctl cert list --ca ./my-ca --revoked
        crabctl --output-format json cert list --ca ./my-ca
    """
    try:
        records = list_issued(ca_dir)
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    if show_revoked:
        records = [r for r in records if r.get("revoked")]

    output_json = (ctx.obj or {}).get("output_format", "text") == "json"
    if output_json:
        click.echo(json.dumps(records, indent=2))
        return

    if not records:
        click.echo("No certificates issued yet." if not show_revoked
                   else "No revoked certificates.")
        return

    for rec in records:
        status = "REVOKED ({})".format(rec.get("revoke_reason", "?")) \
            if rec.get("revoked") else "valid"
        click.echo("  #{:<4}  {:<35}  {}  {}  [{}]".format(
            rec["serial"],
            rec["cn"][:35],
            rec["issued_at"][:10],
            rec["expires_at"][:10],
            status,
        ))

    click.echo("\nTotal: {}  Revoked: {}".format(
        len(records),
        sum(1 for r in records if r.get("revoked")),
    ))


if __name__ == "__main__":
    main()
