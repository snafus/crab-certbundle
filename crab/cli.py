"""
crabctl CLI

Commands:
  build       Build one or more output profiles from configured sources.
  validate    Validate one or more existing output directories.
  diff        Show changes between current directory and a new build.
  list        List certificates in a source, profile output, or directory.
  fetch-crls  Fetch or refresh CRLs for a profile.
  show-config Dump the resolved configuration (useful for debugging).

Global options:
  --config / -c    Path to config file (default: ./crab.yaml or /etc/crab/config.yaml)
  --verbose / -v   Increase log verbosity.
  --quiet / -q     Suppress all output except errors.
"""

import json
import logging
import os
import re
import sys
from typing import List, Optional

import click

from crab import __version__, __commit__
from crab.cert import parse_pem_file
from crab.config import load_config, ConfigError
from crab.sources import build_source
from crab.crl import CRLManager
from crab.output import OutputProfile, build_output
from crab.policy import PolicyEngine
from crab.pki import (
    init_ca, issue_cert, revoke_cert, generate_crl,
    show_ca_info, list_issued,
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
@click.pass_context
def main(ctx, config, verbose, quiet):
    """
    crabctl — OpenSSL CApath directory generator for research infrastructure.

    Combine IGTF trust anchors and public CA roots into hashed CApath directories
    for XRootD, dCache, curl/OpenSSL, and similar middleware.
    """
    ctx.ensure_object(dict)

    # Initial logging setup — may be refined after config is loaded.
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s: %(message)s",
    )

    # Record CLI flags so _apply_logging_config can honour them as overrides.
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet

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
@click.pass_context
def build(ctx, profiles, dry_run, no_crls, report):
    """
    Build output profile(s) from configured sources.

    If no PROFILE names are given, all profiles are built.

    Example:
        crabctl build grid server-auth
        crabctl build --dry-run
    """
    cfg = _load_config_or_exit(ctx)
    profile_names = list(profiles) or list(cfg.profiles.keys())

    total_errors = 0
    for pname in profile_names:
        if pname not in cfg.profiles:
            click.echo("ERROR: Unknown profile '{}'. Available: {}".format(
                pname, ", ".join(cfg.profiles.keys())
            ), err=True)
            total_errors += 1
            continue

        click.echo("Building profile '{}'...".format(pname))
        errors = _build_profile(cfg, pname, dry_run=dry_run, skip_crls=no_crls, do_report=report)
        total_errors += errors

    sys.exit(1 if total_errors else 0)


def _build_profile(cfg, profile_name, dry_run=False, skip_crls=False, do_report=False):
    # type: (...) -> int
    """Build one profile.  Returns number of errors."""
    profile_cfg = cfg.profiles[profile_name]
    source_names = profile_cfg.sources
    errors = 0

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
    click.echo("  Policy: {}/{} certificates accepted".format(len(accepted), len(all_certs)))

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
        click.echo("  CRLs: {} updated, {} failed, {} no URL".format(
            len(crl_result.updated), len(crl_result.failed), len(crl_result.missing)
        ))
        for err in crl_result.errors:
            click.echo("  CRL WARNING: {}".format(err), err=True)

    return errors


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@main.command()
@click.argument("targets", nargs=-1, metavar="[PROFILE_OR_DIR...]")
@click.option("--no-hash-check", is_flag=True, help="Skip hash filename verification.")
@click.option("--no-openssl", is_flag=True, help="Skip openssl verify smoke tests.")
@click.option("--json", "output_json", is_flag=True, help="Output JSON.")
@click.pass_context
def validate(ctx, targets, no_hash_check, no_openssl, output_json):
    """
    Validate one or more CApath directories.

    TARGETS may be profile names (from config) or raw directory paths.
    If no target is given, all configured profiles are validated.

    Exit code: 0 = OK, 1 = warnings, 2 = errors.
    """
    cfg = _load_config_or_exit(ctx)

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
@click.option("--json", "output_json", is_flag=True, help="Output JSON diff.")
@click.pass_context
def diff(ctx, profile_or_dir, old_dir, output_json):
    """
    Show changes between the current output directory and a fresh build.

    Useful for reviewing what a ``crabctl build`` would change before
    committing to it.

    Example:
        crabctl diff grid
        crabctl diff /etc/grid-security/certificates --old-dir /backup/certs
    """
    cfg = _load_config_or_exit(ctx)

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
@click.option("--json", "output_json", is_flag=True, help="Output JSON.")
@click.option("--expired", is_flag=True, help="Show only expired certificates.")
@click.pass_context
def list_cmd(ctx, target, source, output_json, expired):
    """
    List certificates in a profile, source, or directory.

    Examples:
        crabctl list grid
        crabctl list --source igtf-classic
        crabctl list /etc/grid-security/certificates
        crabctl list --json | jq '.[].subject'
    """
    cfg = _load_config_or_exit(ctx)
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
        click.echo("  Updated: {}  Failed: {}  No URL: {}".format(
            len(result.updated), len(result.failed), len(result.missing)
        ))
        for err in result.errors:
            click.echo("  {}".format(err), err=True)


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------

@main.command("refresh")
@click.argument("profiles", nargs=-1, metavar="[PROFILE...]")
@click.option("--dry-run", is_flag=True, help="Show what would be done without writing.")
@click.option("--report", is_flag=True, help="Print a source/policy report after building.")
@click.pass_context
def refresh(ctx, profiles, dry_run, report):
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

    If no PROFILE names are given, all profiles are refreshed.

    \b
    Examples:
        crabctl refresh
        crabctl refresh grid
        crabctl refresh --dry-run
    """
    cfg = _load_config_or_exit(ctx)
    profile_names = list(profiles) or list(cfg.profiles.keys())

    total_errors = 0
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
                click.echo("  CRLs: {} updated, {} failed, {} no URL".format(
                    len(crl_result.updated), len(crl_result.failed), len(crl_result.missing)
                ))
                for err in crl_result.errors:
                    click.echo("  CRL WARNING: {}".format(err), err=True)
            except Exception as exc:
                click.echo(
                    "  WARNING: CRL fetch failed for '{}': {} — continuing with build".format(
                        pname, exc
                    ),
                    err=True,
                )

        # Step 2: Full build; skip the internal CRL step since we just ran it.
        click.echo("Building profile '{}'...".format(pname))
        errors = _build_profile(
            cfg, pname, dry_run=dry_run, skip_crls=True, do_report=report
        )
        total_errors += errors

    sys.exit(1 if total_errors else 0)


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

    CLI flags (``--verbose`` / ``--quiet``) take priority over the config
    file level so that ad-hoc overrides always work as expected.
    """
    lc = cfg.logging_config

    # Resolve effective log level: CLI flags beat config file beats default.
    if ctx.obj.get("verbose"):
        level = logging.DEBUG
    elif ctx.obj.get("quiet"):
        level = logging.ERROR
    else:
        level_name = lc.get("level", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)

    logging.root.setLevel(level)
    for h in logging.root.handlers:
        h.setLevel(level)

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
            fh.setFormatter(
                logging.Formatter("%(asctime)s  %(levelname)s  %(name)s: %(message)s")
            )
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
@click.option("--json", "output_json", is_flag=True, help="Output JSON.")
def ca_show(ca_dir, output_json):
    """
    Display details about the CA in CA_DIR.

    \b
    Examples:
        crabctl ca show ./my-ca
        crabctl ca show ./my-ca --json
    """
    try:
        info = show_ca_info(ca_dir)
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    if output_json:
        click.echo(json.dumps(info, indent=2))
        return

    click.echo("CA directory  : {}".format(info["ca_dir"]))
    click.echo("Subject       : {}".format(info["subject"]))
    click.echo("Key type      : {}".format(info["key_type"]))
    click.echo("Valid from    : {}".format(info["not_before"]))
    click.echo("Valid until   : {}".format(info["not_after"]))
    click.echo("Fingerprint   : {}".format(info["fingerprint_sha256"]))
    click.echo("Issued certs  : {}  ({} revoked)".format(
        info["issued_count"], info["revoked_count"]
    ))
    click.echo("CRL present   : {}".format("yes" if info["crl_exists"] else "no"))


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
    click.echo("  CN          : {}".format(cn))
    click.echo("  Profile     : {}".format(profile))
    click.echo("  Valid for   : {} days".format(days))


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


@cert_group.command("list")
@click.option("--ca", "ca_dir", required=True, metavar="CA_DIR",
              help="Path to the CA directory.")
@click.option("--json", "output_json", is_flag=True, help="Output JSON.")
@click.option("--revoked", "show_revoked", is_flag=True,
              help="Show only revoked certificates.")
def cert_list(ca_dir, output_json, show_revoked):
    """
    List certificates issued by the CA in CA_DIR.

    \b
    Examples:
        crabctl cert list --ca ./my-ca
        crabctl cert list --ca ./my-ca --revoked
        crabctl cert list --ca ./my-ca --json
    """
    try:
        records = list_issued(ca_dir)
    except PKIError as exc:
        click.echo("ERROR: {}".format(exc), err=True)
        sys.exit(1)

    if show_revoked:
        records = [r for r in records if r.get("revoked")]

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
