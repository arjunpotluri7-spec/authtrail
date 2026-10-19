"""Command-line interface: ``authtrail analyze | rules list | rules show | validate-config``."""

import argparse
import contextlib
import os
import sys
import textwrap
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from authtrail import __version__
from authtrail.analyzer import analyze
from authtrail.config import Config, load_config
from authtrail.errors import AuthtrailError, InputError
from authtrail.logsetup import get_logger, setup_logging
from authtrail.models import SEVERITY_NAMES, Severity
from authtrail.parsers import FORMATS
from authtrail.render import render_json, render_markdown, render_table
from authtrail.rules import RULE_TYPES, Rule, apply_overrides, load_rules
from authtrail.timeutil import parse_timestamp

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

log = get_logger("cli")

EPILOG = """\
exit codes:
  0  ran successfully and nothing reached the --fail-on severity
  1  at least one alert or story reached the --fail-on severity
  2  usage, configuration, rule, or input error

examples:
  authtrail analyze samples/linux_auth.log samples/windows_security.json \\
      --config config.example.yaml --year 2026
  authtrail analyze /var/log/auth.log --format markdown --output report.md
  authtrail rules list
  authtrail validate-config config.example.yaml
"""


def _timestamp_arg(value: str) -> datetime:
    try:
        return parse_timestamp(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid timestamp {value!r}; use ISO 8601 such as 2026-10-14T02:00:00Z"
        ) from None


def _year_arg(value: str) -> int:
    try:
        year = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid year {value!r}") from None
    if not 1970 <= year <= 9999:
        raise argparse.ArgumentTypeError(f"year must be between 1970 and 9999, got {year}")
    return year


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--log-level",
        default="WARNING",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        type=str.upper,
        help="diagnostic log level written to stderr (default: WARNING)",
    )
    common.add_argument(
        "--log-format",
        default="text",
        choices=("text", "json"),
        help="diagnostic log format on stderr (default: text)",
    )
    rules_common = argparse.ArgumentParser(add_help=False)
    rules_common.add_argument(
        "--rules-dir", type=Path, help="extra directory of *.yaml rules to load after built-ins"
    )
    rules_common.add_argument(
        "--config", type=Path, help="YAML config (applies per-rule overrides and tuning)"
    )

    parser = argparse.ArgumentParser(
        prog="authtrail",
        description=(
            "Turn authentication logs (Linux auth.log/secure, macOS unified log NDJSON, "
            "Windows Security JSON) into explainable alerts and correlated attack stories. "
            "Read-only and offline: Authtrail only reads the files you name."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"authtrail {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    p_analyze = sub.add_parser(
        "analyze",
        parents=[common, rules_common],
        help="analyze log files and report alerts and attack stories",
        description="Parse log files, run detection rules, and correlate alerts into stories.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_analyze.add_argument("paths", nargs="+", type=Path, metavar="PATH", help="log file(s)")
    p_analyze.add_argument(
        "--format",
        default="table",
        choices=("table", "json", "markdown"),
        help="report format (default: table)",
    )
    p_analyze.add_argument(
        "--format-in",
        default="auto",
        choices=("auto", *FORMATS),
        help="input format for all PATHs (default: auto-detect per file)",
    )
    p_analyze.add_argument("-o", "--output", type=Path, help="write the report to this file")
    p_analyze.add_argument(
        "--force", action="store_true", help="allow --output to overwrite an existing file"
    )
    p_analyze.add_argument(
        "--fail-on",
        default="low",
        choices=(*SEVERITY_NAMES, "none"),
        help="exit 1 if any alert or story is at or above this severity (default: low; "
        "'none' always exits 0 on success)",
    )
    p_analyze.add_argument(
        "--year",
        type=_year_arg,
        default=None,
        help="year of the first line in BSD-syslog files, which carry no year "
        "(default: current UTC year; later lines roll over at Dec -> Jan)",
    )
    p_analyze.add_argument(
        "--since", type=_timestamp_arg, help="ignore events before this ISO 8601 time"
    )
    p_analyze.add_argument(
        "--until", type=_timestamp_arg, help="ignore events after this ISO 8601 time"
    )
    p_analyze.add_argument(
        "--stories",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="correlate alerts into attack stories (default: on)",
    )
    p_analyze.set_defaults(handler=cmd_analyze)

    p_rules = sub.add_parser("rules", help="list or show detection rules")
    rules_sub = p_rules.add_subparsers(dest="rules_command", metavar="ACTION")
    rules_sub.required = True
    p_list = rules_sub.add_parser(
        "list", parents=[common, rules_common], help="list all rules with severity and ATT&CK ids"
    )
    p_list.set_defaults(handler=cmd_rules_list)
    p_show = rules_sub.add_parser(
        "show", parents=[common, rules_common], help="show one rule in full, with parameters"
    )
    p_show.add_argument("rule_id", metavar="RULE_ID")
    p_show.set_defaults(handler=cmd_rules_show)

    p_validate = sub.add_parser(
        "validate-config",
        parents=[common],
        help="check a config file and report problems",
        description="Validate a YAML config, including per-rule overrides against loaded rules.",
    )
    p_validate.add_argument("file", type=Path, metavar="FILE")
    p_validate.add_argument(
        "--rules-dir", type=Path, help="also validate overrides for rules in this directory"
    )
    p_validate.set_defaults(handler=cmd_validate_config)
    return parser


def _load(args: argparse.Namespace) -> tuple[Config, list[Rule]]:
    config = load_config(args.config) if args.config else Config()
    rules = apply_overrides(load_rules(args.rules_dir), config)
    return config, rules


def _write_output(path: Path, content: str, force: bool) -> None:
    """Create the report with 0600 permissions; never follow a symlink or clobber silently."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    if not force:
        flags |= os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise InputError(f"{path}: output file already exists (use --force to overwrite)") from None
    except OSError as exc:
        raise InputError(f"{path}: cannot write output ({exc.strerror})") from None
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        # Windows has no fchmod before Python 3.13; the create mode above still applies.
        with contextlib.suppress(AttributeError, OSError):
            os.fchmod(handle.fileno(), 0o600)
        handle.write(content)


def cmd_analyze(args: argparse.Namespace) -> int:
    """``authtrail analyze``."""
    if args.output is not None:
        if args.output.exists() and not args.force:
            raise InputError(
                f"{args.output}: output file already exists (use --force to overwrite)"
            )
        out_resolved = args.output.resolve()
        for path in args.paths:
            if path.resolve() == out_resolved:
                raise InputError(f"{args.output}: output path is also an input; refusing")
    if args.since and args.until and args.since > args.until:
        raise InputError("--since is later than --until")
    config, rules = _load(args)
    year = args.year if args.year is not None else datetime.now(UTC).year
    report = analyze(
        args.paths,
        config,
        rules,
        year=year,
        format_in=args.format_in,
        since=args.since,
        until=args.until,
        stories=args.stories,
    )
    if args.format == "json":
        content = render_json(report)
    elif args.format == "markdown":
        content = render_markdown(report)
    else:
        use_color = args.output is None and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        content = render_table(report, color=use_color)
    if args.output is not None:
        _write_output(args.output, content, args.force)
        print(
            f"authtrail: wrote {args.format} report to {args.output} "
            f"({len(report.stories)} stories, {len(report.alerts)} alerts)",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(content)
    if args.fail_on == "none" or report.max_severity is None:
        return EXIT_OK
    return EXIT_FINDINGS if report.max_severity >= Severity.parse(args.fail_on) else EXIT_OK


def cmd_rules_list(args: argparse.Namespace) -> int:
    """``authtrail rules list``."""
    _, rules = _load(args)
    print(f"{'ID':<24}{'TYPE':<24}{'SEVERITY':<10}{'ATT&CK':<18}{'ENABLED':<9}SOURCE")
    for rule in rules:
        techniques = ",".join(t.id for t in rule.techniques)
        print(
            f"{rule.id:<24}{rule.type:<24}{rule.severity.label:<10}{techniques:<18}"
            f"{'yes' if rule.enabled else 'no':<9}{rule.source}"
        )
    return EXIT_OK


def cmd_rules_show(args: argparse.Namespace) -> int:
    """``authtrail rules show RULE_ID``."""
    _, rules = _load(args)
    rule = next((r for r in rules if r.id == args.rule_id), None)
    if rule is None:
        raise InputError(
            f"unknown rule id {args.rule_id!r}; known: {', '.join(r.id for r in rules)}"
        )
    print(f"{rule.id}: {rule.title}")
    print(f"  type:      {rule.type}")
    print(f"  severity:  {rule.severity.label}")
    print(f"  enabled:   {'yes' if rule.enabled else 'no'}")
    print(f"  source:    {rule.source}")
    print("  ATT&CK:")
    for technique in rule.techniques:
        print(f"    - {technique.id} {technique.name}")
    print("  description:")
    for line in textwrap.wrap(rule.description, width=90):
        print(f"    {line}")
    print("  parameters (effective value, then meaning):")
    for name, spec in RULE_TYPES[rule.type].items():
        value = rule.params[name]
        shown = str(value).lower() if isinstance(value, bool) else f"{value}"
        print(f"    {name} = {shown}")
        default = str(spec.default).lower() if isinstance(spec.default, bool) else spec.default
        for line in textwrap.wrap(f"{spec.help} (default {default})", width=84):
            print(f"        {line}")
    for reference in rule.references:
        print(f"  reference: {reference}")
    return EXIT_OK


def cmd_validate_config(args: argparse.Namespace) -> int:
    """``authtrail validate-config FILE``."""
    config = load_config(args.file)
    rules = apply_overrides(load_rules(args.rules_dir), config)
    enabled = sum(1 for r in rules if r.enabled)
    print(
        f"OK: {args.file} is valid ({len(config.ip_locations)} ip_locations, "
        f"{len(config.privileged_users)} privileged users, {len(config.rule_overrides)} rule "
        f"overrides, {enabled}/{len(rules)} rules enabled; business hours "
        f"{config.business_hours.describe()})"
    )
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on usage errors, 0 on --help/--version
        return int(exc.code) if isinstance(exc.code, int) else EXIT_ERROR
    setup_logging(args.log_level, args.log_format)
    try:
        return int(args.handler(args))
    except AuthtrailError as exc:
        log.debug("run failed", extra={"event": "error", "error": str(exc)})
        print(f"authtrail: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("authtrail: interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # Output piped into something like `head`; not an error worth a traceback.
        with contextlib.suppress(OSError):
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        return EXIT_OK
