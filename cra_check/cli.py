# cra_check/cli.py
import argparse
import sys

from cra_check.checks import ALL_CHECKS
from cra_check.context import cleanup_scan_context, resolve_input
from cra_check.engine import run_checks
from cra_check.renderers.json_export import render_json
from cra_check.renderers.terminal import render_terminal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cra-check", description="Score a project against CRA Annex I requirements.")
    parser.add_argument("source", help="Path to an SBOM JSON file, or a GitHub/GitLab repo URL.")
    parser.add_argument("--json", dest="json_path", default=None, help="Write a JSON report to this path.")
    parser.add_argument(
        "--severity-threshold",
        choices=["pass", "warn", "fail"],
        default="pass",
        help="Minimum status to display in the terminal report (does not affect score or exit code).",
    )
    parser.add_argument("--offline", action="store_true", help="Skip checks that require network access (e.g. OSV.dev).")
    parser.add_argument("--fail-under", type=float, default=60.0, help="Exit with status 1 if the score is below this threshold.")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ctx = resolve_input(args.source, offline=args.offline)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        report = run_checks(ALL_CHECKS, ctx)
        render_terminal(report, severity_threshold=args.severity_threshold)

        if args.json_path:
            render_json(report, args.json_path)

        return 0 if report.score >= args.fail_under else 1
    finally:
        cleanup_scan_context(ctx)


if __name__ == "__main__":
    sys.exit(main())
