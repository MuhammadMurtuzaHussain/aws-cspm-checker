"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import __version__, report
from .checks import all_checks, execute
from .context import Context
from .model import SEV_RANK
from .runner import AwsError, AwsRunner, FixtureRunner

DEMO_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "demo-account.json"
FORMATS = ("console", "json", "md", "html")
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INCOMPLETE = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-posture-check",
        description="Read-only AWS security posture checker: ten common misconfigurations via the AWS CLI.")
    p.add_argument("--profile", help="AWS CLI profile to use")
    p.add_argument("--region", help="default region for global/identity calls (default: CLI config)")
    p.add_argument("--regions", help="comma-separated regions to scan (default: all enabled regions)")
    p.add_argument("--checks", help="comma-separated check IDs to run (default: all)")
    p.add_argument("--skip", help="comma-separated check IDs to skip")
    p.add_argument("--format", default="console", help=f"comma-separated: {', '.join(FORMATS)}")
    p.add_argument("--output-dir", default="reports", help="where json/md/html reports are written")
    p.add_argument("--fail-on", default="high", choices=[*(s.lower() for s in SEV_RANK), "none"],
                   help="exit 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--max-key-age", type=int, default=90, help="IAM access key max age in days")
    p.add_argument("--demo", action="store_true", help="scan a bundled fictional account; no AWS access needed")
    p.add_argument("--fixtures", help="scan canned CLI output from a JSON file (testing)")
    p.add_argument("--list-checks", action="store_true", help="list the ten checks and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _split(value: Optional[str]) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    checks = all_checks()

    if args.list_checks:
        for meta, _ in checks:
            print(f"{meta.id:<8} {meta.severity:<9} {meta.title}")
        return EXIT_OK

    formats = _split(args.format)
    bad = [f for f in formats if f not in FORMATS]
    wanted, skipped = set(_split(args.checks)), set(_split(args.skip))
    known = {m.id for m, _ in checks}
    if bad or (wanted | skipped) - known:
        print(f"error: unknown format(s) {bad} or check id(s) {sorted((wanted | skipped) - known)}",
              file=sys.stderr)
        return EXIT_USAGE

    fixture_path = DEMO_FIXTURE if args.demo else (Path(args.fixtures) if args.fixtures else None)
    demo = fixture_path is not None
    now = None
    if demo:
        data = json.loads(fixture_path.read_text())
        runner = FixtureRunner(data["responses"])
        if "now" in data.get("meta", {}):
            now = datetime.fromisoformat(data["meta"]["now"]).astimezone(timezone.utc)
    else:
        runner = AwsRunner(profile=args.profile, default_region=args.region,
                           aws_bin=os.environ.get("CSPM_AWS_BIN", "aws"))

    ctx = Context(runner, regions=_split(args.regions) or None,
                  max_key_age_days=args.max_key_age, now=now)
    try:
        account = ctx.account_id()
    except AwsError as exc:
        print(f"error: cannot identify the caller ({exc}). Check your credentials.", file=sys.stderr)
        return EXIT_USAGE

    selected = [(m, f) for m, f in checks if (not wanted or m.id in wanted) and m.id not in skipped]
    results = [execute(m, f, ctx) for m, f in selected]
    meta = {"account": account, "generated": ctx.now.strftime("%Y-%m-%d %H:%M UTC"),
            "version": __version__, "regions": ctx.regions(), "demo": demo}

    stamp = ctx.now.strftime("%Y%m%d-%H%M%S")
    written = []
    for fmt in formats:
        if fmt == "console":
            colour = sys.stdout.isatty() and "NO_COLOR" not in os.environ
            print(report.to_console(results, meta, colour))
            continue
        renderer = {"json": report.to_json, "md": report.to_markdown, "html": report.to_html}[fmt]
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"aws-posture-{account}-{stamp}.{fmt}"
        path.write_text(renderer(results, meta), encoding="utf-8")
        written.append(str(path))
    for path in written:
        print(f"wrote {path}", file=sys.stderr)

    if args.fail_on != "none":
        threshold = SEV_RANK[args.fail_on.upper()]
        if any(SEV_RANK[f.severity] >= threshold for r in results for f in r.findings):
            return EXIT_FINDINGS
    return EXIT_INCOMPLETE if any(r.status == "ERROR" for r in results) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
