from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Dataset generator (GitHub advisory fetcher)")
    # If no subcommand is provided, `main.py` will print help for nicer UX.
    sub = p.add_subparsers(dest="cmd")

    fetch = sub.add_parser("fetch-advisories", help="Fetch global security advisories from GitHub")
    fetch.add_argument("--ecosystem", default=None, help="Ecosystem filter (e.g. npm, pip, rubygems)")
    fetch.add_argument("--severity", default=None, help="Severity filter (e.g. low, medium, high, critical)")
    fetch.add_argument(
        "--type",
        dest="advisory_type",
        default=None,
        help='Advisory type filter (API param "type", e.g. reviewed/unreviewed/malware)',
    )
    fetch.add_argument("--per-page", type=int, default=100, help="Items per page (max 100)")
    fetch.add_argument("--max-pages", type=int, default=1, help="Safety limit; set higher for more data")
    fetch.add_argument("--out", default=None, help="Write results as JSON to this file; otherwise prints to stdout")

    return p


