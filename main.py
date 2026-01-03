from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from cli_parser import build_parser
from github_advisory_client import GitHubAdvisoryClient


def cmd_fetch_advisories(args: argparse.Namespace) -> int:
    # Main owns env parsing and injects configuration into the client.
    token = os.getenv("GITHUB_TOKEN") or os.getenv("github_token")
    api_base_url = os.getenv("GITHUB_API_BASE_URL") or "https://api.github.com"
    api_version = os.getenv("GITHUB_API_VERSION") or "2022-11-28"
    user_agent = os.getenv("GITHUB_USER_AGENT") or "dataset-generator/0.1"
    try:
        timeout_s = int(os.getenv("GITHUB_TIMEOUT_S") or "30")
        sleep_s = float(os.getenv("GITHUB_API_SLEEP_S") or "0.0")
    except ValueError:
        print("Invalid env var: expected GITHUB_TIMEOUT_S=int and GITHUB_API_SLEEP_S=float", file=sys.stderr)
        return 2

    if not token:
        print("Warning: GITHUB_TOKEN not set; requests may be rate-limited.", file=sys.stderr)

    client = GitHubAdvisoryClient(
        token=token,
        api_base_url=api_base_url,
        api_version=api_version,
        user_agent=user_agent,
        request_timeout_s=timeout_s,
    )

    items: List[Dict[str, Any]] = list(
        client.iter_advisories(
            ecosystem=args.ecosystem,
            severity=args.severity,
            advisory_type=args.advisory_type,
            per_page=args.per_page,
            max_pages=args.max_pages,
            sleep_s=sleep_s,
        )
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        print(f"Wrote {len(items)} advisories to {args.out}")
    else:
        print(json.dumps(items, ensure_ascii=False, indent=2))

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.cmd:
        parser.print_help()
        return 2

    if args.cmd == "fetch-advisories":
        return cmd_fetch_advisories(args)

    parser.error(f"Unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

