from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from cli_parser import build_parser
from constants import DEFAULT_GITHUB_API, DEFAULT_GITHUB_API_VERSION, DEFAULT_GITHUB_USER_AGENT, DEFAULT_GITHUB_TIMEOUT_S
from github_advisory_client import GitHubAdvisoryClient


def fetch_advisories(args: argparse.Namespace) -> int:

    client = GitHubAdvisoryClient(
        token=os.getenv("GITHUB_TOKEN") or os.getenv("github_token"),
        api_base_url=os.getenv("GITHUB_API_BASE_URL") or DEFAULT_GITHUB_API,    
        api_version=os.getenv("GITHUB_API_VERSION") or DEFAULT_GITHUB_API_VERSION,
        user_agent=os.getenv("GITHUB_USER_AGENT") or DEFAULT_GITHUB_USER_AGENT,
        request_timeout_s=int(os.getenv("GITHUB_TIMEOUT_S") or DEFAULT_GITHUB_TIMEOUT_S),
    )

    items: List[Dict[str, Any]] = list(
        client.iter_advisories(
            ecosystem=args.ecosystem,
            severity=args.severity,
            advisory_type=args.advisory_type,
            per_page=args.per_page,
            max_pages=args.max_pages,
            sleep_s=float(os.getenv("GITHUB_API_SLEEP_S") or "0.0"),
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
    fetch_advisories(args)


if __name__ == "__main__":
    raise SystemExit(main())

