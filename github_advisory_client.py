"""
GitHub Security Advisory (Global Advisories) API client.

Docs: https://docs.github.com/en/rest/security-advisories?apiVersion=2022-11-28
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Mapping, Optional


@dataclass(frozen=True)
class GitHubAdvisoryClient:
    token: Optional[str] = None
    api_base_url: str = "https://api.github.com"
    api_version: str = "2022-11-28"
    user_agent: str = "dataset-generator/0.1"
    request_timeout_s: int = 30

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.api_version,
            "User-Agent": self.user_agent,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get_json(self, path: str, *, query: Optional[Mapping[str, Any]] = None) -> Any:
        url = self.api_base_url.rstrip("/") + "/" + path.lstrip("/")
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            url = url + "?" + urllib.parse.urlencode(q, doseq=True)

        req = urllib.request.Request(url=url, method="GET", headers=self._headers())

        try:
            with urllib.request.urlopen(req, timeout=self.request_timeout_s) as resp:
                raw = resp.read()
                charset = resp.headers.get_content_charset() or "utf-8"
                text = raw.decode(charset, errors="replace")
                return json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            msg = body or getattr(e, "reason", "") or "HTTP error"
            raise RuntimeError(f"GitHub API error {e.code} for {url}: {msg}") from e

    def list_advisories(
        self,
        *,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        advisory_type: Optional[str] = None,
        per_page: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        List a page of global security advisories.

        Endpoint: GET /advisories
        Docs: https://docs.github.com/en/rest/security-advisories?apiVersion=2022-11-28
        """
        data = self._get_json(
            "/advisories",
            query={
                "ecosystem": ecosystem,
                "severity": severity,
                "type": advisory_type,
                "per_page": per_page,
                "page": page,
            },
        )
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected response type for /advisories: {type(data)}")
        return [d for d in data if isinstance(d, dict)]

    def iter_advisories(
        self,
        *,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        advisory_type: Optional[str] = None,
        per_page: int = 100,
        max_pages: Optional[int] = None,
        sleep_s: float = 0.0,
    ) -> Iterator[Dict[str, Any]]:
        """
        Iterate advisories, page by page, until GitHub returns an empty list.
        """
        page = 1
        while True:
            if max_pages is not None and page > max_pages:
                return

            items = self.list_advisories(
                ecosystem=ecosystem,
                severity=severity,
                advisory_type=advisory_type,
                per_page=per_page,
                page=page,
            )
            if not items:
                return

            for item in items:
                yield item

            page += 1
            if sleep_s > 0:
                time.sleep(sleep_s)

