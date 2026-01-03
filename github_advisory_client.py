from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterator, Optional


@dataclass(frozen=True)
class GitHubAdvisoryClient:
    """Client for fetching advisories from GitHub's global security advisories API."""

    token: Optional[str]
    api_base_url: str
    api_version: str
    user_agent: str
    request_timeout_s: int

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for GitHub API requests."""
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.api_version,
            "User-Agent": self.user_agent,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _fetch_json(
        self, 
        path: str, 
        query_params: Optional[dict[str, Any]] = None
    ) -> Any:
        """Make a GET request to the GitHub API and return JSON response."""
        url = f"{self.api_base_url.rstrip('/')}/{path.lstrip('/')}"
        
        if query_params:
            # Filter out None values
            filtered_params = {k: v for k, v in query_params.items() if v is not None}
            if filtered_params:
                url = f"{url}?{urllib.parse.urlencode(filtered_params, doseq=True)}"

        request = urllib.request.Request(
            url=url, 
            method="GET", 
            headers=self._build_headers()
        )

        try:
            with urllib.request.urlopen(request, timeout=self.request_timeout_s) as response:
                content = response.read()
                encoding = response.headers.get_content_charset() or "utf-8"
                text = content.decode(encoding, errors="replace")
                return json.loads(text) if text else None
                
        except urllib.error.HTTPError as error:
            error_message = self._extract_error_message(error)
            raise RuntimeError(
                f"GitHub API request failed (HTTP {error.code}): {error_message}"
            ) from error

    @staticmethod
    def _extract_error_message(error: urllib.error.HTTPError) -> str:
        """Extract error message from HTTP error response."""
        try:
            return error.read().decode("utf-8", errors="replace")
        except Exception:
            return getattr(error, "reason", "Unknown error")

    def fetch_advisories(
        self,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        advisory_type: Optional[str] = None,
        per_page: int = 100,
        page: int = 1,
    ) -> list[dict[str, Any]]:
        """
        Fetch a single page of security advisories.
        
        Args:
            ecosystem: Filter by package ecosystem (e.g., 'pip', 'npm')
            severity: Filter by severity level (e.g., 'critical', 'high')
            advisory_type: Filter by type (e.g., 'malware', 'reviewed')
            per_page: Number of results per page (max 100)
            page: Page number to fetch
            
        Returns:
            List of advisory dictionaries
        """
        response = self._fetch_json(
            "/advisories",
            query_params={
                "ecosystem": ecosystem,
                "severity": severity,
                "type": advisory_type,
                "per_page": per_page,
                "page": page,
            },
        )
        
        if not isinstance(response, list):
            raise RuntimeError(
                f"Expected list response from API, got {type(response).__name__}"
            )
        
        return [item for item in response if isinstance(item, dict)]

    def iter_advisories(
        self,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        advisory_type: Optional[str] = None,
        per_page: int = 100,
        max_pages: Optional[int] = None,
        sleep_s: float = 0.0,
    ) -> Iterator[dict[str, Any]]:
        """
        Iterate through all advisories across multiple pages.
        
        Args:
            ecosystem: Filter by package ecosystem
            severity: Filter by severity level
            advisory_type: Filter by advisory type
            per_page: Number of results per page
            max_pages: Maximum number of pages to fetch (None for all)
            delay_seconds: Delay between requests to respect rate limits
            
        Yields:
            Individual advisory dictionaries
        """
        page = 1
        
        while max_pages is None or page <= max_pages:
            advisories = self.fetch_advisories(
                ecosystem=ecosystem,
                severity=severity,
                advisory_type=advisory_type,
                per_page=per_page,
                page=page,
            )
            
            if not advisories:
                break

            yield from advisories

            page += 1
            if sleep_s > 0:
                time.sleep(sleep_s)