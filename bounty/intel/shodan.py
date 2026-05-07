"""
bounty.intel.shodan — async Shodan API client with credit-guard and structured logging.

Usage::

    async with ShodanClient(settings.shodan_api_key) as client:
        remaining = await client.credits_remaining()
        results   = await client.search('http.title:"Index of /"', max_pages=1)
        host_info = await client.host("1.1.1.1")
"""

from __future__ import annotations

from typing import Any

import httpx

from bounty import get_logger
from bounty.config import get_settings

log = get_logger(__name__)

_BASE_URL = "https://api.shodan.io"
_TIMEOUT = 30.0


class ShodanError(RuntimeError):
    """Raised for Shodan API errors (auth failure, rate limit, credit exhaustion)."""


class ShodanClient:
    """Async Shodan REST API client.

    Args:
        api_key: Shodan API key.  Reads from ``settings.shodan_api_key`` if
                 not passed explicitly.

    Credit guard:
        ``search()`` and ``host()`` refuse to execute if
        ``credits_remaining()`` < ``settings.shodan_min_credits``.  This
        prevents accidentally draining credits in a loop.

    Usage::

        async with ShodanClient(api_key) as client:
            results = await client.search("ssl.cert.expired:true")
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "ShodanClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=True,
                headers={"Accept": "application/json"},
            )
        return self._http

    def _check_key(self) -> None:
        if not self._api_key:
            raise ShodanError(
                "SHODAN_API_KEY is not configured.  "
                "Set it in .env or as the SHODAN_API_KEY environment variable."
            )

    async def _guard_credits(self) -> int:
        """Fetch remaining credits and raise if below the configured minimum."""
        settings = get_settings()
        remaining = await self.credits_remaining()
        if remaining < settings.shodan_min_credits:
            raise ShodanError(
                f"Shodan query credits too low: {remaining} remaining, "
                f"minimum required is {settings.shodan_min_credits}.  "
                f"Lower SHODAN_MIN_CREDITS or purchase more credits."
            )
        return remaining

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def credits_remaining(self) -> int:
        """Return the number of remaining Shodan query credits.

        Calls ``/api-info``.  Does NOT consume credits.

        Returns:
            Integer count of remaining query credits.

        Raises:
            ShodanError: On authentication failure or API error.
        """
        self._check_key()
        resp = await self._client().get(
            f"{_BASE_URL}/api-info",
            params={"key": self._api_key},
        )
        if resp.status_code == 401:
            raise ShodanError("Shodan authentication failed — check SHODAN_API_KEY.")
        if resp.status_code != 200:
            raise ShodanError(f"Shodan /api-info returned HTTP {resp.status_code}.")
        data: dict[str, Any] = resp.json()
        credits: int = int(data.get("query_credits", 0))
        log.debug("shodan_credits_remaining", credits=credits)
        return credits

    async def search(self, query: str, max_pages: int = 1) -> list[dict[str, Any]]:
        """Run a Shodan host search and return a list of match dicts.

        Each page costs one query credit.  The credit guard is checked before
        any pages are fetched.

        Args:
            query:     Shodan search query string.
            max_pages: Maximum number of pages to fetch (100 results/page).

        Returns:
            List of host-match dicts (ip_str, port, hostnames, org, asn,
            http, ssl, product, data, …).

        Raises:
            ShodanError: Credit guard failed, auth error, or API error.
        """
        self._check_key()
        await self._guard_credits()

        results: list[dict[str, Any]] = []
        bound_log = log.bind(query=query, max_pages=max_pages)

        for page in range(1, max_pages + 1):
            bound_log.info("shodan_search_page", page=page)
            resp = await self._client().get(
                f"{_BASE_URL}/shodan/host/search",
                params={"key": self._api_key, "query": query, "page": page},
            )
            if resp.status_code == 401:
                raise ShodanError("Shodan authentication failed.")
            if resp.status_code == 402:
                raise ShodanError(
                    f"Shodan query credits exhausted on page {page}.  "
                    f"Fetched {len(results)} results before running out."
                )
            if resp.status_code != 200:
                raise ShodanError(
                    f"Shodan /shodan/host/search returned HTTP {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
            data: dict[str, Any] = resp.json()
            matches: list[dict[str, Any]] = data.get("matches", [])
            results.extend(matches)

            total: int = int(data.get("total", 0))
            bound_log.debug("shodan_page_done", page=page, page_results=len(matches), total=total)
            if len(results) >= total:
                break  # no more pages

        bound_log.info("shodan_search_done", total_results=len(results))
        return results

    async def host(self, ip: str) -> dict[str, Any]:
        """Fetch full host information for a single IP.

        Costs one query credit.  Returns an empty dict if the IP is not in
        the Shodan index (404).

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Full Shodan host dict, or ``{}`` if not found.

        Raises:
            ShodanError: Credit guard failed, auth error, or API error.
        """
        self._check_key()
        await self._guard_credits()

        log.info("shodan_host_lookup", ip=ip)
        resp = await self._client().get(
            f"{_BASE_URL}/shodan/host/{ip}",
            params={"key": self._api_key},
        )
        if resp.status_code == 404:
            log.debug("shodan_host_not_found", ip=ip)
            return {}
        if resp.status_code == 401:
            raise ShodanError("Shodan authentication failed.")
        if resp.status_code != 200:
            raise ShodanError(f"Shodan /shodan/host/{ip} returned HTTP {resp.status_code}.")
        return dict(resp.json())

