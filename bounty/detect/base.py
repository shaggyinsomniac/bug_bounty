"""
bounty.detect.base — Abstract base class and shared context for detections.

All detection modules subclass ``Detection`` and implement ``run()`` as an
async generator that yields ``FindingDraft`` objects for each confirmed
vulnerability.

Design constraints (enforced by convention):
- HTTP method is always GET / HEAD — never POST / PUT / DELETE / PATCH.
- Use ``ctx.probe_fn`` for all HTTP requests (rate-limiting is handled there).
- Yield a ``FindingDraft`` only after positive confirmation; "not found" = no yield.
- Raise ``DetectionError`` for tool/network failures; normal "not vulnerable"
  is expressed by simply returning without yielding.
- Call ``ctx.capture_evidence(url, probe_result)`` for every confirmed finding
  BEFORE yielding the draft.  The runner drains captured evidence and links it
  to the persisted Finding row.
"""

from __future__ import annotations

from abc import ABC
from collections.abc import AsyncGenerator, Callable, Awaitable
from dataclasses import dataclass, field
from typing import Any, ClassVar

import structlog

from bounty.config import Settings
from bounty.exceptions import DetectionError
from bounty.models import Asset, EvidencePackage, FindingDraft, FingerprintResult, ProbeResult

__all__ = ["Detection", "DetectionContext", "DetectionError"]


@dataclass
class DetectionContext:
    """Execution context passed to every ``Detection.run()`` call.

    Attributes:
        probe_fn: Async callable ``(url) -> ProbeResult``.  Handles rate
            limiting and timeouts.  Detections MUST use this for all HTTP.
        capture_fn: Async callable ``(url, probe_result, scan_id) ->
            EvidencePackage``.  Persists the evidence to the DB and returns
            a populated ``EvidencePackage``.
        scan_id: ULID of the current scan (for DB FK and evidence paths).
        settings: Application settings singleton.
        log: Pre-bound structlog logger (detection_id bound by runner).
    """

    probe_fn: Callable[[str], Awaitable[ProbeResult]]
    capture_fn: Callable[[str, ProbeResult, str], Awaitable[EvidencePackage]]
    scan_id: str
    settings: Settings
    log: structlog.stdlib.BoundLogger
    _soft_404_cache: dict[str, bool] = field(default_factory=dict)
    _captured_evidence: list[EvidencePackage] = field(default_factory=list)
    post_json_fn: Callable[[str, Any], Awaitable[ProbeResult]] | None = field(default=None)
    """Optional POST callable for detections that require it (e.g. GraphQL introspection).
    Signature: (url: str, json_body: Any) -> ProbeResult.
    None in contexts where POST is not configured.
    """

    async def capture_evidence(self, url: str, probe_result: ProbeResult) -> EvidencePackage:
        """Capture HTTP evidence and track it for linking to the next finding.

        The runner calls ``drain_evidence()`` after each yielded
        ``FindingDraft`` and links the returned packages to the persisted
        Finding row.
        """
        pkg = await self.capture_fn(url, probe_result, self.scan_id)
        self._captured_evidence.append(pkg)
        return pkg

    def drain_evidence(self) -> list[EvidencePackage]:
        """Return and clear the list of evidence captured since last drain."""
        ev = list(self._captured_evidence)
        self._captured_evidence.clear()
        return ev

    def is_soft_404_site(self, asset: Asset) -> bool:
        """Return True if this asset has a catch-all 200 route (soft-404 site)."""
        return self._soft_404_cache.get(asset.id or asset.host, False)

    def set_soft_404(self, asset: Asset, value: bool) -> None:
        """Record soft-404 status for an asset (called by runner before detection)."""
        self._soft_404_cache[asset.id or asset.host] = value


class Detection(ABC):
    """Abstract base for a single detection check.

    Subclasses define the ``id``, ``name``, ``category``, and
    ``severity_default`` class variables, and implement ``run()`` as an
    async generator.

    Example::

        class ExposedGitDirectory(Detection):
            id = "exposed.source_control.git"
            name = "Exposed .git directory"
            category = "exposed_source_control"
            severity_default = 700
            cwe = "CWE-540"

            async def run(self, asset, ctx) -> AsyncGenerator[FindingDraft, None]:
                url = f"{asset.url}/.git/HEAD"
                pr = await ctx.probe_fn(url)
                if not is_real_file_response(pr, [b"ref: refs/heads/"]):
                    return
                await ctx.capture_evidence(url, pr)
                yield FindingDraft(...)
    """

    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[str]
    severity_default: ClassVar[int]
    cwe: ClassVar[str | None] = None
    cve: ClassVar[str | None] = None
    tags: ClassVar[tuple[str, ...]] = ()

    def applicable_to(
        self,
        asset: Asset,
        fingerprints: list[FingerprintResult],
    ) -> bool:
        """Return True if this detection should run against this asset.

        Default implementation returns True (run on all assets).
        Subclasses override to gate by fingerprinted technology.

        HTTP requests MUST NOT be made here — only inspect in-memory state.
        """
        return True

    async def run(
        self,
        asset: Asset,
        ctx: DetectionContext,
    ) -> AsyncGenerator[FindingDraft, None]:
        """Execute the detection and yield confirmed findings.

        Subclasses MUST override this method as an async generator (using
        ``yield``).  The base implementation yields nothing.
        """
        return  # subclass must override
        yield  # pragma: no cover  # noqa: unreachable



