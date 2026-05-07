"""
bounty.fingerprint.tls — Technology / security detections from TLS info.

Pure function (no I/O).  Reads the TLSInfo captured by http_probe.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from bounty.models import Asset, FingerprintResult, ProbeResult

# ── Helpers ────────────────────────────────────────────────────────────────

_SAN_RE = re.compile(r"DNS:([^\s,]+)")
_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in (_DATE_FMT, "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def parse_tls(
    probe_result: ProbeResult,
    asset: Asset,
) -> tuple[list[FingerprintResult], list[str]]:
    """Analyse TLS metadata for security signals and extra hostnames.

    Args:
        probe_result: HTTP probe result containing a ``tls`` field.
        asset: The asset being fingerprinted (used for domain scoping).

    Returns:
        A 2-tuple ``(fingerprints, additional_hostnames)`` where
        ``additional_hostnames`` are SAN DNS values scoped to the asset's
        parent domain.
    """
    tls = probe_result.tls
    if tls is None:
        return [], []

    results: list[FingerprintResult] = []
    additional_hostnames: list[str] = []

    issuer = (tls.issuer or "").lower()
    subject = (tls.subject or "").lower()
    protocol = (tls.protocol or "").strip()
    not_after_raw = tls.not_after

    # ── Self-signed: issuer == subject — mathematically exact → DEFINITIVE ──
    if issuer and subject and issuer == subject:
        results.append(
            FingerprintResult(
                tech="self-signed-cert",
                category="other",
                confidence="definitive",
                evidence=f"tls:issuer-equals-subject={tls.issuer or ''}",
            )
        )

    # ── Let's Encrypt issuer — specific CA strings → STRONG ───────────────
    if "let's encrypt" in issuer or "letsencrypt" in issuer or "r3" in issuer or "e1" in issuer:
        results.append(
            FingerprintResult(
                tech="lets-encrypt",
                category="other",
                confidence="strong",
                evidence=f"tls:issuer={tls.issuer or ''}",
            )
        )

    # ── Legacy TLS protocol — explicit version string → DEFINITIVE ────────
    if protocol and any(p in protocol for p in _LEGACY_PROTOCOLS):
        results.append(
            FingerprintResult(
                tech="legacy-tls",
                category="other",
                confidence="definitive",
                evidence=f"tls:protocol={protocol}",
            )
        )

    # ── Certificate expiry — factual time comparison ───────────────────────
    now = datetime.now(tz=timezone.utc)
    not_after = _parse_date(not_after_raw)
    if not_after:
        delta_days = (not_after - now).days
        if delta_days < 0:
            results.append(
                FingerprintResult(
                    tech="cert-expired",
                    category="other",
                    confidence="definitive",
                    evidence=f"tls:cert-expired={not_after_raw}",
                )
            )
        elif delta_days <= 7:
            results.append(
                FingerprintResult(
                    tech="cert-expiring-soon",
                    category="other",
                    confidence="strong",
                    evidence=f"tls:cert-expires-in-{delta_days}d={not_after_raw}",
                )
            )

    # ── SAN hostname extraction ───────────────────────────────────────────
    # TLSInfo doesn't expose SANs directly; try to extract from subject string
    # (some implementations include them) and from cipher/protocol fields.
    # In practice, SAN data would come from a dedicated TLS library; here we
    # parse whatever textual SAN data is embedded in the subject / issuer.
    for field in (tls.issuer or "", tls.subject or "", tls.cipher or ""):
        for san_match in _SAN_RE.finditer(field):
            hostname = san_match.group(1).rstrip(".")
            if _is_same_domain(hostname, asset.host):
                additional_hostnames.append(hostname)

    return results, list(dict.fromkeys(additional_hostnames))


def _is_same_domain(hostname: str, asset_host: str) -> bool:
    """Return True if hostname shares the root domain with asset_host."""
    # Compute root domain (last two labels)
    def _root(h: str) -> str:
        parts = h.lower().rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h.lower()

    return _root(hostname) == _root(asset_host) and hostname != asset_host

