"""
bounty.detect.mail.mail_config — Mail configuration detections (SPF/DMARC/DKIM).

Uses dnspython to query TXT/MX records.  All detections are de-duplicated per
apex domain via ``ctx.claim_apex("mail", apex)`` so they run only once even
when the scan targets many subdomains of the same domain.

Detections:
- SpfMissing    — no SPF TXT record at the apex  (severity 300)
- SpfWeak       — SPF exists but ends with +all or ?all  (severity 500)
- DmarcMissing  — no _dmarc TXT record  (severity 400)
- DmarcWeak     — DMARC record with p=none  (severity 300)
- DkimNotFound  — none of the common DKIM selectors found  (severity 200)
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = [
    "SpfMissing",
    "SpfWeak",
    "DmarcMissing",
    "DmarcWeak",
    "DkimNotFound",
]

_DKIM_SELECTORS = ("default", "google", "k1", "selector1", "selector2", "mail")

_DEDUP_CATEGORY = "mail"


# ---------------------------------------------------------------------------
# Apex domain helper
# ---------------------------------------------------------------------------

def _apex_domain(host: str) -> str:
    """Return the apex (registered) domain for *host*.

    Uses a simple heuristic: keeps the last two labels, or three labels when
    the second-to-last label is short (co, org, com with a country code).
    """
    host = host.split(":")[0].rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Common 2-part ccTLD suffixes (co.uk, org.uk, com.au, …)
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_apex_or_www(host: str, apex: str) -> bool:
    h = host.split(":")[0].rstrip(".")
    return h == apex or h == f"www.{apex}"


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

async def _get_txt_records(name: str) -> list[str]:
    """Return a list of decoded TXT record strings for *name*."""
    try:
        answers = await dns.asyncresolver.resolve(name, "TXT")
        result: list[str] = []
        for rdata in answers:
            # Each rdata may have multiple strings; join them.
            parts: list[str] = []
            for s in rdata.strings:
                parts.append(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s))
            result.append("".join(parts))
        return result
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []


async def _spf_record(apex: str) -> str | None:
    """Return the SPF TXT record string for *apex*, or None if not found."""
    txts = await _get_txt_records(apex)
    for txt in txts:
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


async def _dmarc_record(apex: str) -> str | None:
    """Return the DMARC TXT record string, or None."""
    txts = await _get_txt_records(f"_dmarc.{apex}")
    for txt in txts:
        if "v=dmarc1" in txt.lower():
            return txt
    return None


async def _any_dkim_found(apex: str) -> bool:
    """Return True if any common DKIM selector TXT record exists."""
    for selector in _DKIM_SELECTORS:
        name = f"{selector}._domainkey.{apex}"
        txts = await _get_txt_records(name)
        if txts:
            return True
    return False


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

class _MailDetectionBase(Detection):
    """Shared applicable_to: run only on apex / www.apex assets, once per apex."""

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        apex = _apex_domain(asset.host)
        return _is_apex_or_www(asset.host, apex)


class SpfMissing(_MailDetectionBase):
    """No SPF TXT record found for the apex domain."""

    id = "mail.spf_missing"
    name = "SPF Record Missing"
    category = "mail_misconfiguration"
    severity_default = 300
    cwe = "CWE-183"
    tags = ("mail", "spf", "email-security")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        apex = _apex_domain(asset.host)
        if not ctx.claim_apex(_DEDUP_CATEGORY + ".spf_missing", apex):
            return
        spf = await _spf_record(apex)
        if spf is not None:
            return
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{apex}",
            title=f"SPF record missing for {apex}",
            category=self.category,
            severity=self.severity_default,
            url=asset.url,
            path="",
            description=(
                f"No SPF TXT record was found for '{apex}'.  Without SPF, any "
                "mail server can send email purporting to be from this domain, "
                "enabling phishing and spam campaigns."
            ),
            remediation=(
                f"Add a TXT record at '{apex}' such as: "
                f"'v=spf1 include:_spf.yourprovider.com ~all'"
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class SpfWeak(_MailDetectionBase):
    """SPF record uses +all or ?all — effectively permits all senders."""

    id = "mail.spf_weak"
    name = "Weak SPF Record (+all / ?all)"
    category = "mail_misconfiguration"
    severity_default = 500
    cwe = "CWE-183"
    tags = ("mail", "spf", "email-security")

    _WEAK_RE = re.compile(r"[+?]all\b", re.IGNORECASE)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        apex = _apex_domain(asset.host)
        if not ctx.claim_apex(_DEDUP_CATEGORY + ".spf_weak", apex):
            return
        spf = await _spf_record(apex)
        if spf is None:
            return
        if not self._WEAK_RE.search(spf):
            return
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{apex}",
            title=f"Weak SPF record for {apex} ({spf[:80]})",
            category=self.category,
            severity=self.severity_default,
            url=asset.url,
            path="",
            description=(
                f"The SPF record for '{apex}' ends with '+all' or '?all', "
                "which permits any host to send email from this domain.  "
                "This undermines SPF enforcement entirely."
            ),
            remediation=(
                "Replace '+all' or '?all' with '-all' (hard fail) or '~all' "
                "(soft fail) after listing all legitimate sending sources."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class DmarcMissing(_MailDetectionBase):
    """No DMARC TXT record at _dmarc.<apex>."""

    id = "mail.dmarc_missing"
    name = "DMARC Record Missing"
    category = "mail_misconfiguration"
    severity_default = 400
    cwe = "CWE-183"
    tags = ("mail", "dmarc", "email-security")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        apex = _apex_domain(asset.host)
        if not ctx.claim_apex(_DEDUP_CATEGORY + ".dmarc_missing", apex):
            return
        dmarc = await _dmarc_record(apex)
        if dmarc is not None:
            return
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{apex}",
            title=f"DMARC record missing for {apex}",
            category=self.category,
            severity=self.severity_default,
            url=asset.url,
            path="",
            description=(
                f"No DMARC TXT record was found at '_dmarc.{apex}'.  "
                "Without DMARC, receiving mail servers have no policy on how "
                "to handle SPF/DKIM failures, enabling domain impersonation."
            ),
            remediation=(
                f"Add a TXT record at '_dmarc.{apex}' such as: "
                "'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'"
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class DmarcWeak(_MailDetectionBase):
    """DMARC record has policy p=none — no enforcement."""

    id = "mail.dmarc_weak"
    name = "Weak DMARC Policy (p=none)"
    category = "mail_misconfiguration"
    severity_default = 300
    cwe = "CWE-183"
    tags = ("mail", "dmarc", "email-security")

    _NONE_RE = re.compile(r"\bp=none\b", re.IGNORECASE)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        apex = _apex_domain(asset.host)
        if not ctx.claim_apex(_DEDUP_CATEGORY + ".dmarc_weak", apex):
            return
        dmarc = await _dmarc_record(apex)
        if dmarc is None:
            return
        if not self._NONE_RE.search(dmarc):
            return
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{apex}",
            title=f"Weak DMARC policy (p=none) for {apex}",
            category=self.category,
            severity=self.severity_default,
            url=asset.url,
            path="",
            description=(
                f"The DMARC record for '{apex}' specifies p=none, which means "
                "no action is taken when messages fail DMARC checks.  "
                "This is a monitor-only mode and provides no protection "
                "against spoofing."
            ),
            remediation=(
                "Upgrade the DMARC policy from p=none to p=quarantine or "
                "p=reject after reviewing the DMARC aggregate reports."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class DkimNotFound(_MailDetectionBase):
    """No DKIM selector TXT record found for common selectors."""

    id = "mail.dkim_not_found"
    name = "DKIM Not Configured (Common Selectors Missing)"
    category = "mail_misconfiguration"
    severity_default = 200
    cwe = "CWE-183"
    tags = ("mail", "dkim", "email-security")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        apex = _apex_domain(asset.host)
        if not ctx.claim_apex(_DEDUP_CATEGORY + ".dkim_not_found", apex):
            return
        found = await _any_dkim_found(apex)
        if found:
            return
        selectors_str = ", ".join(_DKIM_SELECTORS)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{apex}",
            title=f"No DKIM record found for {apex} (checked: {selectors_str})",
            category=self.category,
            severity=self.severity_default,
            url=asset.url,
            path="",
            description=(
                f"None of the common DKIM selectors ({selectors_str}) were "
                f"found for '{apex}'.  Without DKIM, emails cannot be "
                "cryptographically verified, making it easier to spoof "
                "the domain."
            ),
            remediation=(
                "Configure DKIM with your email provider and publish the "
                "public key as a TXT record at '<selector>._domainkey.<domain>'."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )





