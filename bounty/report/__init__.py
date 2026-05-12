"""
bounty.report — Report generation from findings, evidence, and secrets.

All templates produce a Markdown string.
Raw secret values are NEVER included; only the ``secret_preview`` field
(first 8 chars + ellipsis) is used.
"""

from __future__ import annotations

from typing import Any, Literal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe(d: dict[str, Any], key: str, default: str = "") -> str:
    v = d.get(key)
    return str(v) if v is not None else default


def _preview_secrets(secrets: list[dict[str, Any]]) -> list[str]:
    """Preview lines for secrets — preview field only, never raw values."""
    lines: list[str] = []
    for s in secrets:
        provider = _safe(s, "provider", "unknown")
        preview = _safe(s, "secret_preview", "???…")
        status = _safe(s, "status", "unknown")
        identity = _safe(s, "identity")
        line = f"- `{provider}` — preview: `{preview}` — status: {status}"
        if identity:
            line += f" — identity: {identity}"
        lines.append(line)
    return lines


def _sev_rank(label: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(label, 0)


def _highest_severity(findings: list[dict[str, Any]]) -> str:
    return max(
        (_safe(f, "severity_label", "info") for f in findings),
        key=_sev_rank,
        default="info",
    )


# ---------------------------------------------------------------------------
# H1 format
# ---------------------------------------------------------------------------

def _h1_finding_block(
    f: dict[str, Any],
    evidence: list[dict[str, Any]],
    secrets: list[dict[str, Any]],
) -> str:
    title = _safe(f, "title", "Untitled")
    url = _safe(f, "url")
    desc = _safe(f, "description")
    rem = _safe(f, "remediation")
    dedup = _safe(f, "dedup_key")
    sev = _safe(f, "severity_label", "info").upper()

    parts: list[str] = [f"### {title}", ""]
    parts += [f"**Severity:** {sev}", f"**URL:** `{url}`" if url else "", ""]

    if desc:
        parts += ["**Description:**", desc, ""]

    parts += ["**Steps to Reproduce:**", ""]
    if url:
        parts.append(f"1. Send request to `{url}`")
    for ev in evidence:
        curl = _safe(ev, "curl_cmd")
        if curl:
            parts += [f"```bash\n{curl}\n```"]
        resp = _safe(ev, "response_raw")
        if resp:
            parts += [f"Response excerpt:\n```\n{resp[:500]}\n```"]
    parts.append("")

    if rem:
        parts += ["**Recommended Fix:**", rem, ""]

    if secrets:
        parts += ["**Supporting Material (Validated Credentials):**"]
        parts += _preview_secrets(secrets)
        parts.append("")

    parts += [f"*Reference: `{dedup}`*", ""]
    return "\n".join(p for p in parts if p is not None)


def _generate_h1(
    findings: list[dict[str, Any]],
    evidence_by_finding: dict[str, list[dict[str, Any]]],
    secrets_by_finding: dict[str, list[dict[str, Any]]],
) -> str:
    highest = _highest_severity(findings)

    lines: list[str] = ["# Vulnerability Report", ""]
    lines += ["## Summary", ""]
    for f in findings:
        lines.append(f"- **[{_safe(f, 'severity_label', 'info').upper()}]** {_safe(f, 'title', 'Untitled')}")
    lines += ["", f"## Severity", "", f"**{highest.upper()}**", ""]

    lines += ["## Steps to Reproduce", ""]
    for f in findings:
        fid = _safe(f, "id")
        lines.append(_h1_finding_block(f, evidence_by_finding.get(fid, []), secrets_by_finding.get(fid, [])))

    lines += ["## Impact", ""]
    for f in findings:
        desc = _safe(f, "description")
        if desc:
            lines.append(f"**{_safe(f, 'title', 'Untitled')}:** {desc}")
    lines += ["", "## Recommended Fix", ""]
    for f in findings:
        rem = _safe(f, "remediation")
        if rem:
            lines.append(f"**{_safe(f, 'title', 'Untitled')}:** {rem}")
    lines.append("")

    all_sec: list[dict[str, Any]] = []
    for f in findings:
        all_sec.extend(secrets_by_finding.get(_safe(f, "id"), []))
    if all_sec:
        lines += ["## Supporting Material", ""]
        lines += _preview_secrets(all_sec)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Bugcrowd format
# ---------------------------------------------------------------------------

def _bc_finding_block(
    f: dict[str, Any],
    evidence: list[dict[str, Any]],
    secrets: list[dict[str, Any]],
) -> str:
    title = _safe(f, "title", "Untitled")
    url = _safe(f, "url")
    desc = _safe(f, "description")
    rem = _safe(f, "remediation")
    dedup = _safe(f, "dedup_key")
    sev = _safe(f, "severity_label", "info").upper()
    cat = _safe(f, "category")

    parts: list[str] = [f"### {title}", ""]
    parts += [
        f"**VRT Category:** {cat}" if cat else "",
        f"**Severity:** {sev}",
        f"**Endpoint:** `{url}`" if url else "",
        "",
    ]

    if desc:
        parts += ["**Description:**", desc, ""]

    parts += ["**Proof of Concept:**", ""]
    if url:
        parts.append(f"Target: `{url}`")
    for ev in evidence:
        curl = _safe(ev, "curl_cmd")
        if curl:
            parts += [f"```bash\n{curl}\n```"]
        resp = _safe(ev, "response_raw")
        if resp:
            parts += [f"```\n{resp[:500]}\n```"]
    parts.append("")

    if desc:
        parts += ["**Impact:**", desc, ""]

    if rem:
        parts += ["**Suggested Fix:**", rem, ""]

    if secrets:
        parts += ["**Validated Credentials:**"]
        parts += _preview_secrets(secrets)
        parts.append("")

    parts += [f"*Ref: `{dedup}`*", ""]
    return "\n".join(p for p in parts)


def _generate_bugcrowd(
    findings: list[dict[str, Any]],
    evidence_by_finding: dict[str, list[dict[str, Any]]],
    secrets_by_finding: dict[str, list[dict[str, Any]]],
) -> str:
    highest = _highest_severity(findings)
    cats = list({_safe(f, "category") for f in findings if f.get("category")})

    lines: list[str] = ["# Bugcrowd Vulnerability Report", ""]
    lines += [
        f"**Severity:** {highest.upper()}",
        f"**VRT Category:** {', '.join(cats) if cats else 'Other'}",
        "",
        "## Description",
        "",
    ]
    for f in findings:
        desc = _safe(f, "description")
        if desc:
            lines.append(f"**{_safe(f, 'title', 'Untitled')}:** {desc}")
    lines.append("")

    for f in findings:
        fid = _safe(f, "id")
        lines.append(_bc_finding_block(f, evidence_by_finding.get(fid, []), secrets_by_finding.get(fid, [])))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Generic Markdown format
# ---------------------------------------------------------------------------

def _md_finding_block(
    f: dict[str, Any],
    evidence: list[dict[str, Any]],
    secrets: list[dict[str, Any]],
) -> str:
    title = _safe(f, "title", "Untitled")
    url = _safe(f, "url")
    desc = _safe(f, "description")
    rem = _safe(f, "remediation")
    dedup = _safe(f, "dedup_key")
    sev = _safe(f, "severity_label", "info").upper()
    cat = _safe(f, "category")

    parts: list[str] = [f"## {title}", ""]
    rows = [("Severity", sev), ("Category", cat), ("URL", f"`{url}`" if url else "")]
    parts += ["| Field | Value |", "|-------|-------|"]
    for k, v in rows:
        if v:
            parts.append(f"| {k} | {v} |")
    parts.append("")

    if desc:
        parts += ["### Description", "", desc, ""]
    if evidence:
        parts += ["### Evidence", ""]
        for ev in evidence:
            curl = _safe(ev, "curl_cmd")
            if curl:
                parts += [f"```bash\n{curl}\n```"]
            resp = _safe(ev, "response_raw")
            if resp:
                parts += [f"```\n{resp[:1000]}\n```"]
        parts.append("")
    if rem:
        parts += ["### Remediation", "", rem, ""]
    if secrets:
        parts += ["### Validated Credentials", ""]
        parts += _preview_secrets(secrets)
        parts.append("")

    parts += ["---", f"*Dedup key: `{dedup}`*", ""]
    return "\n".join(parts)


def _generate_markdown(
    findings: list[dict[str, Any]],
    evidence_by_finding: dict[str, list[dict[str, Any]]],
    secrets_by_finding: dict[str, list[dict[str, Any]]],
) -> str:
    lines: list[str] = [
        "# Security Report",
        "",
        f"**Total findings:** {len(findings)}",
        "",
        "---",
        "",
    ]
    for f in findings:
        fid = _safe(f, "id")
        lines.append(_md_finding_block(f, evidence_by_finding.get(fid, []), secrets_by_finding.get(fid, [])))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    template: Literal["h1", "bugcrowd", "markdown"],
    findings: list[dict[str, Any]],
    evidence_by_finding: dict[str, list[dict[str, Any]]],
    secrets_by_finding: dict[str, list[dict[str, Any]]],
) -> str:
    """Generate a Markdown report body.

    Args:
        template: Output format — ``"h1"``, ``"bugcrowd"``, or ``"markdown"``.
        findings: List of finding dicts (from DB rows).
        evidence_by_finding: Mapping finding_id → list of evidence dicts.
        secrets_by_finding: Mapping finding_id → list of secret-validation dicts.
            Secret raw values must NOT be stored here; use the ``secret_preview``
            field (first 8 chars + ellipsis).

    Returns:
        Markdown string suitable for storage in ``reports.body``.
    """
    if not findings:
        return "_No findings attached to this report._\n"
    if template == "h1":
        return _generate_h1(findings, evidence_by_finding, secrets_by_finding)
    if template == "bugcrowd":
        return _generate_bugcrowd(findings, evidence_by_finding, secrets_by_finding)
    return _generate_markdown(findings, evidence_by_finding, secrets_by_finding)

