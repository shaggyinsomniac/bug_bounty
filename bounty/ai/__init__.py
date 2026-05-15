"""
bounty.ai — LLM-powered decorative assistance features.

All outputs are SUGGESTED to the operator and never auto-applied.
Severity decisions, dedup actions, and report edits always require
explicit operator confirmation via the UI or CLI.
"""

from __future__ import annotations

from bounty.ai.client import AnthropicClient, get_client
from bounty.ai.dedup import find_duplicate_findings
from bounty.ai.report_polish import polish_report_body
from bounty.ai.severity_check import review_severity

__all__ = [
    "AnthropicClient",
    "get_client",
    "find_duplicate_findings",
    "polish_report_body",
    "review_severity",
]

