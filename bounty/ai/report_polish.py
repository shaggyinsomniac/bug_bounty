"""
bounty.ai.report_polish — LLM-powered report body rewriter.

Rewrites a bug report body for clarity and professionalism while keeping
the same structure and all factual content.

Output is DECORATIVE / SUGGESTED.  The operator must click "Accept Changes"
before the rewritten body is saved to the database.
"""

from __future__ import annotations

from bounty import get_logger
from bounty.ai.client import AnthropicClient, get_client

log = get_logger(__name__)

_SYSTEM = (
    "You are a professional technical writer that specialises in security "
    "vulnerability reports for bug bounty programs.  Rewrite the provided "
    "report body to be clearer, more professional, and better structured "
    "while preserving ALL technical facts, evidence details, and the same "
    "overall structure.  Do NOT add new vulnerability details.  "
    "Return ONLY the rewritten Markdown body with no preamble."
)

_PROMPT_TEMPLATE = """\
Please rewrite the following bug report body for clarity and professionalism.
Keep the same structure, all technical facts, and all evidence.
{template_hint}

--- BEGIN ORIGINAL REPORT BODY ---
{body}
--- END ORIGINAL REPORT BODY ---

Return ONLY the improved Markdown body.
"""


async def polish_report_body(
    body: str,
    template: str = "",
    client: AnthropicClient | None = None,
) -> str:
    """Rewrite a report body for clarity and professionalism.

    Args:
        body: The current Markdown report body.
        template: Optional template name (h1, bugcrowd, markdown) for context.
        client: Optional pre-built client (useful for testing).

    Returns:
        The rewritten Markdown body.  When AI is disabled, returns *body* unchanged.

    Note:
        This function NEVER saves the result.  The caller must explicitly save
        after operator confirmation.
    """
    if not body.strip():
        return body

    ai = client or get_client()

    template_hint = ""
    if template:
        template_hint = f"This report is formatted for the {template.upper()} platform."

    prompt = _PROMPT_TEMPLATE.format(
        body=body[:4000],  # Limit to avoid token overflow
        template_hint=template_hint,
    )

    try:
        polished = await ai.complete(_SYSTEM, prompt, max_tokens=2000)
        if not polished:
            return body
        return polished
    except Exception as exc:  # noqa: BLE001
        log.warning("ai_polish_error", error=str(exc))
        raise

