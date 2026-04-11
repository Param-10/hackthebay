"""
Agent 2 – Fix Review & Verification Agent.

Input : original file content + finding + Agent 1's proposed patch
Output: structured verdict on whether the patch is valid, minimal, and safe
"""
import json
import logging
from typing import Literal
from pydantic import BaseModel
from google.genai import types as genai_types

from app.agents.client import get_client
from app.config import get_settings
from app.agents.reasoning import ReasonedFinding

logger = logging.getLogger(__name__)


# ── Output schema ──────────────────────────────────────────────────────────────

class PatchVerdict(BaseModel):
    rule: str
    file: str
    patch_valid: bool          # Does the patch actually fix the issue?
    patch_minimal: bool        # Does it touch only what's needed?
    patch_safe: bool           # No new vulnerabilities introduced?
    issues: list[str]          # Specific problems if any verdict is False
    final_recommendation: Literal["approve", "revise", "reject"]
    reviewer_note: str         # Short note to include in PR comment


class VerificationOutput(BaseModel):
    verdicts: list[PatchVerdict]
    all_clear: bool            # True only if every patch is approved


# ── Prompt construction ────────────────────────────────────────────────────────

_SYSTEM = """\
You are a senior security engineer acting as a second reviewer for AI-generated patches.
For each finding and its proposed patch, you must verify:
1. Validity   – Does the patch correctly fix the described vulnerability?
2. Minimality – Does the patch change only what is necessary?
3. Safety     – Does the patch introduce any new security issues or break functionality?

Be critical. Reject patches that are incomplete, overly broad, or introduce new risks.
Respond ONLY with valid JSON matching the schema. No markdown fences.
"""


def _build_user_message(
    original_content: str,
    findings: list[ReasonedFinding],
) -> str:
    parts = ["## Original file content\n```\n" + original_content[:4000] + "\n```\n"]
    parts.append("\n## Findings and proposed patches\n")
    parts.append(json.dumps(
        [f.model_dump() for f in findings],
        indent=2,
    ))
    return "\n".join(parts)


# ── Agent call ─────────────────────────────────────────────────────────────────

def run_verification_agent(
    original_content: str,
    findings: list[ReasonedFinding],
) -> VerificationOutput:
    if not findings:
        return VerificationOutput(verdicts=[], all_clear=True)

    client = get_client()
    model = get_settings().gemini_model
    user_msg = _build_user_message(original_content, findings)

    response = client.models.generate_content(
        model=model,
        contents=[
            genai_types.Content(role="user", parts=[genai_types.Part(text=user_msg)]),
        ],
        config=genai_types.GenerateContentConfig(
            system_instruction=_SYSTEM,
            response_mime_type="application/json",
            response_schema=VerificationOutput,
            temperature=0.1,
        ),
    )

    raw = response.text
    logger.debug("Agent 2 raw response: %s", raw[:500])
    return VerificationOutput.model_validate_json(raw)
