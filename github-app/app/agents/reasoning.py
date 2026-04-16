"""
Agent 1 – Security & IaC Reasoning Agent.

Input : changed files + deterministic findings
Output: prioritised findings with risk context and proposed patches
"""
import json
import logging
from typing import Literal
from pydantic import BaseModel
from google.genai import types as genai_types

from app.agents.client import get_client
from app.config import get_settings
from app.scanner.schema import Finding

logger = logging.getLogger(__name__)


# ── Output schema ──────────────────────────────────────────────────────────────

class ReasonedFinding(BaseModel):
    file: str
    line: int | None
    severity: Literal["critical", "high", "medium", "low", "info"]
    rule: str
    explanation: str
    risk_context: str          # plain-language risk description for PR reviewer
    proposed_patch: str | None # diff or replacement snippet, null if not applicable
    patch_explanation: str | None


class ReasoningOutput(BaseModel):
    overall_risk: Literal["critical", "high", "medium", "low", "pass"]
    summary: str               # 2-3 sentence executive summary for PR description
    findings: list[ReasonedFinding]


# ── Prompt construction ────────────────────────────────────────────────────────

_SYSTEM = """\
You are an expert infrastructure security engineer reviewing pull request changes.
You will receive:
1. A list of changed infrastructure files with their full content.
2. A list of deterministic scan findings (may be empty).

Your job:
- Prioritise the findings by real-world exploitability and blast radius.
- For each finding, write a clear explanation in 1-2 sentences suitable for a developer.
- Write risk_context in this style: "Threat: ... Impact: ...".
- Where applicable, propose a minimal, correct patch (prefer unified diff snippets).
- Identify any additional issues the deterministic scanner may have missed.
- Provide an overall risk rating and a concise executive summary.
- Keep findings specific (file + line), avoid duplicates, and do not invent files.

Respond ONLY with valid JSON matching the schema provided. No markdown fences.
"""


def _build_user_message(files: dict[str, str], findings: list[Finding]) -> str:
    parts: list[str] = ["## Changed files\n"]
    for fname, content in files.items():
        parts.append(f"### {fname}\n```\n{content[:4000]}\n```\n")

    parts.append("\n## Deterministic findings\n")
    if findings:
        parts.append(json.dumps([f.model_dump() for f in findings], indent=2))
    else:
        parts.append("None")

    return "\n".join(parts)


# ── Agent call ─────────────────────────────────────────────────────────────────

def run_reasoning_agent(
    files: dict[str, str],
    findings: list[Finding],
) -> ReasoningOutput:
    client = get_client()
    model = get_settings().gemini_model
    user_msg = _build_user_message(files, findings)

    response = client.models.generate_content(
        model=model,
        contents=[
            genai_types.Content(role="user", parts=[genai_types.Part(text=user_msg)]),
        ],
        config=genai_types.GenerateContentConfig(
            system_instruction=_SYSTEM,
            response_mime_type="application/json",
            response_schema=ReasoningOutput,
            temperature=0.2,
        ),
    )

    raw = response.text
    logger.debug("Agent 1 raw response: %s", raw[:500])
    return ReasoningOutput.model_validate_json(raw)
