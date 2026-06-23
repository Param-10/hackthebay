"""
Internal canonical finding format.
Every scanner (deterministic or AI) emits Finding objects.
"""
from typing import Literal
from pydantic import BaseModel


Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium"]


class Finding(BaseModel):
    file: str
    line: int | None = None
    severity: Severity
    rule: str
    explanation: str
    raw_evidence: str
    remediation: str = ""
    reference: str | None = None
    confidence: Confidence = "high"


class ScanResult(BaseModel):
    findings: list[Finding]
    scanned_files: list[str]
