"""
Deterministic scanner dispatcher.
Routes each file to the correct rule set and returns a unified ScanResult.
"""
import logging
from app.scanner.schema import Finding, ScanResult
from app.scanner.filters import FileType, classify
from app.scanner.rules import terraform, kubernetes, dockerfile, github_actions

logger = logging.getLogger(__name__)

_SCANNERS = {
    FileType.terraform: terraform.scan,
    FileType.kubernetes: kubernetes.scan,
    FileType.dockerfile: dockerfile.scan,
    FileType.github_actions: github_actions.scan,
}


def run_deterministic(files: dict[str, str]) -> ScanResult:
    """
    files: {filename -> raw content}
    Returns ScanResult with all findings normalised.
    """
    all_findings: list[Finding] = []
    scanned: list[str] = []

    for filename, content in files.items():
        ftype = classify(filename)
        scanner = _SCANNERS.get(ftype)
        if scanner is None:
            logger.debug("No scanner for %s (type=%s), skipping", filename, ftype)
            continue

        scanned.append(filename)
        try:
            findings = scanner(filename, content)
            all_findings.extend(findings)
            logger.info("%s → %d finding(s) [%s]", filename, len(findings), ftype)
        except Exception:
            logger.exception("Deterministic scanner failed for %s", filename)

    return ScanResult(findings=all_findings, scanned_files=scanned)
