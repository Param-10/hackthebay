"""Strict, mechanically checked patch application for one-click fixes."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

import yaml

from app.scanner.deterministic import run_deterministic
from app.scanner.filters import FileType, classify
from app.scanner.rules.github_actions import _WorkflowLoader
from app.scanner.schema import Finding

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DOCKER_INSTRUCTION = re.compile(
    r"^(ADD|ARG|CMD|COPY|ENTRYPOINT|ENV|EXPOSE|FROM|HEALTHCHECK|LABEL|MAINTAINER|ONBUILD|RUN|SHELL|STOPSIGNAL|USER|VOLUME|WORKDIR)\b",
    re.IGNORECASE,
)
_ACTION_REFERENCE = re.compile(r"\buses:\s*([^\s@]+)@([^\s#]+)", re.IGNORECASE)
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


@dataclass
class PatchCheck:
    eligible: bool
    patched: str | None = None
    notes: list[str] = field(default_factory=list)


def deterministic_patch_for(finding: Finding, original: str) -> str | None:
    """Return a narrow trusted patch only where the safe replacement is unambiguous."""
    rule_id = finding.rule.split(":", 1)[0]
    replacements = {
        "K8S001": ("hostPID", "false"),
        "K8S002": ("hostNetwork", "false"),
        "K8S003": ("privileged", "false"),
    }
    replacement = replacements.get(rule_id)
    if replacement is None or finding.line is None:
        return None

    lines = original.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return None
    old_line = lines[finding.line - 1]
    key, safe_value = replacement
    match = re.match(
        rf"^(?P<prefix>\s*{re.escape(key)}\s*:\s*)(?P<value>true)(?P<suffix>\s*(?:#.*)?)$",
        old_line,
        re.IGNORECASE,
    )
    if match is None:
        return None
    new_line = f"{match.group('prefix')}{safe_value}{match.group('suffix')}"
    return (
        f"--- a/{finding.file}\n"
        f"+++ b/{finding.file}\n"
        f"@@ -{finding.line} +{finding.line} @@\n"
        f"-{old_line}\n"
        f"+{new_line}\n"
    )


def _diff_path(line: str) -> str:
    path = line[4:].split("\t", 1)[0].strip()
    return path[2:] if path.startswith(("a/", "b/")) else path


def apply_unified_diff(original: str, patch: str, expected_file: str) -> str | None:
    """Apply an exact unified diff; fuzzy or replacement-block patches are rejected."""
    if len(patch) > 100_000:
        return None
    lines = patch.splitlines()
    old_header = next((line for line in lines if line.startswith("--- ")), None)
    new_header = next((line for line in lines if line.startswith("+++ ")), None)
    if not old_header or not new_header:
        return None
    if _diff_path(old_header) != expected_file or _diff_path(new_header) != expected_file:
        return None

    source = original.splitlines()
    output: list[str] = []
    source_index = 0
    changed = False
    index = 0
    saw_hunk = False

    while index < len(lines):
        match = _HUNK.match(lines[index])
        if not match:
            index += 1
            continue
        saw_hunk = True
        old_start = int(match.group(1)) - 1
        old_count = int(match.group(2) or "1")
        new_count = int(match.group(4) or "1")
        if old_start < source_index or old_start > len(source):
            return None
        output.extend(source[source_index:old_start])
        cursor = old_start
        consumed = produced = 0
        index += 1

        while index < len(lines) and not _HUNK.match(lines[index]):
            raw = lines[index]
            if raw.startswith(("--- ", "+++ ")):
                return None
            if raw == "\\ No newline at end of file":
                index += 1
                continue
            if not raw or raw[0] not in " +-":
                return None
            marker, text = raw[0], raw[1:]
            if marker == " ":
                if cursor >= len(source) or source[cursor] != text:
                    return None
                output.append(text)
                cursor += 1
                consumed += 1
                produced += 1
            elif marker == "-":
                if cursor >= len(source) or source[cursor] != text:
                    return None
                cursor += 1
                consumed += 1
                changed = True
            else:
                output.append(text)
                produced += 1
                changed = True
            index += 1

        if consumed != old_count or produced != new_count:
            return None
        source_index = cursor

    if not saw_hunk or not changed:
        return None
    output.extend(source[source_index:])
    result = "\n".join(output)
    if original.endswith("\n"):
        result += "\n"
    return result


def _syntax_valid(filename: str, content: str) -> tuple[bool, str]:
    file_type = classify(filename, content)
    try:
        if file_type == FileType.github_actions:
            yaml.load(content, Loader=_WorkflowLoader)
            return True, "GitHub Actions YAML parsed"
        if file_type == FileType.kubernetes:
            list(yaml.safe_load_all(content))
            return True, "Kubernetes YAML parsed"
        if file_type == FileType.dockerfile:
            continuation = False
            for raw in content.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if not continuation and not _DOCKER_INSTRUCTION.match(line):
                    return False, "Dockerfile contains an invalid instruction"
                continuation = line.endswith("\\")
            return (not continuation, "Dockerfile instructions parsed")
        if file_type == FileType.terraform:
            return False, "Terraform fixes require a full HCL parser and are suggestion-only"
    except yaml.YAMLError as exc:
        return False, f"Patched YAML is invalid: {exc}"
    return False, "Unsupported file type"


def _action_references(content: str) -> dict[str, set[str]]:
    references: dict[str, set[str]] = {}
    for action, reference in _ACTION_REFERENCE.findall(content):
        references.setdefault(action.lower(), set()).add(reference)
    return references


def _weakens_action_pinning(original: str, patched: str) -> bool:
    before = _action_references(original)
    after = _action_references(patched)
    for action, references in before.items():
        if not any(_FULL_SHA.fullmatch(reference) for reference in references):
            continue
        patched_references = after.get(action, set())
        if patched_references and any(
            not _FULL_SHA.fullmatch(reference) for reference in patched_references
        ):
            return True
    return False


def _npm_publish_modes(content: str) -> set[str]:
    modes: set[str] = set()
    for raw in content.splitlines():
        stripped = raw.strip()
        if stripped.startswith("- run:"):
            stripped = stripped[len("- run:"):].strip()
        elif stripped.startswith("run:"):
            stripped = stripped[len("run:"):].strip()
        try:
            tokens = shlex.split(stripped, comments=True, posix=True)
        except ValueError:
            continue
        if tokens[:3] == ["npm", "stage", "publish"]:
            modes.add("staged")
        elif tokens[:2] == ["npm", "publish"]:
            modes.add("direct")
    return modes


def verify_finding_patch(
    *,
    original: str,
    patch: str,
    filename: str,
    rule: str,
    severity: str,
) -> PatchCheck:
    patched = apply_unified_diff(original, patch, filename)
    if patched is None:
        return PatchCheck(False, notes=["Patch is not an exact unified diff for this file"])

    syntax_ok, syntax_note = _syntax_valid(filename, patched)
    if not syntax_ok:
        if "duplicate key" in syntax_note.lower():
            return PatchCheck(False, notes=["Patched YAML contains a duplicate key"])
        return PatchCheck(False, notes=[syntax_note])

    if _weakens_action_pinning(original, patched):
        return PatchCheck(False, notes=["Patch replaces an immutable action SHA with a mutable reference"])
    before_publish = _npm_publish_modes(original)
    after_publish = _npm_publish_modes(patched)
    if "staged" in before_publish and "direct" in after_publish:
        return PatchCheck(False, notes=["Patch removes the staged-publishing human approval boundary"])

    before = run_deterministic({filename: original}).findings
    after = run_deterministic({filename: patched}).findings
    rule_id = rule.split(":", 1)[0]
    if any(item.rule.split(":", 1)[0] == rule_id for item in after):
        return PatchCheck(False, notes=["Patch does not remove the targeted deterministic finding"])

    before_ids = {item.rule.split(":", 1)[0] for item in before}
    introduced = [
        item.rule for item in after
        if item.rule.split(":", 1)[0] not in before_ids
    ]
    if introduced:
        return PatchCheck(False, notes=[f"Patch introduces: {', '.join(introduced)}"])

    return PatchCheck(True, patched=patched, notes=[syntax_note, "Targeted finding removed"])
