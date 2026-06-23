"""Changed-line parsing for GitHub pull-request patches."""
from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines_from_patch(
    patch: str | None,
    *,
    status: str,
    content: str,
) -> set[int] | None:
    """Return changed lines in the head file, or None when coverage is unknown."""
    if status == "added":
        return set(range(1, len(content.splitlines()) + 1))
    if not patch:
        return None

    changed: set[int] = set()
    new_line: int | None = None
    for raw in patch.splitlines():
        match = _HUNK.match(raw)
        if match:
            new_line = int(match.group(1))
            continue
        if new_line is None or raw.startswith("\\ No newline"):
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            changed.add(new_line)
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        else:
            new_line += 1
    return changed


def changed_line_context(content: str, lines: set[int], *, radius: int = 2) -> str:
    source = content.splitlines()
    selected: set[int] = set()
    for line in lines:
        selected.update(range(max(1, line - radius), min(len(source), line + radius) + 1))
    return "\n".join(f"[line {line}] {source[line - 1]}" for line in sorted(selected))
