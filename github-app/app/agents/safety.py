"""Input safety helpers for untrusted pull-request content."""
from __future__ import annotations

import re

_ASSIGNMENT_SECRET = re.compile(
    r"(?im)^(\s*[\"']?(?:password|secret|token|api[_-]?key|private[_-]?key)[\"']?\s*[=:]\s*)([^\s#]+|\"[^\"]*\"|'[^']*')"
)
_DOCKER_SECRET = re.compile(
    r"(?im)^(\s*(?:ENV|ARG)\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*)(\S+)"
)


def redact_sensitive_text(content: str) -> str:
    redacted = _ASSIGNMENT_SECRET.sub(r"\1[REDACTED]", content)
    redacted = _DOCKER_SECRET.sub(r"\1[REDACTED]", redacted)

    lines = redacted.splitlines()
    is_kubernetes_secret = any(
        line.strip().lower() == "kind: secret" for line in lines
    )
    secret_block_indent: int | None = None
    private_key_block = False
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if "-----BEGIN" in stripped and "PRIVATE KEY-----" in stripped:
            private_key_block = True
            result.append(" " * indent + "[REDACTED PRIVATE KEY]")
            continue
        if private_key_block:
            if "-----END" in stripped and "PRIVATE KEY-----" in stripped:
                private_key_block = False
            continue
        if is_kubernetes_secret and stripped in ("data:", "stringData:"):
            secret_block_indent = indent
            result.append(line)
            continue
        if secret_block_indent is not None:
            if stripped and indent <= secret_block_indent:
                secret_block_indent = None
            elif ":" in stripped:
                key = line.split(":", 1)[0]
                result.append(f"{key}: [REDACTED]")
                continue
        result.append(line)
    suffix = "\n" if content.endswith("\n") else ""
    return "\n".join(result) + suffix


def bounded_untrusted_files(files: dict[str, str], *, total_limit: int = 64_000) -> dict[str, str]:
    """Redact and cap untrusted context before it crosses the provider boundary."""
    result: dict[str, str] = {}
    remaining = total_limit
    for name in sorted(files):
        if remaining <= 0:
            break
        safe = redact_sensitive_text(files[name])[: min(12_000, remaining)]
        result[name] = safe
        remaining -= len(safe)
    return result
