"""File-type routing: maps a filename to its scanner type."""
import pathlib
from enum import Enum


class FileType(str, Enum):
    terraform = "terraform"
    kubernetes = "kubernetes"
    dockerfile = "dockerfile"
    github_actions = "github_actions"
    unknown = "unknown"


# Files that are YAML but should never be treated as IaC.
_EXCLUDED_FILENAMES = {
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "yarn.lock",
    "package-lock.json",
    "composer.lock",
    ".prettierrc.yml",
    ".prettierrc.yaml",
    ".eslintrc.yml",
    ".eslintrc.yaml",
    ".stylelintrc.yml",
    ".stylelintrc.yaml",
    ".markdownlint.yml",
    ".markdownlint.yaml",
    ".github/dependabot.yml",
    ".github/FUNDING.yml",
    ".releaserc.yml",
    ".releaserc.yaml",
    "renovate.json",
    "codecov.yml",
    "codecov.yaml",
    ".pre-commit-config.yaml",
}

# Basename patterns that are never IaC.
_EXCLUDED_BASENAMES = {
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    ".prettierrc.yml",
    ".prettierrc.yaml",
    ".eslintrc.yml",
    ".eslintrc.yaml",
    ".stylelintrc.yml",
    ".stylelintrc.yaml",
    ".markdownlint.yml",
    ".markdownlint.yaml",
    ".releaserc.yml",
    ".releaserc.yaml",
    "codecov.yml",
    "codecov.yaml",
    ".pre-commit-config.yaml",
}


def _is_excluded(filename: str) -> bool:
    """Check if a file should be excluded from scanning."""
    p = pathlib.PurePosixPath(filename)

    # Check full path matches
    if filename in _EXCLUDED_FILENAMES:
        return True

    # Check basename matches
    if p.name in _EXCLUDED_BASENAMES:
        return True

    return False


def classify(filename: str, content: str | None = None) -> FileType:
    """Classify a file into its scanner type.

    Args:
        filename: The path/name of the file.
        content: Optional file content for content-based sniffing.
    """
    if _is_excluded(filename):
        return FileType.unknown

    p = pathlib.PurePosixPath(filename)

    if p.name == "Dockerfile" or p.suffix == ".dockerfile":
        return FileType.dockerfile

    if filename.startswith(".github/workflows") and p.suffix in (".yml", ".yaml"):
        return FileType.github_actions

    if p.suffix in (".tf", ".tfvars"):
        return FileType.terraform

    if p.suffix in (".yml", ".yaml"):
        # Content sniff: only classify as Kubernetes if the YAML looks like a
        # Kubernetes resource (has `kind` or `apiVersion` at the top level).
        if content is not None:
            if not _looks_like_kubernetes(content):
                return FileType.unknown
        return FileType.kubernetes

    return FileType.unknown


def _looks_like_kubernetes(content: str) -> bool:
    """Quick heuristic: does the YAML content contain K8s resource indicators?"""
    # Check the first 2000 chars for performance on large files
    head = content[:2000]
    # Look for top-level `kind:` or `apiVersion:` which are present in every
    # Kubernetes resource manifest
    for line in head.splitlines():
        stripped = line.strip()
        if stripped.startswith("kind:") or stripped.startswith("apiVersion:"):
            return True
    return False


def is_scannable(filename: str) -> bool:
    # Without content we use a conservative check — the classify() call in the
    # worker will do the full content-aware sniff.
    return classify(filename) != FileType.unknown
