"""File-type routing: maps a filename to its scanner type."""
import pathlib
from enum import Enum


class FileType(str, Enum):
    terraform = "terraform"
    kubernetes = "kubernetes"
    dockerfile = "dockerfile"
    github_actions = "github_actions"
    unknown = "unknown"


def classify(filename: str) -> FileType:
    p = pathlib.PurePosixPath(filename)

    if p.name == "Dockerfile" or p.suffix == ".dockerfile":
        return FileType.dockerfile

    if filename.startswith(".github/workflows") and p.suffix in (".yml", ".yaml"):
        return FileType.github_actions

    if p.suffix in (".tf", ".tfvars"):
        return FileType.terraform

    if p.suffix in (".yml", ".yaml"):
        # Heuristic: contains k8s top-level keys
        return FileType.kubernetes  # caller refines via content sniff

    return FileType.unknown


def is_scannable(filename: str) -> bool:
    return classify(filename) != FileType.unknown
