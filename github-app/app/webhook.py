"""
Webhook signature verification and PR event extraction.
Follows GitHub's HMAC-SHA256 scheme:
  X-Hub-Signature-256: sha256=<hex>
"""
import hashlib
import hmac
import logging
from fastapi import HTTPException, Request
from app.config import get_settings

logger = logging.getLogger(__name__)

INFRA_EXTENSIONS = {
    ".tf", ".tfvars",           # Terraform
    ".yaml", ".yml",            # Kubernetes / GitHub Actions / generic
    "Dockerfile",               # Docker (matched by filename stem)
    ".dockerfile",
}

INFRA_PATHS = {
    ".github/workflows",        # GitHub Actions
}


def verify_signature(payload: bytes, signature_header: str | None) -> None:
    """Raise 401 if HMAC signature doesn't match."""
    secret = get_settings().github_webhook_secret
    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing signature")
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")


def is_infra_file(filename: str) -> bool:
    """Return True if filename belongs to an infra file type we scan."""
    import pathlib
    p = pathlib.PurePosixPath(filename)
    # Dockerfile by name
    if p.name == "Dockerfile" or p.suffix in INFRA_EXTENSIONS:
        return True
    # GitHub Actions path prefix
    for prefix in INFRA_PATHS:
        if filename.startswith(prefix):
            return True
    return False


async def parse_pr_event(request: Request) -> dict | None:
    """
    Parse a GitHub webhook request.
    Returns a job dict if it's a PR open/sync on infra files, else None.
    Raises 401 on bad signature, 400 on bad JSON.
    """
    payload_bytes = await request.body()
    verify_signature(payload_bytes, request.headers.get("X-Hub-Signature-256"))

    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        return None

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    action = body.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return None

    pr = body["pull_request"]
    return {
        "repo_full_name": body["repository"]["full_name"],
        "pr_number": pr["number"],
        "head_sha": pr["head"]["sha"],
        "base_sha": pr["base"]["sha"],
        "installation_id": body["installation"]["id"],
        "pr_url": pr["html_url"],
    }
