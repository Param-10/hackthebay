"""
GitHub API helpers.
- GitHub App JWT creation
- Installation access token exchange
- PR file listing + raw content fetch
"""
import time
import logging
import httpx
import jwt          # PyJWT
from app.config import get_settings

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


def _make_jwt() -> str:
    settings = get_settings()
    now = int(time.time())
    payload = {
        "iat": now - 60,       # issued 60 s ago (clock skew tolerance)
        "exp": now + 600,      # valid 10 min
        "iss": settings.github_app_id,
    }
    return jwt.encode(payload, settings.get_private_key(), algorithm="RS256")


def get_installation_token(installation_id: int) -> str:
    app_jwt = _make_jwt()
    url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
    resp = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["token"]


def list_pr_files(repo: str, pr_number: int, token: str) -> list[dict]:
    """Return GitHub's list of files changed in a PR (up to 300 files)."""
    files = []
    page = 1
    while True:
        resp = httpx.get(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files",
            params={"per_page": 100, "page": page},
            headers=_auth_headers(token),
            timeout=20,
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        files.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return files


def get_file_content(repo: str, path: str, ref: str, token: str) -> str | None:
    """Fetch raw file content at a given ref. Returns None if not found."""
    resp = httpx.get(
        f"{GITHUB_API}/repos/{repo}/contents/{path}",
        params={"ref": ref},
        headers={**_auth_headers(token), "Accept": "application/vnd.github.raw+json"},
        timeout=20,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.text


def _auth_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
