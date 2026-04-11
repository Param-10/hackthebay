"""
Creates a test PR in VamsiVD/git_basics with intentionally vulnerable
infra files so the scanner can process a real webhook.

Usage: PYTHONPATH=. .venv/bin/python3 create_test_pr.py
"""
import httpx, base64, json

REPO            = "VamsiVD/git_basics"
INSTALLATION_ID = 123172856
BRANCH          = "test/iac-scanner-demo"

from app.scanner.fetcher import get_installation_token

TOKEN = get_installation_token(INSTALLATION_ID)
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def gh(method, path, **kwargs):
    resp = httpx.request(method, f"https://api.github.com{path}", headers=HEADERS, **kwargs)
    resp.raise_for_status()
    return resp.json()

# ── Vulnerable test files ──────────────────────────────────────────────────────
FILES = {
    "iac-scan-test/main.tf": """\
resource "aws_security_group_rule" "allow_all" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

variable "db_password" {
  default = "hardcoded_secret_123"
}
""",
    "iac-scan-test/Dockerfile": """\
FROM ubuntu:latest
ENV API_KEY=sk-prod-supersecret
RUN curl https://example.com/install.sh | bash
EXPOSE 22
""",
    "iac-scan-test/k8s.yaml": """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:latest
        securityContext:
          privileged: true
""",
    ".github/workflows/iac-test.yml": """\
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
""",
}

# ── Get default branch SHA ─────────────────────────────────────────────────────
print(f"Repo: {REPO}")
repo_info = gh("GET", f"/repos/{REPO}")
default_branch = repo_info["default_branch"]
ref_info = gh("GET", f"/repos/{REPO}/git/ref/heads/{default_branch}")
base_sha = ref_info["object"]["sha"]
print(f"Base branch: {default_branch}  sha={base_sha[:8]}")

# ── Create or reset branch ─────────────────────────────────────────────────────
try:
    gh("POST", f"/repos/{REPO}/git/refs", json={
        "ref": f"refs/heads/{BRANCH}",
        "sha": base_sha,
    })
    print(f"Created branch: {BRANCH}")
except httpx.HTTPStatusError as e:
    if e.response.status_code == 422:
        # branch exists — reset it
        gh("PATCH", f"/repos/{REPO}/git/refs/heads/{BRANCH}", json={
            "sha": base_sha, "force": True
        })
        print(f"Reset existing branch: {BRANCH}")
    else:
        raise

# ── Commit files ───────────────────────────────────────────────────────────────
for path, content in FILES.items():
    encoded = base64.b64encode(content.encode()).decode()
    # Check if file exists on branch
    try:
        existing = gh("GET", f"/repos/{REPO}/contents/{path}", params={"ref": BRANCH})
        sha = existing["sha"]
    except httpx.HTTPStatusError:
        sha = None

    payload = {
        "message": f"test: add vulnerable {path.split('/')[-1]}",
        "content": encoded,
        "branch": BRANCH,
    }
    if sha:
        payload["sha"] = sha

    gh("PUT", f"/repos/{REPO}/contents/{path}", json=payload)
    print(f"  Committed: {path}")

# ── Open PR ────────────────────────────────────────────────────────────────────
try:
    pr = gh("POST", f"/repos/{REPO}/pulls", json={
        "title": "test: vulnerable IaC files for scanner demo",
        "head": BRANCH,
        "base": default_branch,
        "body": "This PR contains intentionally vulnerable IaC files to trigger the security scanner.",
    })
    print(f"\nPR opened: {pr['html_url']}")
    print(f"PR number : #{pr['number']}")
except httpx.HTTPStatusError as e:
    if e.response.status_code == 422:
        # PR already exists
        prs = gh("GET", f"/repos/{REPO}/pulls", params={"head": f"VamsiVD:{BRANCH}", "state": "open"})
        if prs:
            print(f"\nPR already open: {prs[0]['html_url']}")
        else:
            raise
    else:
        raise
