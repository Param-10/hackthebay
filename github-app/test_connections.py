"""
Integration connection tests.
Run after filling .env with real credentials.
Usage: PYTHONPATH=. .venv/bin/python3 test_connections.py
"""
import sys
import traceback

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"

results = []

def test(name, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        results.append((name, "pass"))
    except SkipTest as e:
        print(f"  {SKIP}  {name}  ({e})")
        results.append((name, "skip"))
    except Exception as e:
        print(f"  {FAIL}  {name}")
        traceback.print_exc()
        results.append((name, "fail"))

class SkipTest(Exception):
    pass


# ── Load settings ──────────────────────────────────────────────────────────────
print("\n── Config ──")

def test_env_loaded():
    from app.config import get_settings
    s = get_settings()
    assert s.github_app_id, "GITHUB_APP_ID missing"
    assert s.github_webhook_secret, "GITHUB_WEBHOOK_SECRET missing"
    assert s.gemini_api_key, "GEMINI_API_KEY missing"

def test_private_key_readable():
    from app.config import get_settings
    key = get_settings().get_private_key()
    assert key.startswith("-----BEGIN"), f"Key doesn't look like PEM: {key[:40]}"

test("Env vars loaded from .env",     test_env_loaded)
test("GitHub private key parseable",  test_private_key_readable)


# ── Gemini connectivity ────────────────────────────────────────────────────────
print("\n── Gemini API ──")

def test_gemini_simple():
    from app.agents.client import get_client
    from app.config import get_settings
    from google.genai import types as genai_types
    from pydantic import BaseModel
    from typing import Literal

    class Pong(BaseModel):
        message: str
        status: Literal["ok"]

    client = get_client()
    resp = client.models.generate_content(
        model=get_settings().gemini_model,
        contents=[genai_types.Content(
            role="user",
            parts=[genai_types.Part(text='Reply with JSON {"message":"pong","status":"ok"}')]
        )],
        config=genai_types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=Pong,
            temperature=0,
        ),
    )
    result = Pong.model_validate_json(resp.text)
    assert result.status == "ok", f"Unexpected: {result}"

def test_gemini_reasoning_agent():
    from app.agents.client import AIBudget
    from app.agents.reasoning import run_reasoning_agent
    from app.scanner.schema import Finding

    findings = [Finding(
        file="main.tf", line=5, severity="high",
        rule="TF001: Open ingress CIDR 0.0.0.0/0",
        explanation="Security group allows unrestricted inbound traffic.",
        raw_evidence='cidr_blocks = ["0.0.0.0/0"]',
    )]
    files = {"main.tf": 'resource "aws_security_group_rule" "bad" {\n  cidr_blocks = ["0.0.0.0/0"]\n}'}

    out, _ = run_reasoning_agent(files, findings, AIBudget(90))
    assert out.overall_risk in ("critical", "high", "medium", "low", "pass")
    assert len(out.findings) > 0
    assert out.summary

def test_gemini_verification_agent():
    from app.agents.client import AIBudget
    from app.agents.reasoning import ReasonedFinding
    from app.agents.verification import run_verification_agent

    findings = [ReasonedFinding(
        file="main.tf", line=5, severity="high",
        rule="TF001: Open ingress CIDR 0.0.0.0/0",
        explanation="Security group allows unrestricted inbound traffic.",
        risk_context="Anyone on the internet can connect to this port.",
        proposed_patch='cidr_blocks = ["10.0.0.0/8"]',
        patch_explanation="Restrict to internal VPC CIDR.",
    )]
    original = 'resource "aws_security_group_rule" "bad" {\n  cidr_blocks = ["0.0.0.0/0"]\n}'

    out, _ = run_verification_agent(original, findings, AIBudget(90))
    assert len(out.verdicts) == 1
    v = out.verdicts[0]
    assert v.final_recommendation in ("approve", "revise", "reject")

test("Gemini structured response (ping)",      test_gemini_simple)
test("Agent 1 reasoning (real call)",          test_gemini_reasoning_agent)
test("Agent 2 verification (real call)",       test_gemini_verification_agent)


# ── GitHub App connectivity ────────────────────────────────────────────────────
print("\n── GitHub App ──")

def test_github_jwt():
    """JWT generation doesn't hit network – just validates key + signing."""
    from app.scanner.fetcher import _make_jwt
    import jwt as pyjwt
    token = _make_jwt()
    # decode without verification to inspect payload
    decoded = pyjwt.decode(token, options={"verify_signature": False})
    from app.config import get_settings
    assert decoded["iss"] == get_settings().github_app_id

def test_github_app_api():
    """Calls /app to verify JWT is accepted by GitHub."""
    import httpx
    from app.scanner.fetcher import _make_jwt
    resp = httpx.get(
        "https://api.github.com/app",
        headers={
            "Authorization": f"Bearer {_make_jwt()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )
    assert resp.status_code == 200, f"GitHub returned {resp.status_code}: {resp.text[:200]}"
    data = resp.json()
    assert "id" in data, f"Unexpected response: {data}"
    print(f"         App: {data.get('name')} (id={data.get('id')})")

test("JWT creation from private key",         test_github_jwt)
test("GitHub /app endpoint accepts JWT",      test_github_app_api)


# ── FastAPI server smoke test ──────────────────────────────────────────────────
print("\n── FastAPI ──")

def test_fastapi_health():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

def test_webhook_bad_sig_rejected():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    resp = client.post(
        "/webhook",
        content=b'{"action":"opened"}',
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": "sha256=badhash",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401

def test_webhook_non_pr_event_ignored():
    import hashlib, hmac
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import get_settings

    payload = b'{"zen":"test"}'
    secret = get_settings().github_webhook_secret
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    client = TestClient(app)
    resp = client.post(
        "/webhook",
        content=payload,
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

test("FastAPI /health returns ok",            test_fastapi_health)
test("Webhook rejects bad signature",         test_webhook_bad_sig_rejected)
test("Non-PR event returns ignored",          test_webhook_non_pr_event_ignored)


# ── Summary ────────────────────────────────────────────────────────────────────
print()
passed = sum(1 for _, s in results if s == "pass")
failed = sum(1 for _, s in results if s == "fail")
skipped = sum(1 for _, s in results if s == "skip")
total = len(results)

print(f"Results: {passed}/{total} passed", end="")
if skipped:  print(f"  {skipped} skipped", end="")
if failed:   print(f"  {failed} FAILED", end="")
print()

if failed:
    sys.exit(1)
