"""
Dry-run: full scan pipeline on local sample files.
Prints the PR review body + inline comments that would be posted to GitHub.
No GitHub webhook or tunnel needed.

Usage:
    PYTHONPATH=. .venv/bin/python3 dry_run.py
    PYTHONPATH=. .venv/bin/python3 dry_run.py path/to/your.tf path/to/Dockerfile
"""
import sys
import json

# ── Sample infra files (used when no args given) ──────────────────────────────
SAMPLE_FILES = {
    "infra/main.tf": """\
resource "aws_security_group_rule" "allow_all" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

variable "db_password" {
  default = "hardcoded_pass_123"
}
""",

    "k8s/deployment.yaml": """\
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
          allowPrivilegeEscalation: true
""",

    "Dockerfile": """\
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ENV API_KEY=sk-prod-supersecret123
RUN curl https://raw.githubusercontent.com/example/setup/main/install.sh | bash
EXPOSE 22
EXPOSE 8080
""",

    ".github/workflows/ci.yml": """\
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Print title
        run: echo "${{ github.event.pull_request.title }}"
      - uses: actions/setup-python@v5
""",
}


def load_files_from_args() -> dict[str, str]:
    files = {}
    for path in sys.argv[1:]:
        try:
            with open(path) as f:
                files[path] = f.read()
            print(f"  Loaded: {path}")
        except OSError as e:
            print(f"  Skip {path}: {e}")
    return files


def print_separator(title=""):
    width = 72
    if title:
        pad = (width - len(title) - 2) // 2
        print("\n" + "─" * pad + f" {title} " + "─" * pad)
    else:
        print("\n" + "─" * width)


def main():
    # ── Pick files ────────────────────────────────────────────────────────────
    if len(sys.argv) > 1:
        print("Loading files from args:")
        files = load_files_from_args()
        if not files:
            print("No files loaded. Exiting.")
            sys.exit(1)
    else:
        print("No args — using built-in sample files:")
        for f in SAMPLE_FILES:
            print(f"  {f}")
        files = SAMPLE_FILES

    # ── Step 1: Deterministic scan ────────────────────────────────────────────
    print_separator("Step 1: Deterministic scan")
    from app.scanner.deterministic import run_deterministic
    det = run_deterministic(files)
    print(f"Scanned: {det.scanned_files}")
    print(f"Findings: {len(det.findings)}")
    for f in det.findings:
        print(f"  [{f.severity.upper():8s}] {f.rule}  ({f.file}:{f.line or '?'})")

    # ── Step 2: Agent 1 – Reasoning ───────────────────────────────────────────
    print_separator("Step 2: Agent 1 – Security reasoning (Gemini)")
    print("Calling Gemini… ", end="", flush=True)
    from app.agents.reasoning import run_reasoning_agent
    reasoning = run_reasoning_agent(files, det.findings)
    print(f"done  overall_risk={reasoning.overall_risk}")
    print(f"\nSummary:\n  {reasoning.summary}")
    print(f"\nFindings ({len(reasoning.findings)}):")
    for f in reasoning.findings:
        patch_flag = " [patch]" if f.proposed_patch else ""
        print(f"  [{f.severity.upper():8s}] {f.rule}{patch_flag}")
        print(f"             Risk: {f.risk_context[:120]}")

    # ── Step 3: Agent 2 – Verification ────────────────────────────────────────
    print_separator("Step 3: Agent 2 – Patch verification (Gemini)")
    from collections import defaultdict
    from app.agents.verification import run_verification_agent, VerificationOutput

    all_verdicts = []
    by_file: dict[str, list] = defaultdict(list)
    for f in reasoning.findings:
        if f.proposed_patch:
            by_file[f.file].append(f)

    if not by_file:
        print("No patches proposed — skipping verification.")
        combined = VerificationOutput(verdicts=[], all_clear=True)
    else:
        for fname, findings in by_file.items():
            print(f"Verifying {len(findings)} patch(es) for {fname}… ", end="", flush=True)
            v_out = run_verification_agent(files.get(fname, ""), findings)
            all_verdicts.extend(v_out.verdicts)
            print("done")

        combined = VerificationOutput(
            verdicts=all_verdicts,
            all_clear=all(v.final_recommendation == "approve" for v in all_verdicts),
        )

    print(f"\nVerdicts ({len(all_verdicts)}):")
    for v in all_verdicts:
        icon = {"approve": "✅", "revise": "⚠️", "reject": "❌"}.get(v.final_recommendation, "?")
        print(f"  {icon} {v.final_recommendation.upper():7s}  {v.rule}")
        if v.issues:
            for issue in v.issues:
                print(f"              • {issue}")

    # ── Step 4: Render what would be posted ───────────────────────────────────
    print_separator("Step 4: PR review body (what GitHub would receive)")
    from app.reporter import _build_summary_body, _build_inline_comments
    summary = _build_summary_body(reasoning, combined)
    print(summary)

    print_separator("Inline comments per file")
    comments = _build_inline_comments(reasoning, combined)
    for c in comments:
        print(f"\n── {c['path']}:{c.get('line','?')} ──")
        print(c["body"])

    print_separator()
    print(f"Done.  Overall risk: {reasoning.overall_risk.upper()}")
    print(f"       {len(reasoning.findings)} finding(s), {len(all_verdicts)} patch(es) verified")


if __name__ == "__main__":
    main()
