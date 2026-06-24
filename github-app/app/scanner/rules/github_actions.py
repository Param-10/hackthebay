"""Deterministic GitHub Actions workflow rules."""
import copy
import re
import shlex
import yaml
from yaml.constructor import ConstructorError
from app.scanner.schema import Finding


_SCRIPT_INJECTION = re.compile(
    r'\$\{\{\s*(github\.event\.(pull_request|issue|comment|head_commit)\.[a-zA-Z_.]+)\s*\}\}',
)
_PINNED_SHA = re.compile(r'@[0-9a-f]{40}$')
_WRITE_ALL = re.compile(r'permissions:\s*write-all', re.IGNORECASE)
_PULL_REQUEST_TARGET = re.compile(r'pull_request_target')


class _WorkflowLoader(yaml.SafeLoader):
    """YAML loader that keeps GitHub's `on` key as a string."""


_WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for _char, _resolvers in _WorkflowLoader.yaml_implicit_resolvers.items():
    _WorkflowLoader.yaml_implicit_resolvers[_char] = [
        item for item in _resolvers if item[0] != "tag:yaml.org,2002:bool"
    ]
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_WorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _npm_publish_mode(command: object) -> str | None:
    """Classify actual npm publish commands without substring matching."""
    for raw in str(command or "").splitlines():
        try:
            tokens = shlex.split(raw.strip(), comments=True, posix=True)
        except ValueError:
            continue
        if tokens[:3] == ["npm", "stage", "publish"]:
            return "staged"
        if tokens[:2] == ["npm", "publish"]:
            return "direct"
    return None


def _has_long_lived_publish_token(*environments) -> bool:
    for environment in environments:
        if not isinstance(environment, dict):
            continue
        for key, value in environment.items():
            if str(key).upper() in {"NODE_AUTH_TOKEN", "NPM_TOKEN"} and "secrets." in str(value):
                return True
    return False


def _line_containing(lines: list[str], needle: str) -> int | None:
    return next((index for index, line in enumerate(lines, 1) if needle in line), None)


def scan(filename: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    # Line-level checks
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        m = _SCRIPT_INJECTION.search(line)
        if m:
            findings.append(Finding(
                file=filename, line=i, severity="critical",
                rule="GA001: Script injection via untrusted context",
                explanation=(
                    f"Expression `{m.group(0)}` interpolated into a run step. "
                    "Attacker-controlled values (e.g. PR title) can inject arbitrary shell commands."
                ),
                raw_evidence=stripped[:200],
            ))

        if _WRITE_ALL.search(line):
            findings.append(Finding(
                file=filename, line=i, severity="high",
                rule="GA002: permissions: write-all",
                explanation="Granting all write permissions violates least privilege.",
                raw_evidence=stripped,
            ))

    # YAML-level checks
    try:
        doc = yaml.load(content, Loader=_WorkflowLoader)
    except yaml.YAMLError:
        return findings

    if not isinstance(doc, dict):
        return findings

    # pull_request_target with checkout of head
    triggers = doc.get("on") or {}
    has_pull_request_target = (
        triggers == "pull_request_target"
        or (isinstance(triggers, list) and "pull_request_target" in triggers)
        or (isinstance(triggers, dict) and "pull_request_target" in triggers)
    )
    if has_pull_request_target:
        findings.append(Finding(
            file=filename,
            line=_line_containing(lines, "pull_request_target"),
            severity="high",
            rule="GA003: pull_request_target trigger",
            explanation=(
                "`pull_request_target` runs in the context of the base branch with write tokens. "
                "Checking out PR head code here can expose secrets."
            ),
            raw_evidence="on: pull_request_target",
        ))

    # Unpinned third-party actions
    jobs = doc.get("jobs", {}) or {}
    workflow_env = doc.get("env", {}) or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        job_env = job.get("env", {}) or {}
        for step in steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if _npm_publish_mode(run) == "direct" and _has_long_lived_publish_token(
                workflow_env,
                job_env,
                step.get("env", {}),
            ):
                command = next(
                    (line.strip() for line in str(run).splitlines() if _npm_publish_mode(line) == "direct"),
                    "npm publish",
                )
                findings.append(Finding(
                    file=filename,
                    line=_line_containing(lines, command),
                    severity="high",
                    rule="GA005: Direct npm publish with long-lived token",
                    explanation=(
                        "Direct publication uses a repository secret instead of a scoped OIDC "
                        "trusted-publisher identity and human-approved staged publishing."
                    ),
                    raw_evidence=command[:200],
                ))

            uses = str(step.get("uses", "") or "")
            if not uses or uses.startswith("."):
                continue  # local or reusable, skip
            if not _PINNED_SHA.search(uses):
                findings.append(Finding(
                    file=filename,
                    line=_line_containing(lines, f"uses: {uses}"),
                    severity="medium",
                    rule="GA004: Action not pinned to full SHA",
                    explanation=(
                        f"`{uses}` is not pinned to a commit SHA. "
                        "Tag/branch references are mutable and susceptible to supply-chain attacks."
                    ),
                    raw_evidence=f"uses: {uses}",
                ))

    return findings
