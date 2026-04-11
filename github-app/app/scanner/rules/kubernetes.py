"""Deterministic Kubernetes YAML rules."""
import yaml
from app.scanner.schema import Finding


def scan(filename: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return findings

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        _check_doc(filename, doc, findings)

    return findings


def _check_doc(filename: str, doc: dict, findings: list[Finding]) -> None:
    kind = doc.get("kind", "")
    spec = doc.get("spec", {}) or {}

    # Pod-level host namespaces
    if spec.get("hostPID"):
        findings.append(Finding(
            file=filename, severity="critical",
            rule="K8S001: hostPID enabled",
            explanation="Sharing host PID namespace allows process inspection/escalation.",
            raw_evidence=f"kind={kind} hostPID=true",
        ))
    if spec.get("hostNetwork"):
        findings.append(Finding(
            file=filename, severity="high",
            rule="K8S002: hostNetwork enabled",
            explanation="Container shares host network stack; risk of traffic interception.",
            raw_evidence=f"kind={kind} hostNetwork=true",
        ))

    containers = _get_containers(doc)
    for c in containers:
        name = c.get("name", "<unnamed>")
        sc = c.get("securityContext", {}) or {}
        resources = c.get("resources", {}) or {}

        if sc.get("privileged"):
            findings.append(Finding(
                file=filename, severity="critical",
                rule="K8S003: Privileged container",
                explanation=f"Container '{name}' runs privileged; equivalent to root on host.",
                raw_evidence=f"container={name} privileged=true",
            ))

        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(Finding(
                file=filename, severity="medium",
                rule="K8S004: allowPrivilegeEscalation not explicitly false",
                explanation=f"Container '{name}' may escalate privileges via setuid binaries.",
                raw_evidence=f"container={name} allowPrivilegeEscalation not set to false",
            ))

        run_as = sc.get("runAsUser")
        if run_as == 0:
            findings.append(Finding(
                file=filename, severity="high",
                rule="K8S005: Container runs as root (UID 0)",
                explanation=f"Container '{name}' explicitly configured to run as root.",
                raw_evidence=f"container={name} runAsUser=0",
            ))

        if not resources.get("limits"):
            findings.append(Finding(
                file=filename, severity="low",
                rule="K8S006: No resource limits",
                explanation=f"Container '{name}' has no CPU/memory limits; risk of node exhaustion.",
                raw_evidence=f"container={name} resources.limits missing",
            ))

        image = c.get("image", "")
        if image.endswith(":latest") or (":" not in image and "@" not in image):
            findings.append(Finding(
                file=filename, severity="medium",
                rule="K8S007: Unpinned image tag",
                explanation=f"Container '{name}' uses '{image}'; unpinned images break reproducibility.",
                raw_evidence=f"container={name} image={image}",
            ))


def _get_containers(doc: dict) -> list[dict]:
    """Walk common Kubernetes structures to find container specs."""
    containers = []
    spec = doc.get("spec", {}) or {}

    # Pod
    pod_spec = spec.get("template", {}).get("spec", spec)
    for key in ("containers", "initContainers", "ephemeralContainers"):
        containers.extend(pod_spec.get(key) or [])

    return [c for c in containers if isinstance(c, dict)]
