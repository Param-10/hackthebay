"""Authoritative remediation metadata for deterministic rules."""
from __future__ import annotations

from app.scanner.schema import Finding

_FAMILY_REFERENCES = {
    "TF": "https://developer.hashicorp.com/terraform/language/manage-sensitive-data",
    "K8S": "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
    "DF": "https://docs.docker.com/build/building/best-practices/",
    "GA": "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
}

_REMEDIATIONS = {
    "TF001": "Restrict ingress to the smallest required CIDR and port range.",
    "TF002": "Remove the value from source control, rotate it, and load it from a secret manager.",
    "TF003": "Enable provider-managed or customer-managed encryption for the resource.",
    "TF004": "Disable the public IP unless the workload explicitly requires direct internet access.",
    "TF005": "Replace wildcard actions with the exact API actions the workload needs.",
    "TF006": "Enable object versioning and define retention appropriate to the workload.",
    "K8S001": "Set hostPID to false and use the pod namespace.",
    "K8S002": "Set hostNetwork to false unless host networking is an explicit operational requirement.",
    "K8S003": "Remove privileged mode and grant only the required capabilities.",
    "K8S004": "Set allowPrivilegeEscalation to false for the container.",
    "K8S005": "Run as a non-zero UID and enforce runAsNonRoot where possible.",
    "K8S006": "Set workload-appropriate CPU and memory requests and limits.",
    "K8S007": "Pin the image to an immutable digest.",
    "DF001": "Pin the base image to an immutable digest.",
    "DF002": "Specify an immutable base-image digest.",
    "DF003": "Create and switch to a dedicated non-root user.",
    "DF004": "Download explicitly, verify a checksum, and remove the archive in the same layer.",
    "DF005": "Download the script, verify its pinned checksum or signature, then execute it.",
    "DF006": "Remove SSH and use the platform's exec or debugging mechanism.",
    "DF007": "Remove and rotate the secret; inject it at runtime through a secret store.",
    "DF008": "Create and select a dedicated non-root user in the final image stage.",
    "GA001": "Pass the value through an environment variable and quote it in the shell script.",
    "GA002": "Declare only the specific read/write permissions required by each job.",
    "GA003": "Avoid executing pull-request head code with pull_request_target credentials.",
    "GA004": "Pin the action to a reviewed full-length commit SHA.",
}


def add_rule_metadata(finding: Finding) -> Finding:
    rule_id = finding.rule.split(":", 1)[0]
    family = "".join(ch for ch in rule_id if ch.isalpha())
    return finding.model_copy(update={
        "remediation": _REMEDIATIONS.get(rule_id, "Review and restrict the insecure configuration."),
        "reference": _FAMILY_REFERENCES.get(family),
    })
