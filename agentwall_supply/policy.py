"""
policy.py
Security Policy Enforcement Engine & SARIF Exporter for AgentWall-Supply.

Allows enterprises to define custom security compliance policies (e.g. max allowed score,
forbidden capability scopes, required Tool-BOM attestations) and export reports to
SARIF (Static Analysis Results Interchange Format) for GitHub Code Scanning integration.
"""

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    max_score: int = 40
    forbidden_scopes: set[str] = field(default_factory=set)
    deny_injection_patterns: set[str] = field(default_factory=set)
    require_tbom: bool = False


DEFAULT_ENTERPRISE_POLICY = PolicyRule(
    rule_id="ENTERPRISE_DEFAULT",
    description="Standard enterprise AI safety policy for Model Context Protocol tools",
    max_score=40,
    forbidden_scopes={"credentials", "shell_exec"},
    deny_injection_patterns={"sensitive_file_reference", "exfil_language", "override_instructions"},
    require_tbom=True,
)


@dataclass
class PolicyViolation:
    rule_id: str
    tool_name: str
    violation_type: str
    message: str


def evaluate_policy(server_report, policy: PolicyRule = DEFAULT_ENTERPRISE_POLICY) -> list[PolicyViolation]:
    """Evaluates a ServerReport against an enterprise PolicyRule."""
    violations = []

    for tr in server_report.tool_reports:
        # Check 1: Tool score cap
        if tr.score > policy.max_score:
            violations.append(PolicyViolation(
                rule_id=policy.rule_id,
                tool_name=tr.tool.name,
                violation_type="SCORE_EXCEEDED",
                message=f"Tool risk score ({tr.score}) exceeds policy threshold ({policy.max_score})",
            ))

        # Check 2: Forbidden scope categories
        found_forbidden = tr.permissions.categories & policy.forbidden_scopes
        if found_forbidden:
            violations.append(PolicyViolation(
                rule_id=policy.rule_id,
                tool_name=tr.tool.name,
                violation_type="FORBIDDEN_SCOPE",
                message=f"Tool requests forbidden scope capabilities: {', '.join(sorted(found_forbidden))}",
            ))

        # Check 3: Denied injection patterns
        for finding in tr.semantic.injection_findings:
            if finding.pattern_label in policy.deny_injection_patterns:
                violations.append(PolicyViolation(
                    rule_id=policy.rule_id,
                    tool_name=tr.tool.name,
                    violation_type="DENIED_INJECTION_PATTERN",
                    message=f"Tool manifest contains prohibited pattern '{finding.pattern_label}' (matched: \"{finding.matched_snippet}\")",
                ))

    return violations


def export_sarif(server_report) -> dict[str, Any]:
    """
    Exports a ServerReport into SARIF v2.1.0 format for GitHub Code Scanning
    and CI/CD security tab integration.
    """
    results = []
    rules_map = {}

    for tr in server_report.tool_reports:
        for finding in tr.semantic.injection_findings:
            rule_id = f"AGENTWALL-{finding.pattern_label.upper()}"
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f"Prompt injection pattern: {finding.pattern_label}"},
                    "fullDescription": {"text": f"Matches injection directive in tool description: {finding.pattern_label}"},
                    "defaultConfiguration": {"level": "error" if finding.severity >= 8 else "warning"}
                }
            results.append({
                "ruleId": rule_id,
                "message": {"text": f"Tool '{tr.tool.name}' flagged for {finding.pattern_label}: \"{finding.matched_snippet}\""},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"mcp-tools/{server_report.server_name}/{tr.tool.name}"}
                    }
                }]
            })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentWall-Supply",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/Ashin-06/AgentWall-Supply",
                    "rules": list(rules_map.values())
                }
            },
            "results": results
        }]
    }
