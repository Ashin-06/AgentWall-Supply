"""
permissions.py
Capability scope inference engine for AgentWall-Supply.
"""

import json
import re
from dataclasses import dataclass, field

_SCOPE_PATTERNS: dict[str, tuple[int, re.Pattern]] = {
    "filesystem_write": (7, re.compile(r"\b(write|delete|remove|overwrite|rm |unlink)\b.{0,20}\b(file|directory|path)\b", re.I)),
    "filesystem_read": (3, re.compile(r"\b(read|list|open|scan)\b.{0,20}\b(file|directory|path)\b", re.I)),
    "network_egress": (6, re.compile(r"\b(http|url|endpoint|webhook|fetch|request|api call|post to|send to)\b", re.I)),
    "credentials": (9, re.compile(r"\b(password|api[_ ]?key|secret|token|credential|private key|ssh key)\b", re.I)),
    "shell_exec": (10, re.compile(r"\b(exec|execute|shell|subprocess|command|bash|eval)\b", re.I)),
    "system_settings": (6, re.compile(r"\b(registry|environment variable|system config|firewall|permissions?)\b", re.I)),
    "email_messaging": (5, re.compile(r"\b(send email|smtp|sms|slack message|dm |direct message)\b", re.I)),
    "browser_control": (5, re.compile(r"\b(click|navigate|browser|dom|screenshot)\b", re.I)),
}


@dataclass
class ScopeFinding:
    category: str
    weight: int
    source: str


@dataclass
class PermissionResult:
    findings: list[ScopeFinding] = field(default_factory=list)

    @property
    def scope_score(self) -> int:
        best = {}
        for f in self.findings:
            best[f.category] = max(best.get(f.category, 0), f.weight)
        return min(sum(best.values()), 30)

    @property
    def categories(self) -> set[str]:
        return {f.category for f in self.findings}


def analyze_permissions(description: str, input_schema: dict) -> PermissionResult:
    findings = []
    for category, (weight, pattern) in _SCOPE_PATTERNS.items():
        if pattern.search(description or ""):
            findings.append(ScopeFinding(category, weight, "description"))

    schema_text = json.dumps(input_schema or {})
    for category, (weight, pattern) in _SCOPE_PATTERNS.items():
        if pattern.search(schema_text):
            findings.append(ScopeFinding(category, weight, "schema"))

    return PermissionResult(findings=findings)
