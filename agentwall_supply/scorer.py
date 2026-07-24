"""
scorer.py
Transparent multi-signal risk scorer for AgentWall-Supply.
"""

from dataclasses import dataclass
from .manifest import ToolDef
from .semantic import SemanticResult, analyze_description
from .permissions import PermissionResult, analyze_permissions
from .drift import DriftResult
from .sandbox import SandboxResult


def _tier(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


@dataclass
class ToolReport:
    tool: ToolDef
    semantic: SemanticResult
    permissions: PermissionResult
    drift_flag: bool
    drift_note: str = ""
    sandbox_result: SandboxResult | None = None

    @property
    def score(self) -> int:
        mismatch_penalty = 15 if self.semantic.mismatch_flag else 0
        drift_penalty = 15 if self.drift_flag else 0
        sandbox_penalty = self.sandbox_result.sandbox_penalty if self.sandbox_result else 0
        return min(
            self.semantic.injection_score
            + self.permissions.scope_score
            + mismatch_penalty
            + drift_penalty
            + sandbox_penalty,
            100,
        )

    @property
    def tier(self) -> str:
        return _tier(self.score)


@dataclass
class ServerReport:
    server_name: str
    tool_reports: list[ToolReport]
    drift: DriftResult

    @property
    def score(self) -> int:
        if not self.tool_reports:
            return 0
        max_score = max(t.score for t in self.tool_reports)
        avg_score = sum(t.score for t in self.tool_reports) / len(self.tool_reports)
        return min(round(max_score * 0.7 + avg_score * 0.3), 100)

    @property
    def tier(self) -> str:
        return _tier(self.score)


def score_server(manifest, drift: DriftResult, sandbox_results: dict[str, SandboxResult] | None = None) -> ServerReport:
    changed_set = set(drift.changed_tools)
    reports = []
    for tool in manifest.tools:
        semantic = analyze_description(tool.name, tool.description)
        perms = analyze_permissions(tool.description, tool.input_schema)
        drift_flag = tool.name in changed_set
        note = "schema/description changed since last scan" if drift_flag else ""
        sb_res = sandbox_results.get(tool.name) if sandbox_results else None
        reports.append(ToolReport(tool, semantic, perms, drift_flag, note, sb_res))
    return ServerReport(server_name=manifest.server_name, tool_reports=reports, drift=drift)
