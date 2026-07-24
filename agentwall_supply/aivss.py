"""
aivss.py
AI Vulnerability Scoring System (AIVSS v1.0) & CVSS v4.0 Vector Calculator
for AgentWall-Supply.

Computes formal, auditable vulnerability metrics and vector strings for enterprise
risk management platforms (DefectDojo, Wiz, Snyk, Jira Security).
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class AIVSSMetrics:
    score: float
    severity: str
    vector_string: str
    attack_vector: str        # Network (N) / Local (L)
    attack_complexity: str    # Low (L) / High (H)
    user_interaction: str     # None (N) / Required (R)
    confidentiality_impact: str # High (H) / Low (L) / None (N)
    integrity_impact: str     # High (H) / Low (L) / None (N)
    prompt_poisoning: str     # Explicit (E) / Paraphrased (P) / None (N)


def calculate_aivss(tool_report) -> AIVSSMetrics:
    """
    Computes formal AIVSS metrics for a single ToolReport.
    Vector Format: AIVSS:1.0/AV:N/AC:L/PR:N/UI:R/C:{H|L|N}/I:{H|L|N}/P:{E|P|N}
    """
    raw_score = tool_report.score
    
    # 1. Base Score normalized to 0.0 - 10.0 scale
    base_score = round(raw_score / 10.0, 1)
    
    # 2. Confidentiality & Integrity Impacts
    c_impact = "N"
    i_impact = "N"
    
    categories = tool_report.permissions.categories
    if "credentials" in categories or "filesystem_read" in categories or "network_egress" in categories:
        c_impact = "H"
    elif len(categories) > 0:
        c_impact = "L"
        
    if "filesystem_write" in categories or "shell_exec" in categories:
        i_impact = "H"
    elif "system_settings" in categories:
        i_impact = "L"
        
    # 3. Prompt Poisoning Vector
    findings = [f.pattern_label for f in tool_report.semantic.injection_findings]
    p_vector = "N"
    if any(f in findings for f in ["override_instructions", "sensitive_file_reference", "exfil_language"]):
        p_vector = "E"
    elif tool_report.semantic.embedding_analysis and tool_report.semantic.embedding_analysis.covert_injection_risk > 0.25:
        p_vector = "P"
        
    # 4. Construct Vector String
    vector_str = f"AIVSS:1.0/AV:N/AC:L/PR:N/UI:R/C:{c_impact}/I:{i_impact}/P:{p_vector}"
    
    # 5. Severity Rating
    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score > 0.0:
        severity = "LOW"
    else:
        severity = "NONE"
        
    return AIVSSMetrics(
        score=base_score,
        severity=severity,
        vector_string=vector_str,
        attack_vector="Network",
        attack_complexity="Low",
        user_interaction="Required",
        confidentiality_impact=c_impact,
        integrity_impact=i_impact,
        prompt_poisoning=p_vector,
    )
