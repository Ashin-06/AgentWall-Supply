"""
tbom.py
Tool Bill of Materials (Tool-BOM) generator and verifier for AgentWall-Supply.
"""

import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

TBOM_SPEC_VERSION = "1.0.0"


def generate_tbom(manifest, server_report) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    tbom_id = f"urn:uuid:{uuid.uuid4()}"

    tools_bom = []
    for tr in server_report.tool_reports:
        tool_entry = {
            "name": tr.tool.name,
            "description": tr.tool.description,
            "fingerprint": f"sha256:{tr.tool.fingerprint()}",
            "inferredCapabilities": sorted(tr.permissions.categories),
            "riskAssessment": {
                "score": tr.score,
                "tier": tr.tier,
                "injectionFindingsCount": len(tr.semantic.injection_findings),
                "mismatchFlag": tr.semantic.mismatch_flag,
                "driftFlag": tr.drift_flag,
            },
            "inputSchema": tr.tool.input_schema,
            "attestation": {
                "verifiedClean": tr.score == 0,
                "policyCompliance": "PASSED" if tr.score < 45 else "FAILED",
            }
        }
        tools_bom.append(tool_entry)

    tbom_manifest = {
        "$schema": "https://agentwall.dev/schemas/tool-bom-v1.json",
        "bomFormat": "Tool-BOM",
        "specVersion": TBOM_SPEC_VERSION,
        "serialNumber": tbom_id,
        "timestamp": now,
        "metadata": {
            "component": {
                "name": manifest.server_name,
                "type": "mcp-server",
                "fingerprint": f"sha256:{manifest.fingerprint()}",
                "toolCount": len(manifest.tools),
            },
            "tooling": {
                "vendor": "AgentWall",
                "name": "AgentWall-Supply",
                "version": "2.0.0",
            }
        },
        "securitySummary": {
            "serverRiskScore": server_report.score,
            "serverRiskTier": server_report.tier,
            "driftDetected": server_report.drift.has_drift,
            "complianceStatus": "APPROVED" if server_report.score < 45 else "QUARANTINED",
        },
        "tools": tools_bom,
    }

    return tbom_manifest


def verify_tbom(tbom_data: dict[str, Any], current_manifest) -> dict[str, Any]:
    tbom_tools = {t["name"]: t for t in tbom_data.get("tools", [])}
    curr_tools = {t.name: t for t in current_manifest.tools}

    missing_in_current = sorted(set(tbom_tools) - set(curr_tools))
    new_in_current = sorted(set(curr_tools) - set(tbom_tools))
    tampered_tools = []

    for name in set(tbom_tools) & set(curr_tools):
        tbom_fp = tbom_tools[name].get("fingerprint", "").replace("sha256:", "")
        curr_fp = curr_tools[name].fingerprint()
        if tbom_fp != curr_fp:
            tampered_tools.append({
                "name": name,
                "expectedFingerprint": tbom_fp,
                "actualFingerprint": curr_fp
            })

    valid = not (missing_in_current or new_in_current or tampered_tools)

    return {
        "valid": valid,
        "serverName": current_manifest.server_name,
        "tbomSerialNumber": tbom_data.get("serialNumber", "unknown"),
        "tamperedTools": tampered_tools,
        "missingTools": missing_in_current,
        "addedTools": new_in_current,
        "verificationStatus": "VERIFIED" if valid else "TAMPER_DETECTED"
    }
