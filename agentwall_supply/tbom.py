"""
tbom.py
Tool Bill of Materials (Tool-BOM) generator and verifier for AgentWall-Supply.
"""

import json
import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any

TBOM_SPEC_VERSION = "1.0.0"


def sign_tbom(tbom_data: dict[str, Any], secret_key: str) -> dict[str, Any]:
    """
    Computes an HMAC-SHA256 cryptographic signature for a Tool-BOM manifest.
    """
    tbom_copy = json.loads(json.dumps(tbom_data))
    tbom_copy.pop("signature", None)
    payload_str = json.dumps(tbom_copy, sort_keys=True)
    sig = hmac.new(secret_key.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    tbom_copy["signature"] = f"hmac-sha256:{sig}"
    return tbom_copy


def verify_tbom_signature(tbom_data: dict[str, Any], secret_key: str) -> bool:
    """
    Verifies an HMAC-SHA256 signature on a Tool-BOM manifest.
    """
    if "signature" not in tbom_data:
        return False
    expected_sig = tbom_data["signature"].replace("hmac-sha256:", "")
    recomputed = sign_tbom(tbom_data, secret_key)
    actual_sig = recomputed["signature"].replace("hmac-sha256:", "")
    return hmac.compare_digest(expected_sig, actual_sig)



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
