"""
exporters.py
JUnit XML Test Exporter & SPDX v2.3 SBOM Exporter for AgentWall-Supply.

Supports exporting security audit results into standard JUnit XML format for CI/CD
pipeline integration (Jenkins, GitLab CI, Azure DevOps) and SPDX v2.3 JSON format.
"""

import json
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
from typing import Any


def export_junit_xml(server_report) -> str:
    """
    Exports a ServerReport into JUnit XML format for CI test reporting.
    """
    testsuite = ET.Element("testsuite", {
        "name": f"AgentWall-Supply.{server_report.server_name}",
        "tests": str(len(server_report.tool_reports)),
        "failures": str(sum(1 for t in server_report.tool_reports if t.score >= 45)),
        "errors": "0",
        "time": "0.05",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    for tr in server_report.tool_reports:
        testcase = ET.SubElement(testsuite, "testcase", {
            "classname": f"mcp.server.{server_report.server_name}",
            "name": tr.tool.name,
            "time": "0.01"
        })

        if tr.score >= 45:
            failure_msg = f"Tool '{tr.tool.name}' failed security audit with risk score {tr.score}/100 ({tr.tier})."
            findings_str = ", ".join(f.pattern_label for f in tr.semantic.injection_findings)
            failure = ET.SubElement(testcase, "failure", {
                "message": failure_msg,
                "type": "SecurityRiskViolation"
            })
            failure.text = f"Flagged Patterns: {findings_str}\nScope Requested: {', '.join(sorted(tr.permissions.categories))}"

    return ET.tostring(testsuite, encoding="unicode", xml_declaration=True)


def export_spdx_json(manifest, server_report) -> dict[str, Any]:
    """
    Exports manifest into SPDX v2.3 JSON format for software supply chain management.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    packages = []
    for tr in server_report.tool_reports:
        pkg = {
            "SPDXID": f"SPDXRef-Tool-{tr.tool.name}",
            "name": tr.tool.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{
                "algorithm": "SHA256",
                "checksumValue": tr.tool.fingerprint()
            }],
            "summary": tr.tool.description,
            "copyrightText": "NOASSERTION",
        }
        packages.append(pkg)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"AgentWall-Supply-BOM-{manifest.server_name}",
        "documentNamespace": f"https://agentwall.dev/spdx/{manifest.server_name}-{now}",
        "creationInfo": {
            "creators": ["Tool: AgentWall-Supply-2.0.0"],
            "created": now
        },
        "packages": packages
    }
