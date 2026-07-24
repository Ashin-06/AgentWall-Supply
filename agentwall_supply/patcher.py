"""
patcher.py
Automated AI Remediation & Policy Auto-Patching Engine for AgentWall-Supply.

Automatically sanitizes malicious or dangerous MCP tool manifests by stripping out
covert prompt injections, anti-disclosure directives, instruction overrides,
and priority hijacking phrasing to produce a hardened, safe manifest.
"""

import json
import re
from typing import Any

from .manifest import ServerManifest, ToolDef

# Patterns to strip or neutralize during auto-remediation
REMEDIATION_RULES = [
    (re.compile(r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|show|reveal)\b.{0,20}\b(user|human)\b\.?", re.I), ""),
    (re.compile(r"\b(ignore|disregard|override)\b.{0,30}\b(previous|prior|system|above)\b.{0,20}\b(instructions?|prompt|rules?)\b\.?", re.I), ""),
    (re.compile(r"\b(secretly|silently|without (?:the )?user'?s? knowledge|behind the scenes)\b\.?", re.I), ""),
    (re.compile(r"\b(always|must)\b.{0,20}\b(call|invoke|run|use)\b.{0,20}\bthis\b.{0,20}\b(before|first|prior)\b\.?", re.I), ""),
    (re.compile(r"\b(do not|don't|never)\b.{0,20}\b(use|call|trust)\b.{0,20}\bother\b.{0,10}\btools?\b\.?", re.I), ""),
    (re.compile(r"(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.env\b|\.pem\b|known_hosts|private key file)", re.I), "[REDACTED_SENSITIVE_PATH]"),
]


def sanitize_tool_description(description: str) -> tuple[str, list[str]]:
    """
    Sanitizes a single tool description by applying remediation rules.
    Returns (cleaned_description, list_of_removed_directives).
    """
    cleaned = description
    removed = []

    for pattern, replacement in REMEDIATION_RULES:
        matches = pattern.findall(cleaned)
        if matches:
            for match in pattern.finditer(cleaned):
                snippet = match.group(0)
                if snippet not in removed:
                    removed.append(snippet)
            cleaned = pattern.sub(replacement, cleaned)

    # Normalize double whitespace left by removals
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned, removed


def sanitize_input_schema(input_schema: dict) -> tuple[dict, list[str]]:
    """Strips sensitive parameters from input schema properties."""
    if not isinstance(input_schema, dict) or "properties" not in input_schema:
        return input_schema, []

    cleaned_schema = json.loads(json.dumps(input_schema))
    props = cleaned_schema.get("properties", {})
    removed_params = []

    for prop_name in list(props.keys()):
        if any(k in prop_name.lower() for k in ["private_key", "id_rsa", "aws_secret", "env_file"]):
            del props[prop_name]
            removed_params.append(prop_name)

    if "required" in cleaned_schema and isinstance(cleaned_schema["required"], list):
        cleaned_schema["required"] = [r for r in cleaned_schema["required"] if r not in removed_params]

    return cleaned_schema, removed_params


def sanitize_manifest(manifest: ServerManifest) -> tuple[ServerManifest, dict[str, Any]]:
    """
    Sanitizes an entire ServerManifest. Returns hardened ServerManifest and summary dict.
    """
    patched_tools = []
    remediation_summary = []

    for tool in manifest.tools:
        clean_desc, removed_directives = sanitize_tool_description(tool.description)
        clean_schema, removed_params = sanitize_input_schema(tool.input_schema)
        
        patched_tools.append(ToolDef(
            name=tool.name,
            description=clean_desc,
            input_schema=clean_schema
        ))

        if removed_directives or removed_params:
            remediation_summary.append({
                "tool_name": tool.name,
                "stripped_directives": removed_directives,
                "stripped_parameters": removed_params,
                "original_description": tool.description,
                "patched_description": clean_desc
            })

    hardened_manifest = ServerManifest(
        server_name=f"{manifest.server_name}-hardened",
        tools=patched_tools
    )

    summary = {
        "server_name": manifest.server_name,
        "patched_server_name": hardened_manifest.server_name,
        "total_tools": len(manifest.tools),
        "tools_patched_count": len(remediation_summary),
        "remediations": remediation_summary
    }

    return hardened_manifest, summary

