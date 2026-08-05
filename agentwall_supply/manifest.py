"""
manifest.py
Loads and normalizes MCP server tool manifests.
"""

import json
import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash of the tool's declared contract, used for drift detection."""
        payload = json.dumps(
            {"name": self.name, "description": self.description, "input_schema": self.input_schema},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ServerManifest:
    server_name: str
    tools: list[ToolDef]

    def fingerprint(self) -> str:
        combined = "".join(sorted(t.fingerprint() for t in self.tools))
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def parse_manifest(data: Any, server_name: str | None = None) -> ServerManifest:
    """Parses a dictionary or list representation of an MCP server into a ServerManifest."""
    if isinstance(data, dict) and "result" in data and isinstance(data.get("result"), dict) and "tools" in data["result"]:
        raw_tools = data["result"]["tools"]
        name = server_name or data.get("serverInfo", {}).get("name", "mcp_server")
    elif isinstance(data, dict) and "tools" in data:
        raw_tools = data["tools"]
        name = server_name or data.get("name", "mcp_server")
    elif isinstance(data, list):
        raw_tools = data
        name = server_name or "mcp_server"
    else:
        raise ValueError("Unrecognized manifest shape")

    if not isinstance(raw_tools, list):
        raw_tools = []

    tools = [
        ToolDef(
            name=t.get("name", "<unnamed>"),
            description=t.get("description", "") or "",
            input_schema=t.get("inputSchema", t.get("input_schema", {})) or {},
        )
        for t in raw_tools
        if isinstance(t, dict)
    ]
    return ServerManifest(server_name=name, tools=tools)


def load_manifest(path: str, server_name: str | None = None) -> ServerManifest:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return parse_manifest(data, server_name=server_name or path)

