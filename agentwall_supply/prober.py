"""
prober.py
Live MCP Server Stdio Protocol Prober for AgentWall-Supply.

Spawns a live MCP server process over standard I/O, performs the JSON-RPC 2.0
handshake (`initialize` & `tools/list`), captures the live tool manifest in real-time,
and passes it to the AgentWall-Supply audit engine.
"""

import json
import os
import subprocess
import sys
import time
from typing import Any

from .manifest import ServerManifest, ToolDef


def probe_live_mcp_server(command_str: str, timeout_seconds: float = 10.0) -> ServerManifest:
    """
    Connects to a live MCP server process via stdio JSON-RPC 2.0, performs initialization,
    sends `tools/list`, and returns a ServerManifest.
    """
    proc = subprocess.Popen(
        command_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        # Step 1: Send MCP JSON-RPC 2.0 Initialize Request
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "AgentWall-Supply Prober", "version": "2.0.0"}
            }
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()

        # Read initialize response
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError(f"Server exited immediately or produced no output when executed: {command_str}")

        init_resp = json.loads(line)
        server_name = init_resp.get("result", {}).get("serverInfo", {}).get("name", command_str)

        # Step 2: Send initialized notification
        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        proc.stdin.write(json.dumps(init_notif) + "\n")
        proc.stdin.flush()

        # Step 3: Send tools/list request
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        proc.stdin.write(json.dumps(tools_req) + "\n")
        proc.stdin.flush()

        tools_line = proc.stdout.readline()
        if not tools_line:
            raise RuntimeError(f"Server closed connection during tools/list request: {command_str}")

        tools_resp = json.loads(tools_line)
        raw_tools = tools_resp.get("result", {}).get("tools", [])

        tools = [
            ToolDef(
                name=t.get("name", "<unnamed>"),
                description=t.get("description", "") or "",
                input_schema=t.get("inputSchema", {}) or {},
            )
            for t in raw_tools
        ]

        return ServerManifest(server_name=server_name, tools=tools)

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
