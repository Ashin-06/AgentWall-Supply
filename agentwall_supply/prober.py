"""
prober.py
Live MCP Server Stdio Protocol & Remote HTTP/HTTPS Prober for AgentWall-Supply.

Supports auditing both local stdio MCP server processes and remote HTTP/SSE
MCP microservices in real-world production environments.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
from typing import Any

from .manifest import ServerManifest, ToolDef


def _readline_with_timeout(stream, timeout: float) -> str:
    q: queue.Queue = queue.Queue()
    def _target():
        try:
            line = stream.readline()
            q.put(line)
        except Exception as e:
            q.put(e)
    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise TimeoutError(f"Timed out after {timeout} seconds waiting for stdio output from server process")
    res = q.get_nowait()
    if isinstance(res, Exception):
        raise res
    return res



def probe_live_mcp_server(target: str, timeout_seconds: float = 10.0) -> ServerManifest:
    """
    Probes an MCP server target.
    - If target starts with 'http://' or 'https://', performs HTTP POST tools/list request.
    - Otherwise, spawns a local stdio process command and performs JSON-RPC 2.0 handshake.
    """
    if target.startswith("http://") or target.startswith("https://"):
        return _probe_http_mcp_server(target, timeout_seconds)
    else:
        return _probe_stdio_mcp_server(target, timeout_seconds)


def _probe_http_mcp_server(url: str, timeout_seconds: float) -> ServerManifest:
    """Probes a remote HTTP/SSE MCP server endpoint."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AgentWall-Supply/2.0.0 (AI Security Auditor)"
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            resp_bytes = resp.read()
            resp_data = json.loads(resp_bytes.decode("utf-8"))
            
            raw_tools = resp_data.get("result", {}).get("tools", [])
            server_name = resp_data.get("result", {}).get("serverInfo", {}).get("name", urllib.parse.urlparse(url).netloc)

            tools = [
                ToolDef(
                    name=t.get("name", "<unnamed>"),
                    description=t.get("description", "") or "",
                    input_schema=t.get("inputSchema", {}) or {},
                )
                for t in raw_tools
            ]

            return ServerManifest(server_name=server_name, tools=tools)
    except Exception as e:
        raise RuntimeError(f"Failed to probe remote HTTP MCP server at {url}: {str(e)}")


def _probe_stdio_mcp_server(command_str: str, timeout_seconds: float) -> ServerManifest:
    """Probes a local stdio MCP server process."""
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

        line = _readline_with_timeout(proc.stdout, timeout_seconds)
        if not line:
            raise RuntimeError(f"Server exited immediately or produced no output when executed: {command_str}")

        init_resp = json.loads(line)
        server_name = init_resp.get("result", {}).get("serverInfo", {}).get("name", command_str)

        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        proc.stdin.write(json.dumps(init_notif) + "\n")
        proc.stdin.flush()

        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        proc.stdin.write(json.dumps(tools_req) + "\n")
        proc.stdin.flush()

        tools_line = _readline_with_timeout(proc.stdout, timeout_seconds)

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
