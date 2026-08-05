"""
test_production_edgecases.py
Tests edge-case robustness, in-memory manifest parsing, REST API handlers,
and production timeout protections for AgentWall-Supply.
"""

import io
import json
import os
import sys
import tempfile
import unittest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentwall_supply.manifest import parse_manifest, ServerManifest, ToolDef
from agentwall_supply.drift import check_and_update_baseline
from agentwall_supply.sandbox import MCPToolSandbox

from agentwall_supply.prober import _readline_with_timeout, probe_live_mcp_server
from agentwall_supply.server import AgentWallRequestHandler
from io import BytesIO


class MockRequest:
    def __init__(self, body_bytes: bytes):
        self.rfile = BytesIO(body_bytes)
        self.wfile = BytesIO()
        self.headers = {"Content-Length": str(len(body_bytes))}

    def make_handler(self, path="/api/scan"):
        handler = AgentWallRequestHandler.__new__(AgentWallRequestHandler)
        handler.rfile = self.rfile
        handler.wfile = self.wfile
        handler.headers = self.headers
        handler.path = path
        handler.request_version = "HTTP/1.1"
        handler.client_address = ("127.0.0.1", 12345)
        
        # Mock response helper methods
        def send_response(code):
            handler.status_code = code
        def send_header(k, v):
            pass
        def end_headers():
            pass
            
        handler.send_response = send_response
        handler.send_header = send_header
        handler.end_headers = end_headers
        return handler


class TestProductionEdgeCases(unittest.TestCase):

    def test_parse_manifest_in_memory_and_malformed(self):
        data = {
            "name": "in_memory_server",
            "tools": [
                {"name": "clean_tool", "description": "Just a tool", "inputSchema": {}},
                "invalid_non_dict_tool",
                None
            ]
        }
        manifest = parse_manifest(data)
        self.assertEqual(manifest.server_name, "in_memory_server")
        self.assertEqual(len(manifest.tools), 1)
        self.assertEqual(manifest.tools[0].name, "clean_tool")

    def test_sandbox_non_dict_properties(self):
        tool = ToolDef(name="bad_schema", description="Test", input_schema={"properties": None})
        manifest = ServerManifest(server_name="test", tools=[tool])
        sandbox = MCPToolSandbox(manifest)
        res = sandbox.fuzz_tool(tool)
        self.assertTrue(res.sandboxed_clean)

    def test_baseline_nested_directory_creation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_path = os.path.join(tmpdir, "nested", "sub", "baseline.json")
            manifest = parse_manifest([{"name": "t", "description": "d"}], server_name="test_server")
            drift = check_and_update_baseline(manifest, path=nested_path, update=True)
            self.assertTrue(os.path.exists(nested_path))
            self.assertTrue(drift.is_new_server)

    def test_server_do_post_in_memory(self):
        payload = json.dumps({"name": "api_test", "tools": [{"name": "tool1", "description": "desc"}]}).encode("utf-8")
        req = MockRequest(payload)
        handler = req.make_handler("/api/scan")
        handler.do_POST()
        
        resp_data = json.loads(req.wfile.getvalue().decode("utf-8"))
        self.assertEqual(resp_data["server_name"], "api_test")
        self.assertEqual(resp_data["tier"], "LOW")

    def test_readline_with_timeout(self):
        stream = io.TextIOWrapper(BytesIO(b"hello world\n"))
        line = _readline_with_timeout(stream, timeout=1.0)
        self.assertEqual(line, "hello world\n")



if __name__ == "__main__":
    unittest.main()
