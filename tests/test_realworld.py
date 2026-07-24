"""
test_realworld.py
Tests real-world MCP server probing, config loading, and production manifest scanning.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentwall_supply.manifest import load_manifest
from agentwall_supply.drift import check_and_update_baseline
from agentwall_supply.scorer import score_server
from agentwall_supply.config import load_config
from agentwall_supply.prober import probe_live_mcp_server

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


class TestRealWorldAgentWallSupply(unittest.TestCase):

    def test_realworld_github_mcp_server_scan(self):
        path = os.path.join(SAMPLES_DIR, "realworld_github_mcp_server.json")
        manifest = load_manifest(path)
        drift = check_and_update_baseline(manifest, update=False)
        report = score_server(manifest, drift)

        self.assertEqual(report.score, 0)
        self.assertEqual(report.tier, "LOW")
        self.assertEqual(len(report.tool_reports), 2)

    def test_config_loader(self):
        config = load_config("non_existent_config.json")
        self.assertEqual(config.max_score, 40)
        self.assertEqual(config.fail_on, "HIGH")

    def test_prober_invalid_http_endpoint_handling(self):
        with self.assertRaises(RuntimeError) as ctx:
            probe_live_mcp_server("http://127.0.0.1:59999/non_existent_endpoint", timeout_seconds=0.5)
        self.assertIn("Failed to probe remote HTTP MCP server", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
