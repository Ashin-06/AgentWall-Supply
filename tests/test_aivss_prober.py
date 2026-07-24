"""
test_aivss_prober.py
Tests AIVSS vector calculations, JUnit XML exporter, and SPDX v2.3 JSON generator.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentwall_supply.manifest import load_manifest
from agentwall_supply.drift import check_and_update_baseline
from agentwall_supply.scorer import score_server
from agentwall_supply.aivss import calculate_aivss
from agentwall_supply.exporters import export_junit_xml, export_spdx_json

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


class TestAIVSSAndExporters(unittest.TestCase):

    def test_aivss_vector_calculation(self):
        path = os.path.join(SAMPLES_DIR, "malicious_calculator_server.json")
        manifest = load_manifest(path)
        drift = check_and_update_baseline(manifest, update=False)
        report = score_server(manifest, drift)

        tool_report = report.tool_reports[0]
        aivss = calculate_aivss(tool_report)

        self.assertTrue(aivss.vector_string.startswith("AIVSS:1.0/"))
        self.assertIn(aivss.severity, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertEqual(aivss.confidentiality_impact, "H")

    def test_junit_xml_exporter(self):
        path = os.path.join(SAMPLES_DIR, "malicious_calculator_server.json")
        manifest = load_manifest(path)
        drift = check_and_update_baseline(manifest, update=False)
        report = score_server(manifest, drift)

        xml_output = export_junit_xml(report)
        self.assertIn("<?xml version=", xml_output)
        self.assertIn("testsuite", xml_output)
        self.assertIn("add_numbers", xml_output)

    def test_spdx_json_exporter(self):
        path = os.path.join(SAMPLES_DIR, "benign_weather_server.json")
        manifest = load_manifest(path)
        drift = check_and_update_baseline(manifest, update=False)
        report = score_server(manifest, drift)

        spdx = export_spdx_json(manifest, report)
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertGreater(len(spdx["packages"]), 0)


if __name__ == "__main__":
    unittest.main()
