"""
cli.py
Command-line entrypoint for AgentWall-Supply v2.0.

Usage:
    python -m agentwall_supply scan <manifest.json> [--name SERVER_NAME] [--baseline PATH] [--json] [--sarif PATH] [--no-update]
    python -m agentwall_supply sandbox <manifest.json> [--json]
    python -m agentwall_supply tbom <manifest.json> [--output PATH] [--verify FILE]
    python -m agentwall_supply policy <manifest.json>
    python -m agentwall_supply serve [--port 8500]
"""

import argparse
import json
import sys

from .manifest import load_manifest
from .drift import check_and_update_baseline, DEFAULT_BASELINE_PATH
from .scorer import score_server
from .report import render_markdown, report_to_dict
from .sandbox import MCPToolSandbox
from .tbom import generate_tbom, verify_tbom
from .server import run_server
from .policy import evaluate_policy, export_sarif, DEFAULT_ENTERPRISE_POLICY
from .prober import probe_live_mcp_server
from .exporters import export_junit_xml, export_spdx_json


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="agentwall-supply",
        description="AgentWall-Supply — AI Supply Chain Security & Tool-BOM Assurance Suite (v2.0)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Subcommand: scan
    scan = sub.add_parser("scan", help="Scan an MCP server tool manifest")
    scan.add_argument("manifest_path", help="Path to manifest JSON file")
    scan.add_argument("--name", default=None, help="Override server name for baseline tracking")
    scan.add_argument("--baseline", default=DEFAULT_BASELINE_PATH, help="Path to baseline store JSON")
    scan.add_argument("--json", action="store_true", help="Output JSON report format")
    scan.add_argument("--sarif", default=None, help="Save report in SARIF v2.1.0 format for GitHub Security Scanning")
    scan.add_argument("--junit", default=None, help="Save report in JUnit XML format for CI test reporting")
    scan.add_argument("--spdx", default=None, help="Save report in SPDX v2.3 JSON SBOM format")
    scan.add_argument("--no-update", action="store_true", help="Don't update baseline store after scanning")
    scan.add_argument("--fail-on", default=None, choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                      help="Exit with code 1 if server risk tier reaches or exceeds level")

    # Subcommand: probe
    probe_cmd = sub.add_parser("probe", help="Probe a live MCP server process via stdio protocol and run audit")
    probe_cmd.add_argument("server_command", help="Executable command to spawn live MCP server process (e.g. 'python server.py')")
    probe_cmd.add_argument("--json", action="store_true", help="Output JSON report format")


    # Subcommand: sandbox
    sandbox_cmd = sub.add_parser("sandbox", help="Run dynamic fuzzing & honeytoken sandbox on an MCP server manifest")
    sandbox_cmd.add_argument("manifest_path", help="Path to manifest JSON file")
    sandbox_cmd.add_argument("--json", action="store_true", help="Output JSON results")

    # Subcommand: tbom
    tbom_cmd = sub.add_parser("tbom", help="Generate or verify a Tool-BOM (SBOM for AI Tools) manifest")
    tbom_cmd.add_argument("manifest_path", help="Path to manifest JSON file")
    tbom_cmd.add_argument("--output", default=None, help="Save Tool-BOM JSON to specified path")
    tbom_cmd.add_argument("--verify", default=None, help="Verify manifest against existing Tool-BOM JSON file")

    # Subcommand: policy
    policy_cmd = sub.add_parser("policy", help="Evaluate server manifest against enterprise security policy")
    policy_cmd.add_argument("manifest_path", help="Path to manifest JSON file")

    # Subcommand: serve
    serve_cmd = sub.add_parser("serve", help="Launch interactive Web Security Dashboard & REST API server")
    serve_cmd.add_argument("--port", type=int, default=8500, help="Port to run web server on (default 8500)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        manifest = load_manifest(args.manifest_path, server_name=args.name)
        drift = check_and_update_baseline(manifest, path=args.baseline, update=not args.no_update)
        report = score_server(manifest, drift)

        if args.sarif:
            sarif_json = export_sarif(report)
            with open(args.sarif, "w", encoding="utf-8") as f:
                json.dump(sarif_json, f, indent=2)
            print(f"SARIF report exported to {args.sarif}")
        elif args.junit:
            xml_str = export_junit_xml(report)
            with open(args.junit, "w", encoding="utf-8") as f:
                f.write(xml_str)
            print(f"JUnit XML report exported to {args.junit}")
        elif args.spdx:
            spdx_json = export_spdx_json(manifest, report)
            with open(args.spdx, "w", encoding="utf-8") as f:
                json.dump(spdx_json, f, indent=2)
            print(f"SPDX v2.3 SBOM report exported to {args.spdx}")
        elif args.json:
            print(json.dumps(report_to_dict(report), indent=2))
        else:
            print(render_markdown(report))

        if args.fail_on:
            tier_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if tier_order.index(report.tier) >= tier_order.index(args.fail_on):
                sys.exit(1)

    elif args.command == "probe":
        manifest = probe_live_mcp_server(args.server_command)
        drift = check_and_update_baseline(manifest)
        report = score_server(manifest, drift)
        if args.json:
            print(json.dumps(report_to_dict(report), indent=2))
        else:
            print(render_markdown(report))


    elif args.command == "sandbox":
        manifest = load_manifest(args.manifest_path)
        sandbox = MCPToolSandbox(manifest)
        results = sandbox.run_sandbox_suite()
        output_data = {
            "server": manifest.server_name,
            "sandbox_results": {
                k: {
                    "clean": v.sandboxed_clean,
                    "violations": [{"type": vio.violation_type, "details": vio.details} for vio in v.violations]
                }
                for k, v in results.items()
            }
        }
        print(json.dumps(output_data, indent=2))

    elif args.command == "tbom":
        manifest = load_manifest(args.manifest_path)
        if args.verify:
            with open(args.verify, "r", encoding="utf-8") as f:
                tbom_data = json.load(f)
            verification = verify_tbom(tbom_data, manifest)
            print(json.dumps(verification, indent=2))
            if not verification["valid"]:
                sys.exit(1)
        else:
            drift = check_and_update_baseline(manifest, update=False)
            report = score_server(manifest, drift)
            tbom_json = generate_tbom(manifest, report)
            output_str = json.dumps(tbom_json, indent=2)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_str)
                print(f"Tool-BOM successfully exported to {args.output}")
            else:
                print(output_str)

    elif args.command == "policy":
        manifest = load_manifest(args.manifest_path)
        drift = check_and_update_baseline(manifest, update=False)
        report = score_server(manifest, drift)
        violations = evaluate_policy(report, DEFAULT_ENTERPRISE_POLICY)
        res_data = {
            "server": manifest.server_name,
            "policy": DEFAULT_ENTERPRISE_POLICY.rule_id,
            "compliant": len(violations) == 0,
            "violations": [
                {"tool": v.tool_name, "type": v.violation_type, "message": v.message}
                for v in violations
            ]
        }
        print(json.dumps(res_data, indent=2))
        if violations:
            sys.exit(1)

    elif args.command == "serve":
        run_server(port=args.port)


if __name__ == "__main__":
    main()
