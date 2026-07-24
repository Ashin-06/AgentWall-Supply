# AgentWall-Supply (v2.0)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-brightgreen.svg)](https://www.python.org/)
[![Tool-BOM Spec](https://img.shields.io/badge/Tool--BOM-v1.0-cyan.svg)](https://agentwall.dev/schemas/tool-bom-v1.json)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-purple.svg)](https://sarifweb.azurewebsites.net/)

**AgentWall-Supply** is an enterprise-grade **AI Supply Chain Security & Tool-BOM (Software Bill of Materials for AI Tools) Assurance Suite** for Model Context Protocol (MCP) servers and Agentic AI tools.

While runtime firewalls filter messages after execution starts, **AgentWall-Supply** secures the upstream AI supply chain: auditing third-party MCP tool definitions before installation, detecting rug-pull schema drift over time, fuzzing tool definitions with honeytoken credentials, and exporting SARIF reports into GitHub Security Code Scanning tabs.

---

## 🛡️ Key Features

```
                    ┌─────────────────────────────────────────┐
                    │      MCP Server Tool Manifest           │
                    └────────────────────┬────────────────────┘
                                         │
       ┌─────────────────────────────────┼─────────────────────────────────┐
       │                                 │                                 │
       ▼                                 ▼                                 ▼
┌───────────────┐               ┌─────────────────┐               ┌─────────────────┐
│ Static Engine │               │ Vector Engine   │               │ Dynamic Sandbox │
│ (Regex & Scope│               │ (TF-IDF & N-gram│               │ (Honeytokens &  │
│ Inference)    │               │ Embeddings)     │               │ Fuzzing Engine) │
└───────┬───────┘               └────────┬────────┘               └────────┬────────┘
        │                                │                                 │
        └────────────────────────────────┼─────────────────────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │ Transparent Scorer (0-100 Risk) │
                        └────────────────┬────────────────┘
                                         │
       ┌─────────────────────────────────┼─────────────────────────────────┼──────────────────┐
       ▼                                 ▼                                 ▼                  ▼
┌───────────────┐               ┌─────────────────┐               ┌─────────────────┐┌────────────────┐
│ CLI / CI      │               │ Tool-BOM        │               │ SARIF Exporter  ││ Web Dashboard  │
│ (--fail-on)   │               │ (CycloneDX-AI)  │               │ (GitHub CodeScan││ (Glassmorphic) │
└───────────────┘               └─────────────────┘               └─────────────────┘└────────────────┘
```

1. **Vector Semantic Distance Engine (`agentwall_supply/embeddings.py`)**:
   - Zero-dependency hybrid n-gram TF-IDF & vector distance semantic analyzer.
   - Detects covert prompt injections, jailbreaks, anti-disclosure directives, and paraphrased exfiltration instructions.

2. **Dynamic Sandboxing & Honeytoken Traps (`agentwall_supply/sandbox.py`)**:
   - Isolated runtime execution environment populated with synthetic honeytoken credentials (`AKIA...`, `id_rsa`, `.env` secrets).
   - Automatically detects parameter traps soliciting sensitive credentials, SSRF/network egress attempts, and shell process spawning.

3. **Tool-BOM (Software Bill of Materials for AI Tools) (`agentwall_supply/tbom.py`)**:
   - Generates standardized CycloneDX-AI / SPDX compliant Tool-BOM manifests containing cryptographic fingerprints, attestation records, and capability matrices.
   - Verifies server integrity against live manifests to catch tampered tool definitions (`python -m agentwall_supply tbom --verify`).

4. **Rug-Pull Baseline & Silent Drift Detector (`agentwall_supply/drift.py`)**:
   - Fingerprints tool contracts (SHA-256) per server to catch silent description/schema modifications between scans.

5. **Enterprise Security Policy & SARIF Exporter (`agentwall_supply/policy.py`)**:
   - Enforces customizable security compliance policies (`max_score`, `forbidden_scopes`).
   - Exports native **SARIF v2.1.0** reports for seamless integration into GitHub Code Scanning security tabs.

6. **Interactive Web Security Dashboard & REST API (`agentwall_supply/server.py`)**:
   - Embedded single-page web security application (`http://localhost:8500`) with real-time score gauges, threat heatmaps, dynamic execution logs, and Tool-BOM exporter.

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Ashin-06/AgentWall-Supply.git
cd AgentWall-Supply
python -m pip install -e .
```

### 1. Run Security Scan

Scan an MCP tool manifest:
```bash
python -m agentwall_supply scan samples/malicious_calculator_server.json
```

Export SARIF report for GitHub Code Scanning:
```bash
python -m agentwall_supply scan samples/malicious_calculator_server.json --sarif scan_results.sarif
```

Fail CI build on HIGH or CRITICAL risk:
```bash
python -m agentwall_supply scan samples/malicious_calculator_server.json --fail-on HIGH
```

### 2. Run Dynamic Sandbox Fuzzing

Fuzz server tools and trace runtime side-effects:
```bash
python -m agentwall_supply sandbox samples/covert_exfil_server.json
```

### 3. Generate or Verify Tool-BOM (SBOM)

Generate Tool-BOM JSON:
```bash
python -m agentwall_supply tbom samples/benign_weather_server.json --output tool_bom.json
```

Verify server integrity against exported Tool-BOM:
```bash
python -m agentwall_supply tbom samples/benign_weather_server.json --verify tool_bom.json
```

### 4. Evaluate Enterprise Security Policy

Validate against corporate compliance rulebook:
```bash
python -m agentwall_supply policy samples/malicious_calculator_server.json
```

### 5. Launch Web Security Dashboard

Launch interactive dashboard:
```bash
python -m agentwall_supply serve --port 8500
```
Open **`http://localhost:8500`** in your browser.

---

## 🧪 Unit Tests

Run all unit tests:
```bash
python -m unittest discover -s tests -v
```

---

## 📄 License

[MIT License](LICENSE)
