# AgentWall-Supply (v2.0)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-brightgreen.svg)](https://www.python.org/)
[![Tool-BOM Spec](https://img.shields.io/badge/Tool--BOM-v1.0-cyan.svg)](https://agentwall.dev/schemas/tool-bom-v1.json)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-purple.svg)](https://sarifweb.azurewebsites.net/)

**AgentWall-Supply** is an enterprise-grade **AI Supply Chain Security, Tool-BOM Assurance & Auto-Remediation Platform** for Model Context Protocol (MCP) servers and Agentic AI tools.

While runtime firewalls filter messages after execution starts, **AgentWall-Supply** secures the upstream AI supply chain: auditing third-party MCP tool definitions before installation, auto-patching prompt poisoning directives, detecting rug-pull schema drift over time, fuzzing tool definitions with honeytoken credentials, and exporting SARIF reports into GitHub Security Code Scanning tabs.

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
       ┌───────────────────┬─────────────┼─────────────┬───────────────────┐
       ▼                   ▼             ▼             ▼                   ▼
┌───────────────┐ ┌───────────────┐ ┌──────────┐ ┌───────────────┐ ┌────────────────┐
│ CLI / CI      │ │ Auto-Patcher  │ │ Tool-BOM │ │ SARIF Exporter│ │ Web Dashboard  │
│ (--fail-on)   │ │ (Auto-Fix)    │ │ (Cyclone)│ │ (GitHub Scan) │ │ (Glassmorphic) │
└───────────────┘ └───────────────┘ └──────────┘ └───────────────┘ └────────────────┘
```

1. **Automated AI Remediation & Auto-Patcher (`agentwall_supply/patcher.py`)**:
   - Automatically sanitizes malicious or dangerous MCP tool manifests, stripping out anti-disclosure directives, system overrides, secrecy rules, and sensitive path references to produce a hardened manifest (`python -m agentwall_supply patch`).

2. **Vector Semantic Distance Engine (`agentwall_supply/embeddings.py`)**:
   - Zero-dependency hybrid n-gram TF-IDF & vector distance semantic analyzer for covert prompt injections.

3. **Dynamic Sandboxing & Honeytoken Traps (`agentwall_supply/sandbox.py`)**:
   - Isolated runtime execution environment populated with synthetic honeytoken credentials (`AKIA...`, `id_rsa`, `.env` secrets) to catch credential traps, SSRF, and command execution.

4. **Tool-BOM (Software Bill of Materials for AI Tools) (`agentwall_supply/tbom.py`)**:
   - Generates standardized CycloneDX-AI / SPDX compliant Tool-BOM manifests with cryptographic fingerprints and attestation records.

5. **Rug-Pull Baseline & Silent Drift Detector (`agentwall_supply/drift.py`)**:
   - Fingerprints tool contracts (SHA-256) per server to catch silent description/schema modifications.

6. **Enterprise Security Policy & SARIF Exporter (`agentwall_supply/policy.py`)**:
   - Enforces customizable security compliance policies and exports native **SARIF v2.1.0** reports for GitHub Security tabs.

7. **Interactive Web Security Dashboard & REST API (`agentwall_supply/server.py`)**:
   - Embedded single-page web security application (`http://localhost:8500`) with real-time score gauges, threat heatmaps, dynamic execution logs, auto-patching API, and Tool-BOM exporter.

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

### 2. Auto-Remediate & Patch Malicious Manifests

Sanitize and output a hardened manifest:
```bash
python -m agentwall_supply patch samples/malicious_calculator_server.json --output hardened_server.json
```

### 3. Probe Live Local or Remote MCP Server

Audit live local stdio process or remote HTTP endpoint:
```bash
python -m agentwall_supply probe "npx -y @modelcontextprotocol/server-filesystem /path"
python -m agentwall_supply probe https://mcp.example.com
```

### 4. Run Dynamic Sandbox Fuzzing

Fuzz server tools and trace runtime side-effects:
```bash
python -m agentwall_supply sandbox samples/covert_exfil_server.json
```

### 5. Generate or Verify Tool-BOM (SBOM)

Generate Tool-BOM JSON:
```bash
python -m agentwall_supply tbom samples/benign_weather_server.json --output tool_bom.json
```

### 6. Launch Web Security Dashboard

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
