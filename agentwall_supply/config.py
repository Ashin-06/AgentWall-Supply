"""
config.py
Project Configuration Loader for AgentWall-Supply.

Loads project-level configuration settings from `.agentwall.json` if present in the
working directory, allowing teams to check in custom policy thresholds and overrides.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentWallConfig:
    max_score: int = 40
    fail_on: str = "HIGH"
    baseline_file: str = ".agentwall_baseline.json"
    forbidden_scopes: list[str] = field(default_factory=lambda: ["credentials", "shell_exec"])
    ignore_patterns: list[str] = field(default_factory=list)


DEFAULT_CONFIG_PATH = ".agentwall.json"


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> AgentWallConfig:
    """
    Loads project config file if exists; returns default AgentWallConfig otherwise.
    """
    if not os.path.exists(config_path):
        return AgentWallConfig()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return AgentWallConfig(
            max_score=data.get("max_score", 40),
            fail_on=data.get("fail_on", "HIGH"),
            baseline_file=data.get("baseline_file", ".agentwall_baseline.json"),
            forbidden_scopes=data.get("forbidden_scopes", ["credentials", "shell_exec"]),
            ignore_patterns=data.get("ignore_patterns", []),
        )
    except Exception:
        return AgentWallConfig()
