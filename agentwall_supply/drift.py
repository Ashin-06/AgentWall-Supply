"""
drift.py
Baseline storage & fingerprint diffing for detecting rug-pull attacks.
"""

import json
import os
from dataclasses import dataclass, field

from .manifest import ServerManifest

DEFAULT_BASELINE_PATH = ".agentwall_baseline.json"


@dataclass
class DriftResult:
    is_new_server: bool = False
    added_tools: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    changed_tools: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.added_tools or self.removed_tools or self.changed_tools)


def _load_baseline(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}



def _save_baseline(path: str, data: dict) -> None:
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)



def check_and_update_baseline(manifest: ServerManifest, path: str = DEFAULT_BASELINE_PATH,
                               update: bool = True) -> DriftResult:
    store = _load_baseline(path)
    key = manifest.server_name
    current = {t.name: t.fingerprint() for t in manifest.tools}

    if key not in store:
        result = DriftResult(is_new_server=True)
        if update:
            store[key] = current
            _save_baseline(path, store)
        return result

    previous = store[key]
    prev_names = set(previous)
    curr_names = set(current)

    added = sorted(curr_names - prev_names)
    removed = sorted(prev_names - curr_names)
    changed = sorted(
        name for name in (curr_names & prev_names)
        if previous[name] != current[name]
    )

    result = DriftResult(added_tools=added, removed_tools=removed, changed_tools=changed)

    if update:
        store[key] = current
        _save_baseline(path, store)

    return result
