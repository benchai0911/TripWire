"""Fictional sandbox bot definitions."""
import json
from core.config import ROOT


def load_presets() -> list[dict]:
    """Load all built-in bots from the bundled JSON file."""
    return json.loads((ROOT / "data/presets.json").read_text(encoding="utf-8"))
