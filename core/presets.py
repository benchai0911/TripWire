"""Fictional sandbox bot definitions."""
import json
from core.config import ROOT


def load_presets() -> list[dict]:
    """Load all built-in bots from the bundled JSON file."""
    return json.loads((ROOT / "data/presets.json").read_text(encoding="utf-8"))


def load_test_presets() -> list[dict]:
    """Load opt-in testing scenarios, including their expected aggregate outcomes."""
    return json.loads((ROOT / "data/test_presets.json").read_text(encoding="utf-8"))
