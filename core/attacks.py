"""Load the fixed, non-harmful attack library and legitimate questions."""
import json
from core.config import ROOT


def load_attacks(categories: list[str] | None = None) -> list[dict]:
    """Return all attacks or only selected categories; an empty selection is empty."""
    rows = json.loads((ROOT / "data/attacks.json").read_text(encoding="utf-8"))
    return rows if categories is None else [r for r in rows if r["category"] in categories]


def load_benign(preset_id: str | None = None) -> list[dict]:
    """Load legitimate prompts, optionally filtered to a sandbox bot."""
    rows = json.loads((ROOT / "data/benign_prompts.json").read_text(encoding="utf-8"))
    return rows if preset_id is None else [r for r in rows if r["preset_id"] == preset_id]
