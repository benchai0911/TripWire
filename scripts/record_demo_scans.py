"""Rebuild clearly labelled fictional mock demos without API calls or model artifacts."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["TRIPWIRE_MOCK"] = "1"
os.environ["TRIPWIRE_CACHE"] = "0"

from core import firewall
from core.attacks import load_attacks, load_benign
from core.presets import load_presets
from core.scanner import run_scan
from core.hardener import harden
from core.scan_archive import encode
from core.config import ROOT


def main():
    bot = load_presets()[0]
    attacks, benign = load_attacks(), load_benign(bot["id"])
    context = {"bot_name": bot["name"] + " · Recorded mock demo", "rules": bot["rules"],
               "attacks": attacks, "benign": benign, "knowledge_text": "", "poisoned_document": False}
    original_load, original_score = firewall.load_model, firewall.score
    # An explicitly scripted input filter makes fixtures reproducible without a joblib artifact.
    firewall.load_model = lambda: True
    blocked = {a["prompt"] for a in attacks if a["category"] in {"prompt_leak", "instruction_override"}}
    firewall.score = lambda text: .99 if text in blocked else .01
    directory = ROOT / "data/demo_scans"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        prompt = bot["system_prompt"]
        for filename, mode, enabled in [("kopi_baseline.json", "baseline", False),
                ("kopi_hardened.json", "hardened_prompt", False), ("kopi_firewall.json", "hardened_prompt_firewall", True)]:
            if mode == "hardened_prompt":
                prompt = harden(prompt, [])["hardened_prompt"]
            scan = run_scan(prompt, bot["rules"], bot["secret_note"], attacks, benign, enabled, .5, mode)
            assert scan.api_calls == 0
            scan.provenance = "recorded_demo"
            (directory / filename).write_text(encode(scan, context), encoding="utf-8")
        print("Recorded three synthetic mock demos; API calls: 0.")
    finally:
        firewall.load_model, firewall.score = original_load, original_score


if __name__ == "__main__":
    main()
