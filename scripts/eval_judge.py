"""Evaluate the human gold set without using it as few-shot training data."""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def summarize(rows):
    from core.judge_check import VERDICTS
    matrix = [[sum(r["Human"] == human and r["Judge"] == predicted for r in rows)
               for predicted in VERDICTS] for human in VERDICTS[:3]]
    return {"agreement": sum(r["Agrees"] for r in rows) / len(rows),
            "n": len(rows), "labels": VERDICTS, "confusion_matrix": matrix,
            "errors": sum(r["Judge"] == "error" for r in rows),
            "needs_review": sum(r["Judge"] == "needs_review" for r in rows),
            "disagreements": [r for r in rows if not r["Agrees"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock", action="store_true", help="Scripted smoke check, not model accuracy")
    parser.add_argument("--before-system", type=Path, help="Evaluate a saved prior prompt on the same gold set")
    parser.add_argument("--output", type=Path, default=ROOT / "ml/judge_metrics.json")
    args = parser.parse_args()
    if args.mock:
        os.environ["TRIPWIRE_MOCK"] = "1"
        if args.output == ROOT / "ml/judge_metrics.json":
            args.output = ROOT / "ml/judge_metrics_mock.json"
    from core import judge
    from core.config import get_settings
    from core.judge_check import evaluate
    from core.llm import mock_mode_enabled
    if not mock_mode_enabled() and not get_settings().api_key:
        parser.error("Configure an API key, or use --mock for a scripted smoke check.")
    raw = (ROOT / "data/judge_gold.json").read_bytes()
    examples = json.loads(raw)
    current = judge.JUDGE_SYSTEM
    result = {"evaluated_at": datetime.now(timezone.utc).isoformat(), "model": get_settings().judge_model,
              "mock": mock_mode_enabled(), "gold_sha256": hashlib.sha256(raw).hexdigest(),
              "prompt_sha256": hashlib.sha256(current.encode()).hexdigest(),
              "note": "Five illustrative labels; not an independent generalisation benchmark. Errors and review count as disagreements."}
    try:
        if args.before_system:
            judge.JUDGE_SYSTEM = args.before_system.read_text(encoding="utf-8")
            result["before"] = summarize(evaluate(examples))
        judge.JUDGE_SYSTEM = current
        result["after"] = summarize(evaluate(examples))
    finally:
        judge.JUDGE_SYSTEM = current
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for phase in ["before", "after"]:
        if phase not in result:
            continue
        value = result[phase]
        print(f"{phase}: agreement {value['agreement']:.1%} ({value['n']} examples), errors {value['errors']}, review {value['needs_review']}")
        print("actual \\ predicted: " + " | ".join(value["labels"]))
        for label, row in zip(value["labels"][:3], value["confusion_matrix"]):
            print(f"{label:12} " + " | ".join(map(str, row)))
    print(f"Saved {args.output}")


if __name__ == "__main__":
    main()
