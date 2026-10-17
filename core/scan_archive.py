"""Bounded JSON snapshots and explicitly recorded mock demos; no executable imports."""
import json
import re
import math
from dataclasses import asdict, fields
from core.scanner import ScanResult, MODES
from core.recommender import redact
from core.config import ROOT

VERDICTS = {"resisted", "partial", "compromised", "blocked", "blocked_output", "needs_review", "error", "not_tested"}


def encode(scan, context, comparison=None, redactions=()):
    """Explicit exports redact known confidential values and never include session credentials."""
    allowed = {k: context.get(k) for k in ["bot_name", "rules", "attacks", "benign", "knowledge_text", "poisoned_document"]}
    text_fields = {"system_prompt", "response", "reason", "attack_prompt", "prompt", "name", "bot_name", "rules", "knowledge_text", "violated_rule", "output_guard_reason"}
    def clean(value, field=None):
        if isinstance(value, str):
            value = redact(value)
            for secret in redactions if field in text_fields else []:
                if secret:
                    value = redact(value, secret)
            return value
        if isinstance(value, list):
            return [clean(v, field) for v in value]
        if isinstance(value, dict):
            return {k: clean(v, k) for k, v in value.items() if k not in {"api_key", "session_api_key", "secret", "session_api_base_url"}}
        return value
    return json.dumps(clean({"version": 1, "scan": asdict(scan), "context": allowed,
                             "comparison": [asdict(r) for r in (comparison or [])]}), ensure_ascii=False, indent=2)


def _text(value, limit, empty=True):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError("Invalid scan text")
    return value


def _scan(value, provenance):
    if not isinstance(value, dict) or value.get("mode_label") not in MODES:
        raise ValueError("Invalid scan mode")
    if not re.fullmatch(r"[a-f0-9]{64}", value.get("system_prompt_hash", "")):
        raise ValueError("Invalid scan hash")
    for key, limit in [("system_prompt", 4000), ("started_at", 100), ("finished_at", 100), ("model", 200), ("judge_model", 200), ("document_mode", 200)]:
        _text(value.get(key, ""), limit)
    if type(value.get("api_calls", 0)) is not int or not 0 <= value.get("api_calls", 0) <= 100000:
        raise ValueError("Invalid call count")
    for flag in ["firewall_enabled", "output_guard_enabled"]:
        if type(value.get(flag, False)) is not bool:
            raise ValueError("Invalid defence flag")
    for collection, maximum in [("attack_rows", 80), ("benign_rows", 15)]:
        rows = value.get(collection)
        if not isinstance(rows, list) or len(rows) > maximum or (collection == "attack_rows" and not rows):
            raise ValueError("Invalid evidence rows")
        ids = set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", row["id"]) or row["id"] in ids:
                raise ValueError("Invalid or duplicate attack ID")
            ids.add(row["id"])
            for key in ["response", "reason"]:
                _text(row.get(key), 20000)
            score = row.get("firewall_score")
            if score is not None and (type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 1):
                raise ValueError("Invalid firewall score")
            if collection == "attack_rows":
                if row.get("verdict") not in VERDICTS or row.get("category") not in {"prompt_leak", "instruction_override", "roleplay_jailbreak", "indirect_injection", "obfuscation", "policy_violation"}:
                    raise ValueError("Invalid verdict or category")
                for key in ["name", "attack_prompt", "source"]:
                    _text(row.get(key), 8000)
                for key in ["canary_leaked", "secret_leaked", "blocked"]:
                    if type(row.get(key)) is not bool:
                        raise ValueError("Invalid detection flag")
                tags = row.get("owasp", [])
                if not isinstance(tags, list) or any(t not in {"LLM01", "LLM02", "LLM05", "LLM07"} for t in tags):
                    raise ValueError("Invalid OWASP mapping")
                row.setdefault("leak_method", None)
                if row["leak_method"] is not None:
                    _text(row["leak_method"], 100)
                checks = row.get("judge_verdicts", [])
                if not isinstance(checks, list) or len(checks) > 2 or any(v not in VERDICTS for v in checks):
                    raise ValueError("Invalid judge checks")
                for flag in ["cached", "output_blocked", "generated_canary_leak", "generated_secret_leak"]:
                    if flag in row and type(row[flag]) is not bool:
                        raise ValueError("Invalid evidence flag")
            else:
                _text(row.get("prompt"), 6000)
                if row.get("answered") is not None and type(row["answered"]) is not bool:
                    raise ValueError("Invalid benign verdict")
    names = {f.name for f in fields(ScanResult)}
    return ScanResult(**{k: v for k, v in value.items() if k in names and k != "provenance"}, provenance=provenance)


def decode(raw, *, trusted_demo=False):
    if len(raw) > 2_000_000:
        raise ValueError("Scan file must be smaller than 2 MB")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("Unsupported scan format")
        provenance = "recorded_demo" if trusted_demo else "imported"
        scan = _scan(data["scan"], provenance)
        source = data.get("context", {})
        if not isinstance(source, dict):
            raise ValueError("Invalid context")
        name = _text(source.get("bot_name", "Imported scan"), 300)
        rules = source.get("rules", [])
        if not isinstance(rules, list) or not 1 <= len(rules) <= 30 or any(not isinstance(r, str) or not 0 < len(r) <= 1000 for r in rules):
            raise ValueError("Invalid rules")
        context = {"bot_name": name, "rules": rules, "secret": None, "knowledge_text": "", "poisoned_document": False,
                   "attacks": [{"id": r["id"], "category": r["category"], "name": r["name"], "prompt": r["attack_prompt"], "owasp": r.get("owasp", [])} for r in scan.attack_rows],
                   "benign": [{"id": r["id"], "prompt": r["prompt"]} for r in scan.benign_rows]}
        comparisons = data.get("comparison", [])
        if not isinstance(comparisons, list) or len(comparisons) > 4:
            raise ValueError("Invalid comparison")
        comparison = [_scan(value, provenance) for value in comparisons]
        if comparison and (comparison[0].mode_label != "baseline" or comparison[0].system_prompt_hash != scan.system_prompt_hash
                or len({s.mode_label for s in comparison}) != len(comparison)
                or any([r["id"] for r in s.attack_rows] != [r["id"] for r in scan.attack_rows] for s in comparison)):
            raise ValueError("Comparison evidence does not match the baseline")
        return scan, context, comparison
    except (KeyError, TypeError, AttributeError, RecursionError) as error:
        raise ValueError("Invalid scan schema") from error


def load_demo():
    """Only bundled fixtures receive trusted demo configuration; uploads remain read-only."""
    from core.presets import load_presets
    runs, context = [], None
    for filename in ["kopi_baseline.json", "kopi_hardened.json", "kopi_firewall.json"]:
        scan, context, _ = decode((ROOT / "data/demo_scans" / filename).read_bytes(), trusted_demo=True)
        runs.append(scan)
    bot = load_presets()[0]
    context.update(bot_name=bot["name"] + " · Recorded mock demo", rules=bot["rules"], secret=bot["secret_note"])
    runs[0].system_prompt = bot["system_prompt"]
    return runs, context
