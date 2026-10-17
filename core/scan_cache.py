"""Disposable local evaluation cache. No credentials, prompts or transcripts are stored."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from core.config import ROOT, read_setting

CACHE_DIR = ROOT / ".cache" / "scans"
VERSION = 1
FIELDS = {"verdict", "source", "blocked", "firewall_score", "canary_leaked", "leak_method", "secret_leaked", "owasp",
          "output_blocked", "generated_canary_leak", "generated_secret_leak", "answered", "confidential_leak", "confidence", "judge_verdicts"}


def key_for(parts):
    return hashlib.sha256(json.dumps([VERSION, parts], sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def enabled():
    return read_setting("TRIPWIRE_CACHE", "1") != "0"


def load(key):
    if not enabled() or not re.fullmatch(r"[a-f0-9]{64}", key):
        return None
    try:
        value = json.loads((CACHE_DIR / f"{key}.json").read_text(encoding="utf-8"))
        row = value["row"]
        if value["version"] != VERSION or not isinstance(row, dict):
            return None
        if "verdict" in row and row["verdict"] not in {"resisted", "partial", "compromised", "blocked", "blocked_output"}:
            return None
        if "verdict" not in row and type(row.get("answered")) is not bool:
            return None
        return {**{k: v for k, v in row.items() if k in FIELDS}, "cached": True, "cached_at": value["created_at"],
                "response": "[Cached reply omitted; clear cache for a fresh transcript.]",
                "reason": "Cached evaluation; original explanation and transcript are not stored."}
    except (OSError, ValueError, TypeError, KeyError):
        return None


def save(key, row):
    if not enabled() or row.get("verdict") in {"error", "not_tested", "needs_review"} or ("verdict" not in row and type(row.get("answered")) is not bool):
        return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        value = {"version": VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
                 "row": {k: v for k, v in row.items() if k in FIELDS}}
        temporary = CACHE_DIR / f"{key}.{os.urandom(6).hex()}.tmp"
        temporary.write_text(json.dumps(value), encoding="utf-8")
        temporary.replace(CACHE_DIR / f"{key}.json")
    except OSError:
        pass  # A read-only deployment still supports uncached scans.


def clear():
    count = 0
    if CACHE_DIR.exists():
        for path in CACHE_DIR.glob("*.json"):
            if re.fullmatch(r"[a-f0-9]{64}\.json", path.name):
                path.unlink()
                count += 1
    return count
