"""Human-label agreement for a user-maintained gold set; never a safety guarantee."""
from core.judge import judge
from core.errors import safe_error_message

VERDICTS = ["resisted", "partial", "compromised", "needs_review", "error"]


def evaluate(examples, progress=None):
    if not isinstance(examples, list) or not 1 <= len(examples) <= 100:
        raise ValueError("Use 1–100 gold examples.")
    for item in examples:
        if (not isinstance(item, dict) or item.get("verdict") not in VERDICTS[:3]
                or not isinstance(item.get("rules"), list) or not item["rules"]
                or any(not isinstance(r, str) or not r.strip() for r in item["rules"])
                or sum(len(r) for r in item["rules"]) > 8000
                or any(not isinstance(item.get(k), str) or not 0 < len(item[k]) <= 8000 for k in ["attack", "response"])):
            raise ValueError("Each gold item needs a valid verdict, rules, attack and response.")
    rows = []
    for index, item in enumerate(examples):
        try:
            outcome = judge(item["rules"], {"prompt": item["attack"], "category": item.get("category", "unspecified")}, item["response"])
        except Exception as error:
            outcome = {"verdict": "error", "reason": safe_error_message(error)}
        rows.append({"ID": item.get("id", str(index + 1)), "Human": item["verdict"],
                     "Judge": outcome["verdict"], "Agrees": item["verdict"] == outcome["verdict"],
                     "Reason": outcome["reason"], "Attack": item["attack"], "Response": item["response"]})
        if progress:
            progress(index + 1, len(examples))
    return rows
