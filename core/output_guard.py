"""Layer three: block known confidential strings and configured output patterns."""
import json
import ast
import re
import base64
from urllib.parse import urlsplit, unquote, unquote_plus
from core.canary import detect_leak
from core.config import read_setting

DEFAULT_PATTERNS = [r"\bSTAFF\d+\b", r"\bsk-[A-Za-z0-9_-]{20,}\b", r"\bAIza[A-Za-z0-9_-]{30,}\b"]
BLOCKED_RESPONSE = "[Blocked by output guard]"


def link_exfiltration(response, canary, secret):
    raw = read_setting("TRIPWIRE_OUTPUT_ALLOWED_DOMAINS", "")
    try:
        domains = json.loads(raw) if raw else []
    except ValueError:
        domains = ast.literal_eval(raw)
    if not isinstance(domains, list) or any(not isinstance(d, str) for d in domains):
        raise ValueError("Image domains must be a list.")
    allowed = {d.lower().strip().rstrip(".") for d in domains}
    markdown = list(re.finditer(r'(!?)\[[^\]\r\n]*\]\(\s*<?([^\s)>]+)>?(?:\s+[\'"][^\r\n]*?[\'"])?\s*\)', response))
    urls = [m.group(2) for m in markdown] + re.findall(r'https?://[^\s<>"\']+', response)
    for url in urls:
        decoded = url
        for _ in range(3):
            for value in [canary, secret]:
                if value:
                    variants = [value, base64.b64encode(value.encode()).decode(), base64.urlsafe_b64encode(value.encode()).decode()]
                    if any(v.lower() in decoded.lower() for v in variants):
                        return "Link exfiltration: URL contains known confidential content."
            decoded = unquote_plus(unquote(decoded))
    for match in markdown:
        if match.group(1) == "!":
            domain = (urlsplit(match.group(2)).hostname or "").lower().rstrip(".")
            if domain not in allowed:
                return "Link exfiltration: markdown image uses a non-allowlisted domain."
    return None


def patterns():
    """An optional JSON string array replaces defaults; invalid config fails closed."""
    raw = read_setting("TRIPWIRE_OUTPUT_PATTERNS", "")
    if raw:
        try:
            values = json.loads(raw)
        except json.JSONDecodeError:
            # read_setting stringifies native TOML arrays from Streamlit secrets.
            values = ast.literal_eval(raw)
    else:
        values = DEFAULT_PATTERNS
    if (not isinstance(values, list) or len(values) > 50 or
            any(not isinstance(p, str) or not p or len(p) > 500 for p in values)):
        raise ValueError("Output patterns must be a JSON array of up to 50 regex strings.")
    return [re.compile(p, re.I) for p in values]


def check(response, canary, secret) -> dict:
    """Return a safe reason without echoing the matched confidential value."""
    try:
        reason = link_exfiltration(response, canary, secret)
        if reason:
            return {"blocked": True, "reason": reason}
    except (ValueError, TypeError, SyntaxError):
        return {"blocked": True, "reason": "Output guard configuration is invalid; reply withheld."}
    leak = detect_leak(response, canary or "", secret)
    if leak["leaked"] or leak["secret_leaked"]:
        return {"blocked": True, "reason": "Known confidential content detected."}
    try:
        if any(p.search(response) for p in patterns()):
            return {"blocked": True, "reason": "Configured confidential-output pattern matched."}
    except (ValueError, TypeError, SyntaxError, re.error):
        return {"blocked": True, "reason": "Output guard configuration is invalid; reply withheld."}
    return {"blocked": False, "reason": "No known confidential string or configured pattern detected."}
