"""One sandbox chat turn through the same model and local defence helpers."""
from core import llm, firewall
from core.canary import detect_leak, inject_canary
from core.config import get_settings, TARGET_TEMPERATURE, FIREWALL_THRESHOLD_DEFAULT
from core.output_guard import check, BLOCKED_RESPONSE
from core.errors import safe_error_message

MAX_MESSAGES = 20  # User and assistant messages combined; reset does not reset the session allowance.


def reply(system_prompt, user, history, canary, secret, use_firewall=False, threshold=FIREWALL_THRESHOLD_DEFAULT, use_guard=False):
    score = None
    try:
        score = firewall.score(user)
    except Exception:
        if use_firewall:
            raise ValueError("Train the local firewall before enabling it.")
    metadata = {"firewall_score": score, "firewall_blocked": False, "canary_leaked": False,
                "secret_leaked": False, "output_blocked": False, "guard_enabled": use_guard}
    if use_firewall and score >= threshold:
        return {"role": "assistant", "content": "[Blocked by input firewall]", **metadata,
                "firewall_blocked": True, "guard_reason": "Not evaluated: input was blocked."}
    messages = [{"role": "system", "content": inject_canary(system_prompt, canary)}]
    messages += [{"role": r["role"], "content": r["content"]} for r in history]
    messages.append({"role": "user", "content": user})
    try:
        response = llm.chat(messages, model=get_settings().model, temperature=TARGET_TEMPERATURE, max_tokens=500)
    except Exception as error:
        return {"role": "assistant", "content": "Could not complete this turn: " + safe_error_message(error),
                **metadata, "target_error": True, "guard_reason": "No reply produced; output checks not evaluated."}
    leak = detect_leak(response, canary, secret)
    guard = check(response, canary, secret)
    return {"role": "assistant", "content": BLOCKED_RESPONSE if use_guard and guard["blocked"] else response,
            **metadata, "canary_leaked": leak["leaked"], "secret_leaked": leak["secret_leaked"],
            "output_blocked": use_guard and guard["blocked"], "guard_would_block": guard["blocked"],
            "guard_reason": guard["reason"]}
