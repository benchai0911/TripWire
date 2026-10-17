"""A bounded model/tool protocol with fake JSON replies and no real tool execution."""
import json
from core import llm
from core.config import ROOT, get_settings
from core.tool_policy import violations


def load_preset():
    return json.loads((ROOT / "data/agent_presets.json").read_text(encoding="utf-8"))[0]


def run_agent(message, preset=None, tool_guard=False):
    preset = preset or load_preset()
    if not isinstance(message, str) or not 0 < len(message) <= 12000:
        raise ValueError("Agent input must contain 1–12000 characters.")
    messages = [{"role": "system", "content": preset["system_prompt"]}, {"role": "user", "content": message}]
    calls, effective, attempted = [], [], []
    limit = False
    for round_index in range(3):
        reply = llm.tool_chat(messages, preset["tools"], model=get_settings().model)
        proposed = reply.get("tool_calls", [])
        if not isinstance(proposed, list) or len(proposed) > 8 or not isinstance(reply.get("content", ""), str):
            raise ValueError("Invalid model tool response")
        if not proposed:
            return {"calls": calls, "violations": effective, "attempted_violations": attempted,
                    "verdict": "compromised" if effective else "resisted", "source": "Tool policy",
                    "response": reply.get("content", ""), "round_limit_reached": False}
        messages.append({"role": "assistant", "content": reply.get("content") or None, "tool_calls": proposed})
        ids = set()
        for item in proposed:
            call_id = item.get("id")
            function = item.get("function", {})
            if not isinstance(call_id, str) or call_id in ids or not isinstance(function.get("name"), str):
                raise ValueError("Invalid model tool call")
            ids.add(call_id)
            try:
                raw = function.get("arguments", "")
                args = json.loads(raw) if isinstance(raw, str) and len(raw) <= 6000 else None
            except ValueError:
                args = None
            call = {"tool": function["name"], "args": args, "round": round_index + 1}
            found = violations(call, calls, preset["policies"])
            blocked = bool(tool_guard and found)
            call.update(blocked=blocked, simulated=not blocked, violations=found)
            calls.append(call)
            attempted.extend(found)
            if not blocked:
                effective.extend(found)
            # There is deliberately no dynamic dispatch, network I/O, mail client or file operation.
            fake = {"error": "blocked by policy"} if blocked else {
                "status": "ok", "simulated": True, "order": (args if isinstance(args, dict) else {}).get("order_id", "A123"), "total": 4.0}
            messages.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(fake)})
        limit = round_index == 2
    return {"calls": calls, "violations": effective, "attempted_violations": attempted,
            "verdict": "compromised" if effective else "resisted", "source": "Tool policy",
            "response": "Tool-call round limit reached; all replies were simulated.", "round_limit_reached": limit}
