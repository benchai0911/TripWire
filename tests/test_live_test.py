"""Conversation context, interception, controls and a non-resettable session cap."""
import pytest
from streamlit.testing.v1 import AppTest
from core import llm, firewall
from core.config import ROOT
from core.live_test import reply


def test_live_conversation_context_and_output_guard(monkeypatch):
    captured = []
    monkeypatch.setattr(firewall, "score", lambda text: .1)
    def chat(messages, **kwargs):
        captured.extend(messages)
        return "Private code: STAFF50."
    monkeypatch.setattr(llm, "chat", chat)
    history = [{"role": "user", "content": "My name is Alex", "firewall_score": .1},
               {"role": "assistant", "content": "Hi Alex"}]
    answer = reply("Cafe assistant", "Who am I?", history, "TRIPWIRE-1234ABCD", "STAFF50", use_guard=True)
    assert [m["content"] for m in captured[1:]] == ["My name is Alex", "Hi Alex", "Who am I?"]
    assert "firewall_score" not in captured[1]
    assert answer["content"] == "[Blocked by output guard]"
    assert answer["secret_leaked"] and answer["output_blocked"]


def test_live_firewall_prevents_api(monkeypatch):
    monkeypatch.setattr(firewall, "score", lambda text: .99)
    answer = reply("Bot", "Attack", [], "TRIPWIRE-1234ABCD", None, use_firewall=True)
    assert answer["firewall_blocked"]
    assert answer["content"] == "[Blocked by input firewall]"


def test_live_error_preserves_input_score_without_false_check_results(monkeypatch):
    monkeypatch.setattr(firewall, "score", lambda text: .2)
    def fail(*a, **kw):
        raise RuntimeError("private provider details")
    monkeypatch.setattr(llm, "chat", fail)
    answer = reply("Bot", "Hello", [], "TRIPWIRE-1234ABCD", None)
    assert answer["firewall_score"] == .2 and answer["target_error"]
    assert "private provider details" not in answer["content"]
    assert "not evaluated" in answer["guard_reason"]


def test_live_page_messages_reset_and_cap(monkeypatch):
    from core.mock_llm import scripted_chat
    monkeypatch.setenv("TRIPWIRE_MOCK", "1")
    monkeypatch.setattr(llm, "chat", lambda messages, **kw: scripted_chat(messages, json_mode=kw.get("json_mode", False)))
    monkeypatch.setattr(firewall, "score", lambda text: .1)
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    app.switch_page("pages/7_Live_Test.py").run(timeout=30)
    assert not app.exception
    app.chat_input[0].set_value("When do you open?").run(timeout=30)
    assert not app.exception
    assert len(app.session_state["live_history"]) == 2
    assert app.session_state["live_messages_used"] == 2
    next(b for b in app.button if b.label == "Reset conversation").click().run(timeout=30)
    assert not app.session_state["live_history"]
    assert app.session_state["live_messages_used"] == 2
    app.session_state["live_messages_used"] = 20
    app.run(timeout=30)
    assert app.chat_input[0].disabled
