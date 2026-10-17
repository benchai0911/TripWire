import json
import pytest
from core import llm, pipeline, firewall
from core.config import ROOT

REAL_CHAT, REAL_TOOL_CHAT = llm.chat, llm.tool_chat


@pytest.fixture
def mock_agents(monkeypatch):
    monkeypatch.setenv("TRIPWIRE_MOCK", "1")
    monkeypatch.setattr(llm, "chat", REAL_CHAT)
    monkeypatch.setattr(llm, "tool_chat", REAL_TOOL_CHAT)
    monkeypatch.setattr(llm.openai, "OpenAI", lambda *a, **kw: pytest.fail("Mock constructed a live SDK"))


def emails():
    return json.loads((ROOT / "data/pipeline_emails.json").read_text(encoding="utf-8"))


def test_mock_pipeline_before_and_after(mock_agents):
    poisoned = emails()[2]
    before = pipeline.run_email(poisoned)
    guarded = pipeline.run_email(poisoned, tool_guard=True)
    boundary = pipeline.run_email(poisoned, boundary_firewall=True)
    assert before["verdict"] == "propagated_and_executed" and before["violations"]
    assert guarded["verdict"] == "propagated_not_executed" and not guarded["violations"]
    assert guarded["attempted_violations"]
    assert boundary["stopped_at"] == "Boundary firewall" and not boundary["calls"]
    assert not pipeline.run_email(emails()[0])["injection_survived"]


def test_agent_b_receives_only_summary(monkeypatch):
    seen = []
    monkeypatch.setattr(llm, "chat", lambda *a, **kw: "Safe summary only")
    monkeypatch.setattr(firewall, "score", lambda text: .1)
    monkeypatch.setattr(pipeline, "run_agent", lambda message, **kw: seen.append(message) or
        {"calls": [], "violations": [], "attempted_violations": []})
    result = pipeline.run_email({"body": "Original email PRIVATE-MARKER", "poisoned": True})
    assert seen == ["Safe summary only"]
    assert result["verdict"] == "stopped_at_A"


def test_boundary_block_skips_agent_b(mock_agents, monkeypatch):
    monkeypatch.setattr(pipeline, "run_agent", lambda *a, **kw: pytest.fail("Blocked summary reached B"))
    assert pipeline.run_email(emails()[2], boundary_firewall=True)["boundary_blocked"]


def test_pipeline_ui_reserves_slots(mock_agents):
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    app.switch_page("pages/8_Advanced.py").run(timeout=30)
    next(r for r in app.radio if r.label == "Attack mode").set_value("Pipeline injection").run(timeout=30)
    next(b for b in app.button if b.label == "Run pipeline emails").click().run(timeout=30)
    assert not app.exception and app.session_state["scans_used"] == 1
    next(t for t in app.toggle if t.label == "Firewall between agents").set_value(True).run(timeout=30)
    next(b for b in app.button if b.label == "Run pipeline emails").click().run(timeout=30)
    assert not app.exception and app.session_state["scans_used"] == 2
    assert app.session_state["api_calls"] == 0
