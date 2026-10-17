"""Output interception, independent judge checks and risk coverage: no live API."""
import base64
import json
import pytest
from core import llm, scanner, output_guard
from core.attacks import load_attacks
from core.presets import load_presets
from core.scoring import security_score, summarize
from core.judge import judge
from core.owasp import coverage


@pytest.mark.parametrize("response", ["TRIPWIRE-1234ABCD", "DCBA4321-ERIWPIRT", "1234ABCD",
    base64.b64encode(b"TRIPWIRE-1234ABCD").decode(), "STAFF50", "sk-" + "x" * 25])
def test_guard_known_forms(response):
    assert output_guard.check(response, "TRIPWIRE-1234ABCD", "STAFF50")["blocked"]


def test_guard_configurable_and_fail_closed(monkeypatch):
    monkeypatch.setenv("TRIPWIRE_OUTPUT_PATTERNS", json.dumps([r"INTERNAL-\d+"]))
    assert output_guard.check("INTERNAL-42", "", None)["blocked"]
    assert not output_guard.check("Opening hours are 7 to 5.", "", None)["blocked"]
    monkeypatch.setenv("TRIPWIRE_OUTPUT_PATTERNS", '["["]')
    assert output_guard.check("A reply", "", None)["blocked"]


def test_guard_intercepts_before_judge_and_persistence(monkeypatch):
    bot = load_presets()[0]
    def target(prompt, user):
        return prompt.split("Internal reference code: ")[1].split(".")[0]
    monkeypatch.setattr(scanner, "ask_target", target)
    monkeypatch.setattr(scanner, "judge", lambda *a: pytest.fail("Intercepted reply reached judge"))
    result = scanner.run_scan(bot["system_prompt"], bot["rules"], bot["secret_note"],
        load_attacks()[:1], [{"id": "B1", "prompt": "Hello"}], False, .5,
        "hardened_prompt_firewall_guard", use_output_guard=True)
    row = result.attack_rows[0]
    assert row["verdict"] == "blocked_output" and row["source"] == "output_guard"
    assert row["generated_canary_leak"] and not row["canary_leaked"]
    assert row["response"] == "[Blocked by output guard]"
    assert result.benign_rows[0]["answered"] is False
    assert summarize(result)["security_score"] == 100
    assert summarize(result)["firewall_false_positive_rate"] == 0
    assert "TRIPWIRE-" not in json.dumps(result.attack_rows)


def test_judges_reverse_rules_and_disagreement(monkeypatch):
    calls = []
    def fake(messages, **kwargs):
        calls.append(messages[-1]["content"])
        return json.dumps({"verdict": "resisted" if len(calls) == 1 else "partial", "reason": "Example",
                           "confidence": .9, "violated_rule": None})
    monkeypatch.setattr(llm, "chat", fake)
    outcome = judge(["First rule", "Second rule"], {"prompt": "Attack"}, "Response")
    assert outcome["verdict"] == "needs_review"
    assert calls[0].index("First rule") < calls[0].index("Second rule")
    assert calls[1].index("Second rule") < calls[1].index("First rule")
    assert security_score([{"verdict": "needs_review"}]) is None
    assert security_score([{"verdict": "needs_review"}, {"verdict": "blocked_output"}]) == 100


def test_owasp_maps_every_attack_and_unresolved_not_pass():
    assert all(r.get("owasp") for r in load_attacks())
    rows = [{"category": "prompt_leak", "owasp": ["LLM07", "LLM02"], "verdict": "needs_review"}]
    values = {r["OWASP ID"]: r for r in coverage(rows)}
    assert values["LLM07"]["Result"] == "INCOMPLETE"
    assert values["LLM02"]["Unresolved"] == 1
    assert values["LLM01"]["Result"] == "NOT TESTED"
    rows[0]["verdict"] = "blocked_output"
    assert next(r for r in coverage(rows) if r["OWASP ID"] == "LLM07")["Result"] == "PASS"


def test_gold_evaluation_keeps_errors_in_denominator(monkeypatch):
    from core import judge_check
    outcomes = iter([{"verdict": "resisted", "reason": "Agreed"}, {"verdict": "needs_review", "reason": "Disagreed"}])
    monkeypatch.setattr(judge_check, "judge", lambda *a: next(outcomes))
    item = {"rules": ["Stay in role"], "attack": "Test", "response": "Reply", "verdict": "resisted"}
    rows = judge_check.evaluate([item, item])
    assert [r["Agrees"] for r in rows] == [True, False]


def test_four_mode_report_retains_each_verdict_column(monkeypatch):
    from dataclasses import replace
    from core.report import comparison_report
    monkeypatch.setattr(scanner, "ask_target", lambda *a: "STAFF50")
    bot = load_presets()[0]
    result = scanner.run_scan(bot["system_prompt"], bot["rules"], bot["secret_note"], load_attacks()[:1],
                              [], False, .5, "baseline")
    modes = ["baseline", "hardened_prompt", "hardened_prompt_firewall", "hardened_prompt_firewall_guard"]
    report = comparison_report([replace(result, mode_label=m) for m in modes], .5)
    assert "Hardened + firewall + output guard" in report
    assert "STAFF50" not in report


def test_model_card_judge_check_ui(monkeypatch):
    from streamlit.testing.v1 import AppTest
    from core.config import ROOT
    from core.mock_llm import scripted_chat
    monkeypatch.setenv("TRIPWIRE_MOCK", "1")
    monkeypatch.setattr(llm, "chat", lambda messages, **kw: scripted_chat(messages, json_mode=kw.get("json_mode", False)))
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    page = str(next((ROOT / "pages").glob("5_*")).relative_to(ROOT)).replace("\\", "/")
    app.switch_page(page).run(timeout=30)
    next(b for b in app.button if b.label == "Run judge check").click().run(timeout=30)
    assert not app.exception
    rows = app.session_state["judge_check"]["rows"]
    assert len(rows) == 5
    assert any(m.label == "Agreement with human labels" for m in app.metric)
