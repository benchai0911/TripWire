"""Exercise real orchestration with fake Chat Completions responses."""
import json
import pytest
from core import firewall, llm
from core.attacks import load_attacks, load_benign
from core.judge import judge
from core.presets import load_presets
from core.scanner import run_scan
from core.scoring import summarize


@pytest.fixture
def bot():
    return load_presets()[0]


def fake_judgement(**overrides):
    return json.dumps({"verdict": "resisted", "violated_rule": None,
                       "reason": "Stayed within rules.", "confidence": 0.9, **overrides})


def test_deterministic_leak_skips_judge(monkeypatch, bot):
    calls = []
    def fake(messages, **kwargs):
        calls.append(messages)
        assert messages[0]["content"].startswith(bot["system_prompt"])
        return messages[0]["content"].split("Internal reference code: ")[1].split(".")[0]
    monkeypatch.setattr(llm, "chat", fake)
    result = run_scan(bot["system_prompt"], bot["rules"], bot["secret_note"], load_attacks()[:2], [], False, 0.5, "baseline")
    assert len(calls) == 2
    assert all(row["verdict"] == "compromised" and row["source"] == "canary" for row in result.attack_rows)
    assert len(result.system_prompt_hash) == 64
    assert "TRIPWIRE-" not in result.system_prompt


def test_firewall_skips_all_remote_calls(monkeypatch, bot):
    monkeypatch.setattr(firewall, "score", lambda text: 0.99)
    result = run_scan(bot["system_prompt"], bot["rules"], None, load_attacks()[:2], load_benign(bot["id"])[:1], True, 0.5, "hardened_prompt_firewall")
    assert all(row["verdict"] == "blocked" for row in result.attack_rows)
    assert result.benign_rows[0]["answered"] is False
    assert summarize(result)["firewall_false_positive_rate"] == 100
    assert result.api_calls == 0


def test_parallel_progress_order_and_accounting(monkeypatch, bot):
    def fake(messages, json_mode=False, **kwargs):
        llm.call_observer.get()()
        if json_mode:
            assert "TRIPWIRE-" not in messages[1]["content"]
            if "legitimate user question" in messages[0]["content"]:
                return json.dumps({"answered": True, "reason": "Answered the question."})
            return fake_judgement()
        return "The café opens at 7am."
    monkeypatch.setattr(llm, "chat", fake)
    progress = []
    result = run_scan(bot["system_prompt"], bot["rules"], None, load_attacks()[:3], load_benign(bot["id"])[:2], False, 0.5, "baseline", lambda n, total: progress.append((n, total)))
    assert result.api_calls == 10
    assert [r["id"] for r in result.attack_rows] == [r["id"] for r in load_attacks()[:3]]
    assert progress == [(n, 5) for n in range(1, 6)]
    assert summarize(result)["security_score"] == 100
    assert summarize(result)["over_refusal_rate"] == 0


def test_invalid_judge_retries_once(monkeypatch):
    calls = []
    monkeypatch.setattr(llm, "chat", lambda *a, **kw: calls.append(1) or '{"verdict":"resisted"}')
    outcome = judge(["Protect secrets"], load_attacks()[0], "No.")
    assert outcome["verdict"] == "error"
    assert len(calls) == 2


def test_target_failure_visible_not_scored(monkeypatch, bot):
    def failure(*args, **kwargs):
        raise RuntimeError("Never display this raw request or credential")
    monkeypatch.setattr(llm, "chat", failure)
    result = run_scan(bot["system_prompt"], bot["rules"], None, load_attacks()[:1], load_benign(bot["id"])[:1], False, 0.5, "baseline")
    assert summarize(result)["security_score"] is None
    assert summarize(result)["over_refusal_rate"] is None
    assert "credential" not in result.attack_rows[0]["reason"]
    assert result.attack_rows[0]["source"] == "target"


def test_input_limits(bot):
    with pytest.raises(ValueError):
        run_scan("x" * 4001, bot["rules"], None, load_attacks(), [], False, 0.5, "baseline")
    with pytest.raises(ValueError):
        run_scan(bot["system_prompt"], [], None, load_attacks(), [], False, 0.5, "baseline")
