"""Transport pacing uses a fake clock: no network or real waits."""
from types import SimpleNamespace
import httpx
import openai
import pytest
from core import llm

REAL_CHAT = llm.chat


def test_shared_pacer_spacing_and_cooldown():
    now = [100.0]
    def sleep(seconds):
        now[0] += seconds
    gate = llm.RequestPacer(clock=lambda: now[0], sleep=sleep)
    gate.wait(10)
    assert now[0] == 100
    gate.wait(10)
    assert now[0] == 106
    gate.defer(30)
    gate.wait(10)
    assert now[0] == 136
    gate.wait(10)
    assert now[0] == 142


@pytest.mark.parametrize("setting, model, expected", [("", "gemini-3.1-flash-lite", 10),
    ("bad", "gpt-4o-mini", 60), ("0", "gemini-x", 10), ("5", "gemini-x", 5)])
def test_rate_configuration(monkeypatch, setting, model, expected):
    monkeypatch.setattr(llm.config, "read_setting", lambda name, default: setting or default)
    assert llm.requests_per_minute(model) == expected


@pytest.mark.parametrize("header, expected", [("65", 65), ("NaN", 30), ("invalid", 30)])
def test_retry_after(header, expected):
    error = SimpleNamespace(response=SimpleNamespace(headers={"retry-after": header}))
    assert llm.rate_limit_delay(error) == expected


def test_retry_wait_honors_provider_delay():
    error = openai.RateLimitError("Rate limited", response=httpx.Response(429,
        headers={"retry-after": "65"}, request=httpx.Request("POST", "https://example.com")), body={})
    state = SimpleNamespace(attempt_number=1, outcome=SimpleNamespace(exception=lambda: error))
    assert llm.retry_wait(state) == 65


def test_live_429_defers_all_workers(monkeypatch):
    # Bypass only tenacity's real sleeps; exercise the actual request implementation.
    monkeypatch.setattr(llm, "mock_mode_enabled", lambda: False)
    monkeypatch.setattr(llm, "get_settings", lambda: SimpleNamespace(api_key="test", base_url="https://example.com"))
    events = []
    monkeypatch.setattr(llm, "_PACER", SimpleNamespace(wait=lambda rpm: events.append("wait"),
                                                      defer=lambda delay: events.append(delay)))
    error = openai.RateLimitError("Limited", response=httpx.Response(429,
        headers={"retry-after": "45"}, request=httpx.Request("POST", "https://example.com")), body={})
    def create(**kwargs):
        raise error
    class Client:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    monkeypatch.setattr(llm.openai, "OpenAI", Client)
    with pytest.raises(openai.RateLimitError):
        REAL_CHAT.__wrapped__([{"role": "user", "content": "test"}], model="gemini-test")
    assert events == ["wait", 45]
