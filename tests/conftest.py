"""No automated test may contact OpenAI."""
import pytest
import os
from core import config
from core import llm


@pytest.fixture(autouse=True)
def prohibit_live_openai(monkeypatch):
    # Test runs must not depend on, expose, or use the developer's real secrets file.
    monkeypatch.setattr(config, "read_setting", lambda name, default="": os.environ.get(name, default).strip())
    def prohibited(*args, **kwargs):
        raise AssertionError("A test attempted an unmocked LLM request")
    monkeypatch.setattr(llm, "chat", prohibited)
