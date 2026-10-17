"""The only OpenAI entry point, with bounded retries and request counting."""
import os
import math
import time
from email.utils import parsedate_to_datetime
from contextvars import ContextVar
from threading import Lock
from typing import Callable

import openai
import streamlit as st
from streamlit.runtime.scriptrunner import get_script_run_ctx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from core import config
from core.config import get_settings

call_observer: ContextVar[Callable[[], None] | None] = ContextVar("call_observer", default=None)


def requests_per_minute(model: str) -> int:
    """Use a conservative Gemini default; allow matching the provider's actual quota."""
    default = 10 if "gemini" in model.lower() else 60
    try:
        value = int(config.read_setting("TRIPWIRE_REQUESTS_PER_MINUTE", str(default)))
        return value if 1 <= value <= 600 else default
    except (ValueError, TypeError):
        return default


def rate_limit_delay(error) -> float:
    """Honor Retry-After seconds or an HTTP date; otherwise wait thirty seconds."""
    try:
        header = error.response.headers.get("retry-after", "30")
        try:
            value = float(header)
        except ValueError:
            value = parsedate_to_datetime(header).timestamp() - time.time()
        return max(1.0, value) if math.isfinite(value) else 30.0
    except (AttributeError, TypeError, ValueError, OverflowError):
        return 30.0


class RequestPacer:
    """One shared gate for target, judge, advisor and concurrent scan workers."""
    def __init__(self, clock=time.monotonic, sleep=time.sleep):
        self.clock, self.sleep = clock, sleep
        self.lock = Lock()
        self.next_at = 0.0

    def wait(self, rpm):
        while True:
            with self.lock:
                delay = self.next_at - self.clock()
                if delay <= 0:
                    self.next_at = self.clock() + 60.0 / rpm
                    return
            # Release the lock so a 429 can extend the cooldown for everyone.
            self.sleep(min(delay, 1.0))

    def defer(self, seconds):
        with self.lock:
            self.next_at = max(self.next_at, self.clock() + seconds)


_PACER = RequestPacer()
_BACKOFF = wait_exponential(multiplier=1, min=1, max=8)


def retry_wait(state):
    error = state.outcome.exception()
    return max(_BACKOFF(state), rate_limit_delay(error)) if isinstance(error, openai.RateLimitError) else _BACKOFF(state)


def mock_mode_enabled() -> bool:
    """An explicit 1 in either environment or secrets enables free testing."""
    return os.environ.get("TRIPWIRE_MOCK", "").strip() == "1" or config.read_setting("TRIPWIRE_MOCK") == "1"


class CallCounter:
    """Thread-safe, per-scan request counter; workers never touch session_state."""
    def __init__(self) -> None:
        self.count = 0
        self._lock = Lock()

    def increment(self) -> None:
        with self._lock:
            self.count += 1


@retry(stop=stop_after_attempt(3), wait=retry_wait,
       retry=retry_if_exception_type((openai.RateLimitError, openai.APITimeoutError,
                                     openai.APIConnectionError, openai.InternalServerError)),
       reraise=True)
def chat(messages: list[dict], model: str, temperature: float = 0.0,
         json_mode: bool = False, max_tokens: int = 600) -> str:
    """Call Chat Completions; count each HTTP attempt, including retries."""
    if mock_mode_enabled():
        from core.mock_llm import scripted_chat
        return scripted_chat(messages, json_mode=json_mode)
    settings = get_settings()
    if not settings.api_key:
        raise ValueError("Configure OPENAI_API_KEY before making a scan.")
    _PACER.wait(requests_per_minute(model))
    observer = call_observer.get()
    if observer:
        observer()
    elif get_script_run_ctx(suppress_warning=True) is not None:
        st.session_state["api_calls"] = st.session_state.get("api_calls", 0) + 1
    kwargs = {"model": model, "messages": messages, "temperature": temperature,
              "max_tokens": max_tokens}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    # Disable SDK retries so tenacity is the single retry policy.
    with openai.OpenAI(api_key=settings.api_key, base_url=settings.base_url,
                       timeout=30.0, max_retries=0) as client:
        try:
            response = client.chat.completions.create(**kwargs)
        except openai.RateLimitError as error:
            _PACER.defer(rate_limit_delay(error))
            raise
    return response.choices[0].message.content or ""


@retry(stop=stop_after_attempt(3), wait=retry_wait,
       retry=retry_if_exception_type((openai.RateLimitError, openai.APITimeoutError,
                                     openai.APIConnectionError, openai.InternalServerError)), reraise=True)
def tool_chat(messages: list[dict], tools: list[dict], model: str) -> dict:
    """Model-proposed function calls only. No callable tools or executors are attached."""
    if mock_mode_enabled():
        from core.mock_agent import tool_reply
        return tool_reply(messages)
    settings = get_settings()
    if not settings.api_key:
        raise ValueError("Configure an API key before testing an agent.")
    _PACER.wait(requests_per_minute(model))
    observer = call_observer.get()
    if observer:
        observer()
    elif get_script_run_ctx(suppress_warning=True) is not None:
        st.session_state["api_calls"] = st.session_state.get("api_calls", 0) + 1
    with openai.OpenAI(api_key=settings.api_key, base_url=settings.base_url, timeout=30, max_retries=0) as client:
        try:
            result = client.chat.completions.create(model=model, messages=messages, tools=tools,
                tool_choice="auto", temperature=0, max_tokens=1500)
        except openai.RateLimitError as error:
            _PACER.defer(rate_limit_delay(error))
            raise
    message = result.choices[0].message
    return {"content": message.content or "", "tool_calls": [
        {"id": call.id, "type": "function", "function": {"name": call.function.name, "arguments": call.function.arguments}}
        for call in (message.tool_calls or [])]}
