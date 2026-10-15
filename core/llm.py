"""The only OpenAI entry point, with bounded retries and request counting."""
from contextvars import ContextVar
from threading import Lock
from typing import Callable

import openai
import streamlit as st
from streamlit.runtime.scriptrunner import get_script_run_ctx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from core.config import get_settings

call_observer: ContextVar[Callable[[], None] | None] = ContextVar("call_observer", default=None)


class CallCounter:
    """Thread-safe, per-scan request counter; workers never touch session_state."""
    def __init__(self) -> None:
        self.count = 0
        self._lock = Lock()

    def increment(self) -> None:
        with self._lock:
            self.count += 1


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8),
       retry=retry_if_exception_type((openai.RateLimitError, openai.APITimeoutError,
                                     openai.APIConnectionError, openai.InternalServerError)),
       reraise=True)
def chat(messages: list[dict], model: str, temperature: float = 0.0,
         json_mode: bool = False, max_tokens: int = 600) -> str:
    """Call Chat Completions; count each HTTP attempt, including retries."""
    observer = call_observer.get()
    if observer:
        observer()
    elif get_script_run_ctx(suppress_warning=True) is not None:
        st.session_state["api_calls"] = st.session_state.get("api_calls", 0) + 1
    settings = get_settings()
    if not settings.api_key:
        raise ValueError("Configure OPENAI_API_KEY before making a scan.")
    kwargs = {"model": model, "messages": messages, "temperature": temperature,
              "max_tokens": max_tokens}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    # Disable SDK retries so tenacity is the single retry policy.
    with openai.OpenAI(api_key=settings.api_key, base_url=settings.base_url,
                       timeout=30.0, max_retries=0) as client:
        response = client.chat.completions.create(**kwargs)
    return response.choices[0].message.content or ""
