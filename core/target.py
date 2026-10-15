"""Simulate a chatbot via a system prompt, never an external target endpoint."""
from core import llm
from core.config import TARGET_TEMPERATURE, get_settings


def ask_target(system_prompt_with_canary: str, user_message: str) -> str:
    """Ask the configured target model a single isolated question."""
    return llm.chat([{"role": "system", "content": system_prompt_with_canary},
                     {"role": "user", "content": user_message}],
                    model=get_settings().model, temperature=TARGET_TEMPERATURE, max_tokens=500)
