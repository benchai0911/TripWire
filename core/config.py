"""Secrets-first configuration; credentials never enter UI output."""
import os
import json
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

import streamlit as st
from streamlit.runtime.scriptrunner import get_script_run_ctx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
MAX_SYSTEM_PROMPT_CHARS = 4000
MAX_ATTACKS_PER_SCAN = 40
MAX_SCANS_PER_SESSION = 30
MAX_PARALLEL_CALLS = 5
TARGET_TEMPERATURE = 0.0
JUDGE_TEMPERATURE = 0.0

def load_firewall_threshold() -> float:
    """Use the validation-selected operating point, with safe legacy fallback."""
    try:
        value = json.loads((ROOT / "ml/metrics.json").read_text(encoding="utf-8")).get("threshold", .5)
        if type(value) in (int, float) and .1 <= value <= .9:
            return float(value)
    except (OSError, ValueError, TypeError):
        pass
    return .5


FIREWALL_THRESHOLD_DEFAULT = load_firewall_threshold()


def read_setting(name: str, default: str = "") -> str:
    """Read Streamlit secrets, falling back to the environment."""
    try:
        value = st.secrets.get(name)
        if value is not None:
            return str(value).strip()
    except (FileNotFoundError, st.errors.StreamlitSecretNotFoundError):
        pass
    return os.environ.get(name, default).strip()


@dataclass(frozen=True, repr=False)
class Settings:
    api_key: str
    model: str
    judge_model: str
    supabase_url: str
    supabase_key: str
    base_url: str = "https://api.openai.com/v1"
    cache_namespace: str = "server"


runtime_settings: ContextVar[Settings | None] = ContextVar("tripwire_runtime_settings", default=None)


def valid_base_url(value):
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(value)
        return not value or (parts.scheme in {"http", "https"} and bool(parts.hostname) and not parts.username and not parts.password)
    except ValueError:
        return False


def get_settings() -> Settings:
    """Return current configuration without exposing a credential repr."""
    if runtime_settings.get() is not None:
        return runtime_settings.get()
    default_model = read_setting("OPENAI_MODEL", "gpt-4o-mini")
    key, base_url = read_setting("OPENAI_API_KEY"), read_setting("OPENAI_BASE_URL", "https://api.openai.com/v1")
    namespace = "server"
    if get_script_run_ctx(suppress_warning=True) is not None:
        own_key = st.session_state.get("session_api_key", "").strip()
        if own_key:
            import hashlib
            import uuid
            fingerprint = hashlib.sha256(own_key.encode()).hexdigest()
            if st.session_state.get("credential_fingerprint") != fingerprint:
                st.session_state["credential_fingerprint"] = fingerprint
                st.session_state["credential_cache_namespace"] = uuid.uuid4().hex
            namespace = st.session_state["credential_cache_namespace"]
            key = own_key
            base_url = st.session_state.get("session_api_base_url", "").strip() or base_url
        else:
            st.session_state.pop("credential_fingerprint", None)
            st.session_state.pop("credential_cache_namespace", None)
    return Settings(key, read_setting("TARGET_MODEL") or default_model,
                    read_setting("JUDGE_MODEL") or default_model,
                    read_setting("SUPABASE_URL"), read_setting("SUPABASE_SERVICE_KEY"),
                    base_url, namespace)
