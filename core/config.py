"""Secrets-first configuration; credentials never enter UI output."""
import os
from dataclasses import dataclass
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
MAX_SYSTEM_PROMPT_CHARS = 4000
MAX_ATTACKS_PER_SCAN = 40
MAX_SCANS_PER_SESSION = 8
MAX_PARALLEL_CALLS = 5
TARGET_TEMPERATURE = 0.0
JUDGE_TEMPERATURE = 0.0
FIREWALL_THRESHOLD_DEFAULT = 0.5


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


def get_settings() -> Settings:
    """Return current configuration without exposing a credential repr."""
    model = read_setting("OPENAI_MODEL", "gpt-4o-mini")
    return Settings(read_setting("OPENAI_API_KEY"), model,
                    read_setting("JUDGE_MODEL", model),
                    read_setting("SUPABASE_URL"), read_setting("SUPABASE_SERVICE_KEY"),
                    read_setting("OPENAI_BASE_URL", "https://api.openai.com/v1"))
