"""Optional Supabase persistence; failures cannot prevent local scans."""
import re
import streamlit as st
from supabase import create_client
from core.config import get_settings
from core.scoring import summarize


@st.cache_resource
def _client(url: str, _key: str):
    return create_client(url, _key)


def _get_client():
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_key:
        return None
    return _client(settings.supabase_url, settings.supabase_key)


def is_enabled() -> bool:
    """Enable history only when both credentials exist and a client initializes."""
    try:
        return _get_client() is not None
    except Exception:
        st.warning("History could not initialize. Local scans remain available.")
        return False


def _safe_excerpt(row: dict, save_prompt: bool) -> str:
    # Do not indirectly persist a leaked system prompt when prompt storage is off.
    if not save_prompt and row["verdict"] in {"partial", "compromised"}:
        return "[Potential confidential disclosure omitted; full transcript is available only in this session.]"
    return re.sub(r"TRIPWIRE-[A-Fa-f0-9]{8}", "[CANARY REDACTED]", row["response"], flags=re.I)[:300]


def save_scan(result, bot_name: str, save_prompt: bool = False) -> str | None:
    """Save summary and 300-character excerpts; prompt storage requires explicit opt-in."""
    scan_id = None
    try:
        client = _get_client()
        if client is None:
            return None
        metrics = summarize(result)
        if metrics["security_score"] is None:
            st.warning("History was not saved because this scan has no scored attacks.")
            return None
        summary = {"bot_name": bot_name, "mode": result.mode_label,
                   "security_score": metrics["security_score"], "grade": metrics["grade"],
                   "over_refusal_rate": metrics["over_refusal_rate"],
                   "firewall_fp_rate": metrics["firewall_false_positive_rate"],
                   "total_attacks": len(result.attack_rows), "system_prompt_hash": result.system_prompt_hash,
                   "saved_system_prompt": result.system_prompt if save_prompt else None}
        saved = client.table("scans").insert(summary).execute().data
        scan_id = saved[0]["id"]
        rows = [{"scan_id": scan_id, "attack_id": r["id"], "category": r["category"],
                 "verdict": r["verdict"], "source": r["source"], "canary_leaked": r["canary_leaked"],
                 "blocked_by_firewall": r["blocked"], "firewall_score": r["firewall_score"],
                 "judge_reason": ("Potential confidential disclosure; details omitted."
                                  if not save_prompt and r["verdict"] in {"partial", "compromised"}
                                  else r["reason"][:1000]),
                 "response_excerpt": _safe_excerpt(r, save_prompt)}
                for r in result.attack_rows]
        if rows:
            client.table("attack_results").insert(rows).execute()
        return scan_id
    except Exception:
        # Best-effort rollback prevents a misleading empty history record.
        if scan_id:
            try:
                client.table("scans").delete().eq("id", scan_id).execute()
            except Exception:
                pass
        st.warning("Could not save complete history. Your scan results are still available in this session.")
        return None


def list_scans(limit: int = 50) -> list[dict]:
    """List newest summaries without fetching saved system prompts."""
    try:
        client = _get_client()
        if client is None:
            return []
        fields = "id,created_at,bot_name,mode,security_score,grade,over_refusal_rate,firewall_fp_rate,total_attacks,system_prompt_hash"
        return client.table("scans").select(fields).order("created_at", desc=True).limit(max(1, min(limit, 100))).execute().data
    except Exception:
        st.warning("Could not load scan history. Try again later.")
        return []


def get_scan(scan_id: str) -> dict | None:
    """Retrieve one saved scan and its associated attack excerpts."""
    try:
        client = _get_client()
        if client is None:
            return None
        scans = client.table("scans").select("*").eq("id", scan_id).limit(1).execute().data
        if not scans:
            return None
        attacks = client.table("attack_results").select("*").eq("scan_id", scan_id).execute().data
        return {"scan": scans[0], "attacks": attacks}
    except Exception:
        st.warning("Could not load this scan. Try again later.")
        return None
