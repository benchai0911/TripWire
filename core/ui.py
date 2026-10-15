"""Shared page chrome, validation and readable scan results."""
import html
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st

from core.config import MAX_SCANS_PER_SESSION, get_settings

SCAN_PAGE = "pages/1_🎯_Scan.py"


def setup_page(title: str) -> None:
    """Apply consistent chrome and stop cleanly when credentials are missing."""
    st.set_page_config(page_title=f"{title} · Tripwire", page_icon="⚡", layout="wide")
    st.session_state.setdefault("api_calls", 0)
    st.session_state.setdefault("scans_used", 0)
    st.markdown("""<style>
    .block-container {max-width: 1250px; padding-top: 2.5rem;}
    h1 {letter-spacing: -0.04em;} h2 {letter-spacing: -0.02em;}
    div[data-testid="stMetric"] {background: #171D29; border: 1px solid #293247;
      padding: 1rem; border-radius: 12px;}
    </style>""", unsafe_allow_html=True)
    with st.sidebar:
        st.title("⚡ Tripwire")
        st.caption("Attack. Detect. Defend.")
        st.metric("API calls", st.session_state["api_calls"])
        st.metric("Scans remaining", max(0, MAX_SCANS_PER_SESSION - st.session_state["scans_used"]))
        st.caption(f"Target: {get_settings().model}")
    if not get_settings().api_key:
        st.error("Add OPENAI_API_KEY to .streamlit/secrets.toml or .env, then restart the app. "
                 "Use the provided example file. No key is displayed or logged.")
        st.stop()


def reserve_scans(count: int = 1) -> bool:
    """Reserve scan slots before starting work, including unsuccessful attempts."""
    if st.session_state["scans_used"] + count > MAX_SCANS_PER_SESSION:
        st.info(f"This session allows {MAX_SCANS_PER_SESSION} scans. "
                f"This action needs {count} remaining scan slots. Start a new session to continue.")
        return False
    st.session_state["scans_used"] += count
    return True


def show_results(result) -> None:
    """Render summary, category chart, verdict table and complete transcripts."""
    from core.scoring import summarize
    st.caption(f"Document mode: {result.document_mode} ? Firewall: {'on' if result.firewall_enabled else 'off'}")
    metrics = summarize(result)
    counts = Counter(row["verdict"] for row in result.attack_rows)
    cols = st.columns(5)
    score = metrics["security_score"]
    cols[0].metric("Security score", "N/A" if score is None else f"{score:.1f}%", metrics["grade"])
    cols[1].metric("Resisted / blocked", counts["resisted"] + counts["blocked"])
    cols[2].metric("Partial", counts["partial"])
    cols[3].metric("Compromised", counts["compromised"])
    cols[4].metric("Canary leaks", sum(r["canary_leaked"] for r in result.attack_rows))
    st.caption(f"{metrics['scored_attacks']}/{len(result.attack_rows)} attacks scored · "
               f"{metrics['attack_errors']} attack errors · {metrics['benign_errors']} benign errors · "
               f"{result.api_calls} API attempts")
    if metrics["attack_errors"]:
        st.warning("Errors are excluded from scores. An incomplete scan can overstate security; "
                   "inspect the error rows and re-run when API service is available.")
        reasons = list(dict.fromkeys(row["reason"] for row in result.attack_rows if row["verdict"] == "error"))
        for reason in reasons[:3]:
            st.error(reason)
    categories = [{"Category": k.replace("_", " "), "Score": v}
                  for k, v in metrics["category_scores"].items() if v is not None]
    if categories:
        st.plotly_chart(px.bar(pd.DataFrame(categories), x="Score", y="Category", orientation="h",
                              range_x=[0, 100], color_discrete_sequence=["#FFB000"]),
                        key=f"categories-{result.mode_label}-{result.system_prompt_hash}")
    frame = pd.DataFrame(result.attack_rows)[["id", "category", "name", "verdict", "source", "firewall_score"]]
    colors = {"resisted": "#143c31", "blocked": "#143c31", "partial": "#534018",
              "compromised": "#57262d", "error": "#303849"}
    st.dataframe(frame.style.map(lambda v: f"background-color: {colors.get(v, '#171D29')}",
                                 subset=["verdict"]), hide_index=True)
    for row in result.attack_rows:
        with st.expander(f"{row['id']} · {row['name']} · {row['verdict'].upper()}"):
            st.caption(row["category"].replace("_", " "))
            st.text(row["attack_prompt"])
            st.markdown("**Bot response**")
            # Escape all model output before HTML; never render injected HTML.
            text = html.escape(row["response"] or "No target call (blocked or failed).")
            if row["canary_leaked"] or row["secret_leaked"]:
                st.markdown(f'<pre style="color:#ff6b7a;white-space:pre-wrap">{text}</pre>', unsafe_allow_html=True)
            else:
                st.text(row["response"] or "No target call (blocked or failed).")
            st.caption({"canary": "Canary ✅ deterministic", "judge": "Judge 🤖",
                        "firewall": "Local firewall", "target": "Target error"}.get(row["source"], row["source"]))
            st.write(row["reason"])
            if row["leak_method"]:
                st.caption(f"Leak detection: {row['leak_method']}")
    answered = sum(r.get("answered") is True for r in result.benign_rows)
    st.subheader("Benign usability check")
    st.write(f"Bot answered {answered}/{len(result.benign_rows)} normal questions.")
    st.caption("Unresolved benign evaluations are reported separately, not treated as refusals.")
    if result.benign_rows:
        st.dataframe(pd.DataFrame(result.benign_rows), hide_index=True)
