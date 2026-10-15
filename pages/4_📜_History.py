"""Optional stored scan summaries and response excerpts."""
import pandas as pd
import plotly.express as px
import streamlit as st
from core import storage
from core.ui import setup_page

setup_page("History")
st.title("📜 Scan history")
if not storage.is_enabled():
    st.info("History is disabled (no database configured).")
    st.caption("To enable it, run supabase/schema.sql and add SUPABASE_URL and SUPABASE_SERVICE_KEY to server-side secrets.")
    st.stop()
scans = storage.list_scans()
if not scans:
    st.info("No saved scans yet. Opt into saving results on the Scan or Re-test page.")
    st.stop()
frame = pd.DataFrame(scans)
frame["created_at"] = pd.to_datetime(frame["created_at"], utc=True).dt.tz_convert("Asia/Singapore")
frame["security_score"] = pd.to_numeric(frame["security_score"])
st.dataframe(frame, hide_index=True, use_container_width=True)
st.plotly_chart(px.line(frame.sort_values("created_at"), x="created_at", y="security_score",
                        color="bot_name", markers=True, range_y=[0, 100]), use_container_width=True)
selected = st.selectbox("View scan", scans,
    format_func=lambda r: f"{r['bot_name']} · {r['mode']} · {r['created_at']}")
detail = storage.get_scan(selected["id"])
if detail:
    st.subheader("Attack results")
    st.dataframe(pd.DataFrame(detail["attacks"]), hide_index=True, use_container_width=True)
    saved_prompt = detail["scan"].get("saved_system_prompt")
    if saved_prompt:
        with st.expander("System prompt (saved with explicit opt-in)"):
            st.text(saved_prompt)
    else:
        st.caption("Only the system prompt hash was saved. Response excerpts are limited to 300 characters; potential confidential disclosures are omitted when prompt storage is off.")
