"""Inspect the latest baseline scan without crowding scan configuration."""
import streamlit as st
from core.ui import empty_state, SCAN_PAGE, show_results, cta_band, demo_button, resume_button

with st.container(key="tw_content"):
    demo_button("results_demo")
    with st.expander("Load saved scan"):
        upload = st.file_uploader("Saved scan JSON (max 2 MB)", type=["json"], max_upload_size=2)
        if st.button("Load saved scan", disabled=upload is None):
            try:
                from core.scan_archive import decode
                result, context, comparison = decode(upload.getvalue())
                st.session_state.update(baseline=result, scan_context=context)
                for key in ["comparison", "selected_fixes", "applied_recommendations", "unseen_scan", "hardened_draft", "hardening_changes"]:
                    st.session_state.pop(key, None)
                if comparison:
                    st.session_state["comparison"] = {"runs": comparison, "threshold": .5, "enabled": comparison[-1].firewall_enabled}
                st.rerun()
            except (ValueError, UnicodeError):
                st.error("Invalid scan JSON. Use a Tripwire export smaller than 2 MB with valid evidence rows.")
    if "baseline" not in st.session_state:
        empty_state("No scan yet", "Choose a bot and run your first baseline scan.", "Start a scan", SCAN_PAGE)
        st.stop()
    context = st.session_state.get("scan_context", {})
    from core.scan_archive import encode
    from core.config import get_settings
    result = st.session_state["baseline"]
    archive = encode(result, context, st.session_state.get("comparison", {}).get("runs"),
                     redactions=[context.get("secret"), get_settings().api_key])
    st.download_button("Export scan", archive, file_name="tripwire-scan.json", mime="application/json")
    st.caption("Snapshots redact known secrets and canaries and never include API keys. Imported snapshots are read-only.")
    resume_button(result, context)
    show_results(st.session_state["baseline"], bot_name=context.get("bot_name", "Your chatbot"), show_hero=False, recommendations=True)
    from pathlib import Path
    harden_page = next((Path(__file__).parent).glob("2_*"))
    cta_band("Ready to defend?", "Strengthen your prompt and compare the same attacks again.", "Harden & Retest", str(harden_page))
