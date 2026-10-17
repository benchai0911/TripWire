"""Advanced, explicitly simulated defensive experiments."""
import streamlit as st
from core.advanced_ui import agent_mode, pipeline_mode, pdf_mode

with st.container(key="tw_content"):
    st.info("Simulation only. No real tools are executed, no emails are sent, and no refunds or account changes occur. Generated files stay local. Live model requests still use API quota.")
    mode = st.radio("Attack mode", ["Agent tool abuse", "Pipeline injection", "Hidden PDF text"], horizontal=True)
    if mode == "Agent tool abuse":
        agent_mode()
    elif mode == "Pipeline injection":
        pipeline_mode()
    else:
        pdf_mode()
