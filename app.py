"""Tripwire landing page."""
import streamlit as st
from core.ui import SCAN_PAGE, setup_page

setup_page("Home")
st.caption("CHATBOT SECURITY • SANDBOX TESTING")
st.title("Tripwire — catch your chatbot's weaknesses before anyone else does.")
st.write("Test a system prompt. Find the leaks. Strengthen the rules. See what changed.")
st.page_link(SCAN_PAGE, label="Start a scan →", icon="🎯")
st.divider()
for col, title, body in zip(st.columns(3), ["01 · Attack", "02 · Detect", "03 · Defend"], [
    "Run 30 safe attacks against a fictional sandbox bot or your own pasted system prompt.",
    "A secret canary catches leaks deterministically. An LLM judge checks business rules.",
    "Rewrite the prompt, add a locally trained firewall, and re-test security and helpfulness.",
]):
    with col:
        st.subheader(title)
        st.write(body)
st.divider()
st.subheader("Evidence you can inspect")
st.write("Full transcripts, category scores, an explainable TF-IDF classifier, and normal-user "
         "checks show both security gains and the cost of over-blocking.")
st.info("Tripwire tests simulated bots through OpenAI. It cannot target external chatbot endpoints. "
        "Pasted prompts and test conversations are sent to OpenAI; use fictional or authorised data.")
