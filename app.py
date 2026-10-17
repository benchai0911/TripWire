"""Tripwire editorial landing page and native top navigation."""
from pathlib import Path
import streamlit as st

st.set_page_config(page_title="Tripwire", page_icon=str(Path(__file__).parent / "assets/tripwire-mark.svg"), layout="wide", initial_sidebar_state="collapsed")
from core import storage
from core.ui import SCAN_PAGE, RESULTS_PAGE, setup_page, inject_css, render_navbar, page_header, hero, stats_band, numbered_card, section_heading, sample_transcript, footer


def home():
    hero("Catch your chatbot's weaknesses before anyone else does.",
         "Test the rules. Find the leaks. Build a stronger line of defence.",
         cta_label="Start a scan")
    stats_band("What Tripwire checks", [("Attack techniques", "30", None), ("Attack categories", "6", None), ("Defence layers", "3", None)])
    with st.container(key="home_sections"):
        section_heading("A clearer path to a safer chatbot.", "HOW IT WORKS")
        for col, number, title, body, shape in zip(st.columns(3), ["01", "02", "03"], ["ATTACK", "DETECT", "DEFEND"], [
            "Challenge a sandbox bot or your authorised prompt with controlled attacks.",
            "Find confidential leaks and broken rules with canaries and an LLM judge.",
            "Harden the prompt, add a local firewall, and measure what improves."], ["circle", "triangle", "square"]):
            with col:
                numbered_card(number, title, body, shape)
    with st.container(key="why_band"):
        with st.container(key="why_inner"):
            left, right = st.columns([1, 1], gap="large", vertical_alignment="center")
            with left:
                sample_transcript()
            with right:
                section_heading("Trust the evidence. Strengthen the defence.", "WHY IT MATTERS")
                st.write("A convincing answer can still break a business rule. Tripwire makes those failures visible, with complete transcripts and repeatable before-and-after comparisons.")
                st.page_link(SCAN_PAGE, label="Explore your chatbot's weak spots", icon=":material/arrow_outward:")




inject_css()
paths = sorted((Path(__file__).parent / "pages").glob("*.py"))
by_prefix = {path.name.split("_")[0]: str(path) for path in paths}
pages = [st.Page(home, title="Home", default=True),
         st.Page(by_prefix["1"], title="Scan", url_path="scan"),
         st.Page(RESULTS_PAGE, title="Results", url_path="results"),
         st.Page(by_prefix["2"], title="Harden & Retest", url_path="shield"),
         st.Page(by_prefix["3"], title="Firewall", url_path="science"),
         st.Page(by_prefix["5"], title="Model Card", url_path="verified_user"),
         st.Page(by_prefix["7"], title="Live Test", url_path="live-test"),
         st.Page(by_prefix["8"], title="Advanced", url_path="advanced"),
         st.Page(by_prefix["4"], title="History", url_path="history", visibility="visible" if storage.is_enabled() else "hidden")]
def legacy_scan_route():
    st.switch_page(SCAN_PAGE)


legacy_scan = st.Page(legacy_scan_route, title="Legacy scan route", url_path="radar", visibility="hidden")
pg = st.navigation([*pages, legacy_scan], position="hidden")
render_navbar(pages, pg)
headers = {
    "Advanced": ("Advanced attack lab", "Explore simulated agent tools, trust boundaries and document ingestion.", "CONTROLLED EXPERIMENTS"),
    "Live Test": ("Live test sandbox", "Chat with a bot and inspect each defence layer.", "INTERACTIVE TEST"),
    "Scan": ("Scan a chatbot", "Choose a bot and run a baseline to uncover leaks and rule violations.", "STEP 1 \u00b7 ATTACK"),
    "Results": (st.session_state.get("scan_context", {}).get("bot_name", "Your scan results"), "Review the evidence behind every verdict.", "SCAN RESULTS"),
    "Harden & Retest": ("Harden & retest", "Strengthen the prompt, then measure security and usability.", "STEP 2 \u00b7 DEFEND"),
    "Firewall": ("Firewall playground", "Inspect the decisions of a locally trained classifier.", "MY TRAINED MODEL"),
    "Model Card": ("Model card & safety", "Measured evidence, trade-offs, and the limits of this sandbox.", "TRANSPARENCY"),
    "History": ("Scan history", "Review saved evidence and security scores over time.", "EVIDENCE"),
}
page_body = st.container(key="page_shell")
footer()
with page_body:
    setup_page(pg.title)
    if pg.title in headers:
        title, subtitle, label = headers[pg.title]
        page_header(title, subtitle, label)
    pg.run()
