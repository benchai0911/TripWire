"""Select a sandbox, inspect the test set and run the baseline scan."""
import streamlit as st
from core.attacks import load_attacks, load_benign
from core.config import MAX_SYSTEM_PROMPT_CHARS
from core.presets import load_presets
from core.scanner import run_scan
from core.ui import reserve_scans, setup_page, show_results

setup_page("Scan")
st.title("🎯 Find the weak spots")
st.write("Start with a sandbox bot or a system prompt you are authorised to test.")
choice = st.radio("Bot source", ["Use a sandbox bot", "Paste my own system prompt"], horizontal=True)
if choice == "Use a sandbox bot":
    presets = load_presets()
    preset = st.selectbox("Sandbox bot", presets, format_func=lambda p: p["name"])
    st.caption(preset["description"])
    prompt, rules, secret = preset["system_prompt"], preset["rules"], preset["secret_note"]
    benign = load_benign(preset["id"])
    bot_name = preset["name"]
    with st.expander("System prompt and business rules"):
        st.text(prompt)
        for rule in rules:
            st.write(f"• {rule}")
else:
    prompt = st.text_area("Your system prompt", height=220, max_chars=MAX_SYSTEM_PROMPT_CHARS)
    st.caption(f"{len(prompt)}/{MAX_SYSTEM_PROMPT_CHARS} characters")
    rules = [line.strip() for line in st.text_area("Rules to check (one per line)", max_chars=4000).splitlines() if line.strip()]
    secret = st.text_input("Optional confidential value to detect", type="password", max_chars=200) or None
    normal = st.text_area("Normal questions for your bot (one per line, up to 15)", max_chars=6000,
                          help="Use questions within your bot's purpose so over-refusal measurement is meaningful.")
    benign = [{"id": f"CUSTOM-{i}", "prompt": line.strip()}
              for i, line in enumerate(normal.splitlines(), 1) if line.strip()][:15]
    bot_name = "Custom bot"
    if not benign:
        st.info("Add normal questions to measure over-refusal for your custom bot.")
knowledge_text = st.text_area("Knowledge base", max_chars=4000, height=160,
                              help="Optional reference documents supplied to the target bot.")
poisoned_document = st.toggle("Include a poisoned document", value=False,
                              help="Appends a simulated malicious instruction to the reference documents.")
categories = list(dict.fromkeys(r["category"] for r in load_attacks()))
selected = st.multiselect("Attack categories", categories, default=categories)
attacks = load_attacks(selected)
st.caption(f"{len(attacks)} attacks will run (~{2 * len(attacks)} API calls), plus up to "
           f"{2 * len(benign)} calls for normal questions. Retries can increase usage.")

# Persistence controls are attached here once storage is available.
try:
    from core import storage
    history_enabled = storage.is_enabled()
except ImportError:
    history_enabled = False
save_history = st.checkbox("Save results to history", value=False) if history_enabled else False
save_prompt = st.checkbox("Also save my system prompt", value=False, disabled=not save_history) if history_enabled else False

if st.button("Run baseline scan", type="primary", disabled=not prompt.strip() or not rules or not attacks):
    if reserve_scans():
        progress = st.progress(0, text="Starting scan…")
        try:
            result = run_scan(prompt, rules, secret, attacks, benign, False, 0.5, "baseline",
                              lambda n, total: progress.progress(n / total, text=f"Evaluated {n}/{total} prompts"),
                              knowledge_text=knowledge_text, poisoned_document=poisoned_document)
            st.session_state["api_calls"] += result.api_calls
            st.session_state["baseline"] = result
            st.session_state["scan_context"] = {"rules": rules, "secret": secret, "attacks": attacks,
                                                "benign": benign, "bot_name": bot_name,
                                                "knowledge_text": knowledge_text, "poisoned_document": poisoned_document}
            for key in ["hardened_draft", "hardening_changes", "comparison", "unseen_scan"]:
                st.session_state.pop(key, None)
            if save_history:
                storage.save_scan(result, bot_name, save_prompt)
            st.rerun()
        except Exception:
            st.error("Scan could not start. Check your inputs and configuration, then try again.")
        finally:
            progress.empty()
if "baseline" in st.session_state:
    st.subheader(f"Baseline · {st.session_state['scan_context']['bot_name']}")
    show_results(st.session_state["baseline"])
    st.page_link("pages/2_🛡️_Harden_and_Retest.py", label="Harden and re-test →", icon="🛡️")
