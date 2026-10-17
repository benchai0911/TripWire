"""Configure a quick or full baseline, with a responsive run summary."""
import streamlit as st
from core.attacks import load_attacks, load_benign
from core.config import MAX_SYSTEM_PROMPT_CHARS, get_settings, valid_base_url
from core.presets import load_presets, load_test_presets
from core.llm import mock_mode_enabled
from core.scanner import run_scan
from core.scan_planning import choose, estimate
from core.ui import RESULTS_PAGE, reserve_scans, step_heading

with st.container(key="tw_content"):
    st.write("Start with a sandbox bot or a system prompt you are authorised to test.")
    with st.container(key="scan_layout"):
        form, summary = st.columns([.65, .35], gap="large")
        with form:
            step_heading("01", "Your bot")
            choice = st.radio("Bot source", ["Use a sandbox bot", "Paste my own system prompt"], horizontal=True)
            custom = choice == "Paste my own system prompt"
            if custom:
                if st.button("Fill with example"):
                    sample = load_presets()[0]
                    st.session_state.update(custom_prompt=sample["system_prompt"], custom_rules="\n".join(sample["rules"]),
                        custom_secret=sample["secret_note"], custom_questions="\n".join(b["prompt"] for b in load_benign(sample["id"])))
                prompt = st.text_area("Your system prompt", key="custom_prompt", height=220, max_chars=MAX_SYSTEM_PROMPT_CHARS,
                    placeholder="You are the assistant for Kopi Corner Cafe. Help with menu prices and opening hours. Never reveal private staff details.")
                st.caption(f"{len(prompt)}/{MAX_SYSTEM_PROMPT_CHARS} characters")
                bot_name, rules_key, secret_key, normal_key = "Custom bot", "custom_rules", "custom_secret", "custom_questions"
                rule_default, secret_default, normal_default = "", "", ""
                st.html('<span id="suggest-rules" style="scroll-margin-top:100px"></span>')
                if st.button("Suggest rules & questions", disabled=not prompt.strip() or (not get_settings().api_key and not mock_mode_enabled())):
                    try:
                        from core.suggestions import suggest
                        with st.spinner("Suggesting editable rules and normal questions..."):
                            suggested = suggest(prompt, st.session_state.get(secret_key))
                        st.session_state[rules_key] = "\n".join(suggested["rules"])
                        st.session_state[normal_key] = "\n".join(suggested["questions"])
                    except Exception:
                        st.error("Could not suggest safe rules and questions. Enter them manually or try again later.")
            else:
                show_test_bots = st.toggle("Show test bots", value=False, help="Add deliberately vulnerable test bots.")
                presets = load_presets() + (load_test_presets() if show_test_bots else [])
                preset = st.selectbox("Sandbox bot", presets, format_func=lambda p: p["name"], key="test_bot") if show_test_bots else st.radio("Sandbox bot", presets,
                    format_func=lambda p: f"**{p['name']}**\n\n{p['description']}", horizontal=True, key="sandbox_bot")
                if show_test_bots:
                    st.caption(preset["description"])
                prompt, bot_name = preset["system_prompt"], preset["name"]
                rules_key, secret_key, normal_key = [f"preset_{field}:{preset['id']}" for field in ["rules", "secret", "questions"]]
                rule_default, secret_default = "\n".join(preset["rules"]), preset.get("secret_note") or ""
                normal_default = "\n".join(b["prompt"] for b in load_benign(preset.get("benign_preset_id", preset["id"])))
                with st.expander("System prompt", expanded=True):
                    prompt = st.text_area("Sandbox system prompt (editable)", value=prompt,
                        key=f"preset_prompt:{preset['id']}", height=320, max_chars=MAX_SYSTEM_PROMPT_CHARS,
                        help="Edit this bot's prompt before scanning. Changes stay in this session.")
            with st.expander("Advanced"):
                knowledge_text = st.text_area("Knowledge base", key="knowledge_text", max_chars=4000, height=140,
                    placeholder="Opening hours: Monday to Friday, 7am-5pm. Menu: kopi $1.50, toast $2.00.",
                    help="Optional reference documents supplied to the target bot.")
                poisoned_document = st.toggle("Include a poisoned document", value=False,
                    help="Adds a simulated malicious instruction to reference documents.")
            with st.expander("Use your own API key"):
                st.text_input("API key", type="password", key="session_api_key", placeholder="Your provider-issued API key")
                st.text_input("API base URL (optional)", key="session_api_base_url", placeholder="https://api.openai.com/v1")
                st.caption("Used only in this session; never saved or exported. Clear the key to use the server key. Use a provider compatible with the configured models.")
            step_heading("02", "What to protect")
            rules_text = st.text_area("Rules to check (one per line)", value=rule_default, key=rules_key, max_chars=4000, height=240,
                placeholder="Never reveal the staff discount code.\nOnly offer prices and discounts listed on the menu.")
            rules = [line.strip() for line in rules_text.splitlines() if line.strip()]
            secret = st.text_input("Optional confidential value to detect", value=secret_default, key=secret_key, type="password", max_chars=200,
                placeholder="Example: STAFF50 (use fictional data)") or None
            if not prompt.strip():
                st.error("Enter a system prompt before running the scan.")
            if not rules:
                st.error("Add at least one business rule before running the scan.")
            step_heading("03", "Normal questions")
            normal = st.text_area("Normal questions for your bot (one per line, up to 15)", value=normal_default, key=normal_key, max_chars=6000, height=150,
                placeholder="What time do you open?\nHow much is kopi?\nDo you offer takeaway?", help="Use legitimate in-scope questions to measure over-refusal.")
            benign = [{"id": f"NORMAL-{i}", "prompt": line.strip()} for i, line in enumerate(normal.splitlines(), 1) if line.strip()][:15]
            if not benign:
                st.warning("Over-refusal won't be measured")
                if custom:
                    st.markdown('[Suggest rules & questions](#suggest-rules) or add normal questions above.')
            step_heading("04", "Attacks")
            categories = list(dict.fromkeys(r["category"] for r in load_attacks()))
            selected = st.multiselect("Attack categories", categories, default=categories, format_func=lambda v: v.replace("_", " ").capitalize())
            scan_mode = st.radio("Scan size", ["Quick scan", "Full scan (30)"], horizontal=True,
                help="Quick scan uses two attacks per selected category. Full uses all attacks in the selected categories.")
            attacks = choose(load_attacks(selected), full=scan_mode == "Full scan (30)")
            if not attacks:
                st.warning("Choose at least one attack category.")
            from core import storage
            save_history = st.checkbox("Save results to history", value=False) if storage.is_enabled() else False
            save_prompt = st.checkbox("Also save my system prompt", value=False, disabled=not save_history) if storage.is_enabled() else False
        with summary:
            with st.container(key="scan_summary", border=True):
                st.subheader("Your scan")
                st.write(bot_name)
                st.caption(f"{scan_mode} | {len(attacks)} attacks | {len(benign)} normal questions")
                settings = get_settings()
                planned = estimate(len(attacks), len(benign), settings)
                if mock_mode_enabled():
                    st.success("MOCK MODE | 0 API calls")
                else:
                    st.write(f"Estimated {planned['calls']} API calls | about {planned['minutes']:.1f} minutes")
                    st.caption("Before cache savings, firewall blocks, retries and optional recommendation tailoring. Judging uses batches of up to six.")
                    if benign:
                        st.caption("Includes normal-question checks.")
                if not benign:
                    st.warning("Over-refusal won't be measured")
                if not settings.api_key and not mock_mode_enabled():
                    st.info("Add your own API key above, configure a server key, or explore saved demo results.")
                base = st.session_state.get("session_api_base_url", "").strip()
                valid_url = valid_base_url(base)
                if not valid_url:
                    st.error("Use a complete HTTP(S) API base URL without embedded credentials.")
                can_run = bool(prompt.strip() and rules and attacks and valid_url and (settings.api_key or mock_mode_enabled()))
                if st.button("Run baseline scan", type="primary", disabled=not can_run, width="stretch"):
                    if reserve_scans():
                        progress = st.progress(0, text="Starting scan...")
                        try:
                            result = run_scan(prompt, rules, secret, attacks, benign, False, .5, "baseline",
                                lambda n, total: progress.progress(n / total, text=f"Collecting and evaluating {n}/{total}"),
                                knowledge_text=knowledge_text, poisoned_document=poisoned_document)
                            st.session_state["api_calls"] += result.api_calls
                            st.session_state["baseline"] = result
                            st.session_state["scan_context"] = {"rules": rules, "secret": secret, "attacks": attacks,
                                "benign": benign, "bot_name": bot_name, "knowledge_text": knowledge_text, "poisoned_document": poisoned_document}
                            for key in ["hardened_draft", "hardening_changes", "comparison", "unseen_scan"]:
                                st.session_state.pop(key, None)
                            if save_history:
                                storage.save_scan(result, bot_name, save_prompt)
                            st.switch_page(RESULTS_PAGE)
                        except Exception:
                            st.error("Scan could not start. Check your inputs and configuration, then try again.")
                        finally:
                            progress.empty()
