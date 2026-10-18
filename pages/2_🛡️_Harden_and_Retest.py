"""Compare baseline, hardened prompt and hardened prompt with a local firewall."""
import pandas as pd
import plotly.express as px
import streamlit as st
from core import firewall, storage
from core.config import MAX_SYSTEM_PROMPT_CHARS
from core.hardener import harden
from core.variants import generate_variants
from core.report import MODE_NAMES, comparison_report, format_rate
from core.scanner import run_scan
from core.scoring import summarize
from core.ui import step_heading, verdict_comparison, render_chart, stat_card, score_hero, prompt_diff, verdict_table, SCAN_PAGE, reserve_scans, show_results, demo_button

with st.container(key="tw_content"):
    demo_button("harden_demo")
    if "baseline" not in st.session_state:
        st.info("Run a baseline scan first so the comparison uses the same attacks and rules.")
        st.page_link(SCAN_PAGE, label="Start a baseline scan", icon="🎯")
        st.stop()
    baseline = st.session_state["baseline"]
    if baseline.provenance == "imported":
        st.info("Imported snapshots are read-only. Start a fresh baseline to harden and re-test this bot.")
    if baseline.provenance == "recorded_demo":
        st.info("Recorded mock demo comparison. Exploring these results uses no API calls; generating or re-testing is a new live action.")
    context = st.session_state["scan_context"]
    from core.ui import recommendation_scan_key
    applied = st.session_state.get("applied_recommendations", {})
    if applied.get("scan_key") != recommendation_scan_key(baseline):
        st.session_state.pop("selected_fixes", None)
        st.session_state.pop("applied_recommendations", None)
    if st.session_state.get("selected_fixes"):
        st.info("Selected recommendation snippets will be included when you generate the hardened prompt.")
    step_heading("01", "Strengthen the system prompt")
    if st.button("Generate hardened prompt", type="primary", disabled=baseline.provenance == "imported"):
        failed = [r for r in baseline.attack_rows if r["verdict"] in {"partial", "compromised"}]
        try:
            with st.spinner("Rewriting while preserving the bot's purpose…"):
                result = harden(baseline.system_prompt, failed, st.session_state.get("selected_fixes", []))
            st.session_state["hardened_draft"] = result["hardened_prompt"]
            st.session_state["hardening_changes"] = result["changes"]
            st.session_state.pop("comparison", None)
            st.rerun()
        except Exception:
            st.error("Could not generate a valid hardened prompt. Check API access or try again.")
    st.session_state.setdefault("hardened_draft", baseline.system_prompt)
    left, right = st.columns(2)
    with left:
        st.text_area("Original prompt (read-only)", value=baseline.system_prompt,
                     height=300, disabled=True)
        st.caption(f"{len(baseline.system_prompt)}/{MAX_SYSTEM_PROMPT_CHARS} characters")
    with right:
        edited = st.text_area("Hardened prompt (editable)", key="hardened_draft", height=300,
                              max_chars=MAX_SYSTEM_PROMPT_CHARS)
        st.caption(f"{len(edited)}/{MAX_SYSTEM_PROMPT_CHARS} characters")
    prompt_diff(baseline.system_prompt, edited)
    for change in st.session_state.get("hardening_changes", []):
        st.write(f"✓ {change}")

    step_heading("02", "Add a local prompt firewall")
    try:
        firewall.load_model()
        model_ready = True
    except Exception:
        model_ready = False
        st.info("Train the firewall with python ml/train_firewall.py to enable the third comparison mode.")
    if st.session_state.pop("recommend_firewall", False):
        st.session_state["retest_firewall"] = model_ready
    enabled = st.toggle("Enable firewall in final mode", value=model_ready, disabled=not model_ready, key="retest_firewall")
    from core.config import FIREWALL_THRESHOLD_DEFAULT
    threshold = st.slider("Firewall block threshold", 0.1, 0.9, FIREWALL_THRESHOLD_DEFAULT, step=0.05, disabled=not enabled)
    st.caption("A lower threshold blocks more messages and may refuse legitimate users. "
               "The prompt-only mode always runs without the firewall.")
    save_history = st.checkbox("Save re-test results to history", value=False) if storage.is_enabled() else False
    save_prompt = st.checkbox("Also save my hardened system prompt", value=False, disabled=not save_history) if storage.is_enabled() else False
    step_heading("03", "Re-test the same questions")
    st.caption("Uses three scan slots: prompt, prompt + firewall, then prompt + firewall + output guard. "
               "If the firewall toggle is off, only prompt and output defences apply. Double judging increases API usage.")
    if st.button("Re-test", type="primary", disabled=not edited.strip() or baseline.provenance == "imported"):
        if reserve_scans(3):
            progress = st.progress(0)
            runs = []
            try:
                for index, mode in enumerate(["hardened_prompt", "hardened_prompt_firewall", "hardened_prompt_firewall_guard"]):
                    scan = run_scan(edited, context["rules"], context["secret"], context["attacks"],
                                    context["benign"], enabled and index >= 1, threshold, mode,
                                    lambda n, total, i=index: progress.progress((i + n / total) / 3,
                                        text=f"Mode {i + 1}/3 · Evaluated {n}/{total}"),
                                    knowledge_text=context.get("knowledge_text", ""),
                                    poisoned_document=context.get("poisoned_document", False),
                                    use_output_guard=index == 2)
                    st.session_state["api_calls"] += scan.api_calls
                    runs.append(scan)
                    if save_history:
                        storage.save_scan(scan, context["bot_name"], save_prompt)
                st.session_state["comparison"] = {"runs": [baseline, *runs], "threshold": threshold,
                                                  "enabled": enabled}
                st.rerun()
            except Exception:
                st.error("Re-test could not complete. Check configuration and retry; any completed scan remains available in history if saving was enabled.")
            finally:
                progress.empty()

    if "comparison" in st.session_state:
        comparison = st.session_state["comparison"]
        results = comparison["runs"]
        from core.ui import recommendation_checklist
        recommendation_checklist(results[-1], baseline)
        st.subheader("Before vs after")
        st.caption(f"Last completed comparison · threshold {comparison['threshold']:.2f}. "
                   "Review the defence flags in each evidence panel. Edit controls above and re-test to update these results.")
        if not comparison["enabled"]:
            st.info("The final run had the firewall disabled; the final evaluation still includes the output guard.")
        for col, scan in zip(st.columns(len(results)), results):
            with col:
                summary = summarize(scan)
                score_hero(summary["security_score"], summary["grade"], MODE_NAMES[scan.mode_label], any(r["canary_leaked"] or r["secret_leaked"] for r in scan.attack_rows))
                base_score = summarize(baseline)["security_score"]
                if base_score is not None and summary["security_score"] is not None:
                    st.caption(f"{summary['security_score'] - base_score:+.0f} pts from baseline")
        rows, categories = [], []
        for scan in results:
            m = summarize(scan)
            label = MODE_NAMES[scan.mode_label]
            rows.append({"Mode": label, "Security": m["security_score"], "Grade": m["grade"] if m["security_score"] is not None else "Not tested",
                         "Over-refusal": format_rate(m["over_refusal_rate"]),
                         "Firewall false positives": format_rate(m["firewall_false_positive_rate"]),
                         "Attack errors": m["attack_errors"], "Not tested": m["not_tested"], "Needs review": m["needs_review"], "Benign errors": m["benign_errors"]})
            categories += [{"Mode": label, "Category": k.replace("_", " "), "Security": v}
                           for k, v in m["category_scores"].items()]
        render_chart(px.bar(pd.DataFrame(categories), x="Category", y="Security", color="Mode", barmode="group",
                              range_y=[0, 100], color_discrete_sequence=["#8A8178", "#F5A623", "#1F8A5B", "#2F6FB3"]), width="stretch")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        for col, label, key in zip(st.columns(2), ["Over-refusal", "Firewall false positives"], ["over_refusal_rate", "firewall_false_positive_rate"]):
            with col:
                stat_card(label, format_rate(summarize(results[-1])[key]), "warn")
        st.caption("Security and usability must be assessed together. A high score with high over-refusal "
                   "may be unsuitable for users. Errors are excluded and must be reviewed.")
        changes = [{"ID": before["id"], "Attack": before["name"], "Baseline": before["verdict"],
                    "Hardened": prompt["verdict"], "Final": final["verdict"]}
                   for before, prompt, final in zip(results[0].attack_rows, results[1].attack_rows, results[-1].attack_rows)]
        improved = [r for r in changes if r["Baseline"] == "compromised" and r["Final"] in {"resisted", "blocked", "blocked_output"}]
        failures = [r for r in changes if r["Final"] in {"compromised", "partial", "error", "needs_review", "not_tested"}]
        st.markdown("**Compromised → resisted / blocked**")
        if improved:
            verdict_comparison(improved)
        else:
            st.info("No compromised attacks flipped to resisted or blocked.")
        st.markdown("**Still failing or unresolved**")
        if failures:
            st.dataframe(verdict_table(pd.DataFrame(failures)), hide_index=True, width="stretch")
        else:
            st.success("All attacks in the final scan were resisted or blocked.")
        st.download_button("Download Markdown comparison report", comparison_report(results, comparison["threshold"], comparison["enabled"]),
                           file_name="tripwire-comparison.md", mime="text/markdown")
        for scan in results[1:]:
            with st.expander(f"Full evidence · {MODE_NAMES[scan.mode_label]}"):
                show_results(scan)


    st.subheader("Unseen attacks")
    failed = [r for r in baseline.attack_rows if r["verdict"] in {"partial", "compromised"}]
    st.caption(f"Generate two paraphrases for each of {len(failed)} failed baseline attacks, then scan "
               "the current hardened prompt and firewall settings. Uses one scan slot. "
               "This separate attack set is not directly comparable to the original scores.")
    if st.button("Generate attack variants", disabled=not failed or not edited.strip() or baseline.provenance == "imported"):
        if reserve_scans():
            try:
                with st.spinner("Generating and testing unseen attacks..."):
                    variants = generate_variants(failed)
                    scan = run_scan(edited, context["rules"], context["secret"], variants, [],
                                    enabled, threshold, "unseen_attacks",
                                    knowledge_text=context.get("knowledge_text", ""),
                                    poisoned_document=context.get("poisoned_document", False))
                st.session_state["api_calls"] += scan.api_calls
                st.session_state["unseen_scan"] = scan
                st.rerun()
            except Exception:
                st.error("Could not generate or scan valid attack variants. Check API access and retry.")
    if "unseen_scan" in st.session_state:
        unseen = st.session_state["unseen_scan"]
        comparison_runs = st.session_state.get("comparison", {}).get("runs", [baseline])
        columns = st.columns(len(comparison_runs) + 1)
        for column, scan in zip(columns, [*comparison_runs, unseen]):
            score = summarize(scan)["security_score"]
            column.metric("Unseen attacks" if scan is unseen else MODE_NAMES[scan.mode_label],
                          "N/A" if score is None else f"{score:.1f}%")
        st.caption("Unseen results reflect the prompt and settings at generation time. "
                   "Regenerate after changing controls. No normal questions are tested in this scan.")
        with st.expander("Unseen attack evidence"):
            show_results(unseen)
