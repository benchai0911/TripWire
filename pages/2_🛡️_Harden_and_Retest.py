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
from core.ui import SCAN_PAGE, reserve_scans, setup_page, show_results

setup_page("Harden and Re-test")
st.title("🛡️ Defend. Then prove it.")
if "baseline" not in st.session_state:
    st.info("Run a baseline scan first so the comparison uses the same attacks and rules.")
    st.page_link(SCAN_PAGE, label="Start a baseline scan", icon="🎯")
    st.stop()
baseline = st.session_state["baseline"]
context = st.session_state["scan_context"]
st.subheader("1 · Strengthen the system prompt")
if st.button("Generate hardened prompt", type="primary"):
    failed = [r for r in baseline.attack_rows if r["verdict"] in {"partial", "compromised"}]
    try:
        with st.spinner("Rewriting while preserving the bot's purpose…"):
            result = harden(baseline.system_prompt, failed)
        st.session_state["hardened_draft"] = result["hardened_prompt"]
        st.session_state["hardening_changes"] = result["changes"]
        st.session_state.pop("comparison", None)
        st.rerun()
    except Exception:
        st.error("Could not generate a valid hardened prompt. Check API access or try again.")
st.session_state.setdefault("hardened_draft", baseline.system_prompt)
left, right = st.columns(2)
with left:
    st.caption("Original")
    st.text(baseline.system_prompt)
with right:
    edited = st.text_area("Hardened prompt (editable)", key="hardened_draft", height=300,
                          max_chars=MAX_SYSTEM_PROMPT_CHARS)
    st.caption(f"{len(edited)}/{MAX_SYSTEM_PROMPT_CHARS} characters")
for change in st.session_state.get("hardening_changes", []):
    st.write(f"• {change}")

st.subheader("2 · Add a local prompt firewall")
try:
    firewall.load_model()
    model_ready = True
except Exception:
    model_ready = False
    st.info("Train the firewall with python ml/train_firewall.py to enable the third comparison mode.")
enabled = st.toggle("Enable firewall in final mode", value=model_ready, disabled=not model_ready)
threshold = st.slider("Firewall block threshold", 0.1, 0.9, 0.5, step=0.05, disabled=not enabled)
st.caption("A lower threshold blocks more messages and may refuse legitimate users. "
           "The prompt-only mode always runs without the firewall.")
save_history = st.checkbox("Save re-test results to history", value=False) if storage.is_enabled() else False
save_prompt = st.checkbox("Also save my hardened system prompt", value=False, disabled=not save_history) if storage.is_enabled() else False
st.subheader("3 · Re-test the same questions")
st.caption("Uses two scan slots: hardened prompt, then hardened prompt + firewall. "
           "If the firewall toggle is off, both re-tests use the prompt alone.")
if st.button("Re-test", type="primary", disabled=not edited.strip()):
    if reserve_scans(2):
        progress = st.progress(0)
        runs = []
        try:
            for index, mode in enumerate(["hardened_prompt", "hardened_prompt_firewall"]):
                scan = run_scan(edited, context["rules"], context["secret"], context["attacks"],
                                context["benign"], enabled and index == 1, threshold, mode,
                                lambda n, total, i=index: progress.progress((i + n / total) / 2,
                                    text=f"Mode {i + 1}/2 · Evaluated {n}/{total}"),
                                knowledge_text=context.get("knowledge_text", ""),
                                poisoned_document=context.get("poisoned_document", False))
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
    st.subheader("Before vs after")
    st.caption(f"Last completed comparison · threshold {comparison['threshold']:.2f}. "
               "Edit controls above and re-test to update these results.")
    if not comparison["enabled"]:
        st.info("The final run had the firewall disabled; it is another prompt-only evaluation.")
    rows, categories = [], []
    for scan in results:
        m = summarize(scan)
        label = MODE_NAMES[scan.mode_label]
        rows.append({"Mode": label, "Security": m["security_score"], "Grade": m["grade"],
                     "Over-refusal": format_rate(m["over_refusal_rate"]),
                     "Firewall false positives": format_rate(m["firewall_false_positive_rate"]),
                     "Attack errors": m["attack_errors"], "Benign errors": m["benign_errors"]})
        categories += [{"Mode": label, "Category": k.replace("_", " "), "Security": v}
                       for k, v in m["category_scores"].items()]
    st.plotly_chart(px.bar(pd.DataFrame(rows), x="Mode", y="Security", color="Mode", barmode="group",
                          range_y=[0, 100], color_discrete_sequence=["#73849D", "#FFB000", "#33CBA0"]), use_container_width=True)
    st.plotly_chart(px.bar(pd.DataFrame(categories), x="Category", y="Security", color="Mode", barmode="group",
                          range_y=[0, 100], color_discrete_sequence=["#73849D", "#FFB000", "#33CBA0"]), use_container_width=True)
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.caption("Security and usability must be assessed together. A high score with high over-refusal "
               "may be unsuitable for users. Errors are excluded and must be reviewed.")
    changes = [{"ID": before["id"], "Attack": before["name"], "Baseline": before["verdict"],
                "Hardened": prompt["verdict"], "Final": final["verdict"]}
               for before, prompt, final in zip(*(r.attack_rows for r in results))]
    improved = [r for r in changes if r["Baseline"] == "compromised" and r["Final"] in {"resisted", "blocked"}]
    failures = [r for r in changes if r["Final"] in {"compromised", "partial", "error"}]
    st.markdown("**Compromised → resisted / blocked**")
    if improved:
        st.dataframe(pd.DataFrame(improved), hide_index=True, use_container_width=True)
    else:
        st.info("No compromised attacks flipped to resisted or blocked.")
    st.markdown("**Still failing or unresolved**")
    if failures:
        st.dataframe(pd.DataFrame(failures), hide_index=True, use_container_width=True)
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
if st.button("Generate attack variants", disabled=not failed or not edited.strip()):
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
