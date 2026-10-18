"""Show measured classifier evidence, safety guardrails and limitations."""
import json
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from core.config import ROOT
from core.ui import render_chart, stat_card

with st.container(key="tw_content"):
    from core import scan_cache
    if st.button("Clear cache"):
        try:
            count = scan_cache.clear()
            st.success(f"Cleared {count} cached evaluations.")
        except OSError:
            st.error("Cache files could not be removed. Check local filesystem permissions.")
    st.subheader("A small model with inspectable evidence")
    path = ROOT / "ml/metrics.json"
    try:
        metrics = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        metrics = None
        st.info("No training metrics available. Install requirements-train.txt and run python ml/train_firewall.py.")
    if metrics:
        st.write(metrics["pipeline"])
        if metrics.get("model_comparison"):
            st.subheader("Model comparison · train-only five-fold CV")
            st.dataframe(pd.DataFrame(metrics["model_comparison"])[["model", "cv_f1_mean", "cv_f1_std"]], hide_index=True, width="stretch")
            st.caption(f"Selected {metrics['selected_model']} by mean CV F1. Default threshold {metrics['threshold']:.4f}, selected on validation for highest recall at false-positive rate ≤5%.")
        if metrics.get("before"):
            st.subheader("Before / after · same held-out test split")
            keys = ["accuracy", "precision", "recall", "f1", "false_positive_rate"]
            st.dataframe(pd.DataFrame({"Metric": keys, "Previous pipeline (refit)": [metrics["before"][k] for k in keys],
                "New firewall": [metrics["evaluation"][k] for k in keys]}), hide_index=True, width="stretch")
            st.caption(metrics["before"]["description"] + ". The original saved model is excluded because it has seen parts of the new split. Validation's FPR constraint is not a test-set guarantee.")
            if metrics.get("historical"):
                with st.expander("Historical metrics · different holdout"):
                    st.write(metrics["historical"]["note"])
                    st.json(metrics["historical"]["evaluation"])
        st.markdown("Training source: [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) "
                    "(Apache-2.0), plus Tripwire attack and legitimate-question examples.")
        st.caption(f"Trained {metrics['training_date']} · seed {metrics['random_seed']} · scikit-learn {metrics['sklearn_version']}")
        st.json(metrics["dataset_sizes"])
        st.write(metrics["evaluation_note"])
        evidence, tradeoffs = st.columns(2)
        with evidence:
            labels = ["accuracy", "precision", "recall", "f1", "roc_auc"]
            frame = pd.DataFrame({"Metric": labels, "Trained firewall": [metrics["evaluation"][k] for k in labels],
                                  "Most-frequent baseline": [metrics["baseline"][k] for k in labels]})
            for metric in ["precision", "recall", "f1", "roc_auc"]:
                stat_card(metric.replace("_", " "), format(metrics["evaluation"][metric], ".3f"), help=f'Baseline {metrics["baseline"][metric]:.3f}')
            st.dataframe(frame, hide_index=True, width="stretch")
            render_chart(px.imshow(np.array(metrics["evaluation"]["confusion_matrix"]),
                x=["Predicted benign", "Predicted injection"], y=["Actual benign", "Actual injection"],
                text_auto=True, color_continuous_scale="YlOrBr", title=f"Test confusion matrix · threshold {metrics.get('threshold', .5):.4f}"), width="stretch")
        with tradeoffs:
            st.caption("Threshold evidence below uses validation only." if metrics.get("thresholds_split") == "validation" else "Historical threshold evidence used the old test split.")
            thresholds = []
            for threshold, values in metrics["thresholds"].items():
                tn, fp = values["confusion_matrix"][0]
                thresholds.append({"Threshold": float(threshold), **{k: values[k] for k in labels},
                                   "False-positive rate": fp / (tn + fp) if tn + fp else 0})
            st.dataframe(pd.DataFrame(thresholds), hide_index=True, width="stretch")
            for key, title in [("false_positives", "Example false positives"), ("false_negatives", "Example false negatives")]:
                with st.expander(title):
                    st.caption("Held-out dataset examples are displayed as data and never sent to the target bots.")
                    if metrics[key]:
                        st.code(json.dumps(metrics[key], indent=2, ensure_ascii=False), language=None)
                    else:
                        st.write("No examples observed at the selected threshold.")
    st.subheader("Guardrails")
    for item in [
        "Only simulated bots: there is no external target URL or endpoint input.",
        "The fixed attack library tests leaks and business-rule violations without harmful-content requests.",
        "Judge inputs are delimited untrusted data. Two rule orders are evaluated; disagreements require review. Deterministic canary/secret detection overrides the judge.",
        "Layer 3 output guard blocks known confidential strings and patterns before delivery. It can miss unknown disclosures.",
        "Canary detection checks exact, normalised, reversed, base64 and hex-only forms and has unit tests.",
        "Normal questions measure over-refusal and firewall false positives beside security scores.",
        "History is optional. Prompts are saved only with opt-in; hashes are stored by default and excerpts are capped at 300 characters.",
        "Prompts and conversations are sent to OpenAI; use authorised, non-sensitive data.",
        "Input limits: 4000-character system prompts, 40 attacks per scan, 30 scan slots per session, five workers.",
        "Keys remain in server-side secrets or gitignored .env files. API failures have bounded retries and visible errors.",
        "The local model is loaded only from a trusted bundled artifact. Do not substitute untrusted joblib files.",
    ]:
        st.write(f"✓ {item}")
    st.subheader("Known limitations")
    for item in [
        "LLM judges can misjudge borderline cases or follow an injection despite the defence. Temperature zero and canaries reduce, but do not eliminate, this risk.",
        "A simulated prompt is not a production bot with tools, RAG, authentication or additional safety layers.",
        "TF-IDF may miss novel, paraphrased or non-English attacks, and may flag legitimate uses of 'ignore' or 'instructions'.",
        "The attack library is fixed. Real attackers adapt, and model versions can change results.",
        "Local attack examples partly train the firewall, so demo scan scores are not an independent generalisation benchmark.",
        "Session limits are a demo cost guardrail, not account-level quotas or authentication. A public deployment shares configured history across visitors.",
        "Benign judgement errors are excluded from refusal rates; review coverage. Benign responses leaking confidential data are recorded as unsafe answers.",
    ]:
        st.caption(f"⚠ {item}")

    st.subheader("Judge Check")
    saved_metrics_path = ROOT / "ml/judge_metrics.json"
    if saved_metrics_path.exists():
        try:
            recorded = json.loads(saved_metrics_path.read_text(encoding="utf-8"))
            st.caption(f"Saved CLI evaluation: {recorded['evaluated_at']} · model {recorded['model']} · {'SCRIPTED MOCK — not accuracy' if recorded['mock'] else 'live API'}")
            if "before" in recorded:
                st.write(f"Saved agreement: {recorded['before']['agreement']:.1%} → {recorded['after']['agreement']:.1%} ({recorded['after']['n']} examples).")
            else:
                st.write(f"Saved agreement: {recorded['after']['agreement']:.1%} ({recorded['after']['n']} examples).")
            st.caption(recorded["note"])
            saved_matrix = pd.DataFrame(recorded["after"]["confusion_matrix"],
                index=recorded["after"]["labels"][:3], columns=recorded["after"]["labels"])
            render_chart(px.imshow(saved_matrix, text_auto=True, labels={"x": "Judge verdict", "y": "Human label"}, color_continuous_scale="YlOrBr", title="Saved judge confusion matrix"), width="stretch")
            if recorded["after"]["disagreements"]:
                with st.expander("Saved judge disagreements"):
                    st.dataframe(pd.DataFrame(recorded["after"]["disagreements"]), hide_index=True, width="stretch")
        except (OSError, ValueError, TypeError, KeyError):
            st.info("Run python scripts/eval_judge.py to refresh saved judge metrics.")
    st.caption("Five illustrative seed labels are provided in data/judge_gold.json. Edit and expand them before treating this as a benchmark. Each item uses two judges, plus possible retries. Mock results are scripted, not model reliability measurements.")
    from core.config import get_settings
    from core.judge_check import evaluate, VERDICTS
    import hashlib
    try:
        gold_text = (ROOT / "data/judge_gold.json").read_text(encoding="utf-8")
        examples = json.loads(gold_text)
        if not isinstance(examples, list) or not examples or len(examples) > 100:
            raise ValueError("Use a non-empty gold list of at most 100 examples.")
        from core.llm import mock_mode_enabled
        identity = hashlib.sha256((gold_text + get_settings().judge_model + get_settings().base_url + str(mock_mode_enabled())).encode()).hexdigest()
        st.caption(f"{len(examples)} labelled examples; at least {2 * len(examples)} judge API calls in live mode.")
        if st.button("Run judge check"):
            progress = st.progress(0)
            try:
                rows = evaluate(examples, lambda n, total: progress.progress(n / total))
                st.session_state["judge_check"] = {"identity": identity, "rows": rows}
            finally:
                progress.empty()
        saved = st.session_state.get("judge_check", {})
        if saved.get("identity") == identity:
            rows = saved["rows"]
            frame = pd.DataFrame(rows)
            st.metric("Agreement with human labels", f"{100 * sum(r['Agrees'] for r in rows) / len(rows):.1f}%")
            st.caption("Denominator includes all examples: errors and Needs review count as disagreements.")
            matrix = pd.crosstab(frame["Human"], frame["Judge"]).reindex(index=VERDICTS[:3], columns=VERDICTS, fill_value=0)
            render_chart(px.imshow(matrix, text_auto=True, labels={"x": "Judge verdict", "y": "Human label", "color": "Examples"}, color_continuous_scale="YlOrBr"), width="stretch")
            st.subheader("Disagreements")
            disagreements = frame[~frame["Agrees"]]
            if disagreements.empty:
                st.success("All labels agreed on this gold set.")
            else:
                st.dataframe(disagreements, hide_index=True, width="stretch")
        elif saved:
            st.info("Gold examples or judge model changed. Run the check again to refresh agreement.")
    except (OSError, ValueError, TypeError, KeyError):
        st.error("Judge Check could not load valid examples or complete. Check data/judge_gold.json and API access, then retry.")
