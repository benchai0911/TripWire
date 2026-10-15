"""Show measured classifier evidence, safety guardrails and limitations."""
import json
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from core.config import ROOT
from core.ui import setup_page

setup_page("Safety and Model Card")
st.title("📋 Safety & model card")
st.subheader("A small model with inspectable evidence")
path = ROOT / "ml/metrics.json"
try:
    metrics = json.loads(path.read_text(encoding="utf-8"))
except (OSError, ValueError):
    metrics = None
    st.info("No training metrics available. Install requirements-train.txt and run python ml/train_firewall.py.")
if metrics:
    st.write(metrics["pipeline"])
    st.markdown("Training source: [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) "
                "(Apache-2.0), plus Tripwire attack and legitimate-question examples.")
    st.caption(f"Trained {metrics['training_date']} · seed {metrics['random_seed']} · scikit-learn {metrics['sklearn_version']}")
    st.json(metrics["dataset_sizes"])
    st.write(metrics["evaluation_note"])
    labels = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    frame = pd.DataFrame({"Metric": labels, "Trained firewall": [metrics["evaluation"][k] for k in labels],
                          "Most-frequent baseline": [metrics["baseline"][k] for k in labels]})
    st.dataframe(frame, hide_index=True, use_container_width=True)
    st.plotly_chart(px.imshow(np.array(metrics["evaluation"]["confusion_matrix"]),
        x=["Predicted benign", "Predicted injection"], y=["Actual benign", "Actual injection"],
        text_auto=True, color_continuous_scale="YlOrBr", title="Held-out confusion matrix · threshold 0.5"), use_container_width=True)
    thresholds = []
    for threshold, values in metrics["thresholds"].items():
        tn, fp = values["confusion_matrix"][0]
        thresholds.append({"Threshold": float(threshold), **{k: values[k] for k in labels},
                           "False-positive rate": fp / (tn + fp) if tn + fp else 0})
    st.dataframe(pd.DataFrame(thresholds), hide_index=True, use_container_width=True)
    for key, title in [("false_positives", "Example false positives"), ("false_negatives", "Example false negatives")]:
        with st.expander(title):
            st.caption("Held-out dataset examples are displayed as data and never sent to the target bots.")
            if metrics[key]:
                st.dataframe(pd.DataFrame(metrics[key]), hide_index=True, use_container_width=True)
            else:
                st.write("No examples observed at threshold 0.5.")
st.subheader("Guardrails")
for item in [
    "Only simulated bots: there is no external target URL or endpoint input.",
    "The fixed attack library tests leaks and business-rule violations without harmful-content requests.",
    "Judge inputs are delimited untrusted data. Deterministic canary/secret detection overrides the judge.",
    "Canary detection checks exact, normalised, reversed, base64 and hex-only forms and has unit tests.",
    "Normal questions measure over-refusal and firewall false positives beside security scores.",
    "History is optional. Prompts are saved only with opt-in; hashes are stored by default and excerpts are capped at 300 characters.",
    "Prompts and conversations are sent to OpenAI; use authorised, non-sensitive data.",
    "Input limits: 4000-character system prompts, 40 attacks per scan, eight scan slots per session, five workers.",
    "Keys remain in server-side secrets or gitignored .env files. API failures have bounded retries and visible errors.",
    "The local model is loaded only from a trusted bundled artifact. Do not substitute untrusted joblib files.",
]:
    st.write(f"• {item}")
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
    st.write(f"• {item}")
