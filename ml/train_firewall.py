"""Train an offline prompt firewall with honest, deduplicated holdout evaluation.

Run from the repository root: python ml/train_firewall.py
No training example is ever sent to an LLM or added to the app's attack library.
"""
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Hugging Face includes the full cache path again in lock filenames on Windows.
# A short OS-temp cache avoids MAX_PATH errors in deeply nested project folders.
os.environ.setdefault("HF_HOME", str(Path(tempfile.gettempdir()) / "tw-hf")
                      if os.name == "nt" else str(ROOT / ".build-cache/huggingface"))

import joblib
import numpy as np
import sklearn
from datasets import load_dataset
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

SEED = 42
EXTRA_BENIGN = [
    "What time does the café open on Sunday?", "Is the café open on public holidays?",
    "Can I reserve a table for two?", "How much does a cup of coffee cost?",
    "Is takeaway available?", "Do you serve decaffeinated coffee?",
    "Can I have my toast without butter?", "Are there dairy-free drinks?",
    "Is there space for a stroller?", "Where can I find the café menu?",
    "Can I pay by card?", "How long does a takeaway order take?",
    "Do you serve breakfast all day?", "Is there a set meal on the menu?",
    "Please explain the password reset instructions.", "I forgot my student login name.",
    "Is the official reset portal available on mobile?", "How do I enrol in MFA?",
    "What should I do if my login verification expires?", "Where can I find IT helpdesk hours?",
    "How can I contact campus IT support?", "Can you explain the account recovery process?",
    "I cannot open the student portal. Who can help?", "Do I need my student ID to contact support?",
    "How can I update my recovery email through the portal?", "Can I ignore an old password reset email?",
    "How many sick leave days are available?", "What benefits apply to full-time staff?",
    "Where can I find the leave request form?", "Can I use leave in half-day increments?",
    "Who approves my annual leave?", "How do I check my own leave balance?",
    "Who can explain the learning allowance?", "Is outpatient care covered by our benefits?",
    "How do I submit a training reimbursement?", "Where is the benefits portal?",
    "How does leave proration work?", "How can I update my own contact details?",
    "Please summarise the public leave policy.", "What is the email address for HR support?",
]


def canonical(text: str) -> str:
    """Group case/whitespace duplicates to prevent train/test overlap."""
    return " ".join(text.casefold().split())


def evaluate(labels, probabilities, threshold: float) -> dict:
    """Compute classification and ranking metrics on a held-out set."""
    predictions = (np.asarray(probabilities) >= threshold).astype(int)
    return {"accuracy": float(accuracy_score(labels, predictions)),
            "precision": float(precision_score(labels, predictions, zero_division=0)),
            "recall": float(recall_score(labels, predictions, zero_division=0)),
            "f1": float(f1_score(labels, predictions, zero_division=0)),
            "roc_auc": float(roc_auc_score(labels, probabilities)),
            "confusion_matrix": confusion_matrix(labels, predictions, labels=[0, 1]).tolist()}


def main() -> None:
    """Load official splits, augment, train, evaluate and save reproducible artifacts."""
    try:
        dataset = load_dataset("deepset/prompt-injections")
        if not {"train", "test"}.issubset(dataset):
            raise ValueError("Expected official train and test splits.")
    except Exception:
        print("Could not load deepset/prompt-injections. Check network access and Hugging Face availability; no artifact was created.", file=sys.stderr)
        raise SystemExit(1)
    attack_data = json.loads((ROOT / "data/attacks.json").read_text(encoding="utf-8"))
    benign_data = json.loads((ROOT / "data/benign_prompts.json").read_text(encoding="utf-8"))
    extra = [(r["prompt"], 1) for r in attack_data] + [(r["prompt"], 0) for r in benign_data]
    extra += [(text, 0) for text in EXTRA_BENIGN]
    # Deduplicate before splitting, not afterwards (including conflicting labels).
    unique_extra = {canonical(text): (text, label) for text, label in extra}
    extra = list(unique_extra.values())
    extra_train, extra_test = train_test_split(extra, test_size=0.2, random_state=SEED,
                                             stratify=[label for _, label in extra])
    original_train = [(r["text"], int(r["label"])) for r in dataset["train"]]
    original_test = [(r["text"], int(r["label"])) for r in dataset["test"]]
    test_map = {canonical(t): (t, label) for t, label in original_test + extra_test}
    train_map = {canonical(t): (t, label) for t, label in original_train + extra_train
                 if canonical(t) not in test_map}
    train, test = list(train_map.values()), list(test_map.values())
    x_train, y_train = zip(*train)
    x_test, y_test = zip(*test)
    assert not set(map(canonical, x_train)) & set(map(canonical, x_test))
    model = Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0, random_state=SEED)),
    ])
    model.fit(x_train, y_train)
    probabilities = model.predict_proba(x_test)[:, list(model.classes_).index(1)]
    dummy = DummyClassifier(strategy="most_frequent").fit(np.zeros((len(train), 1)), y_train)
    baseline_probabilities = dummy.predict_proba(np.zeros((len(test), 1)))[:, list(dummy.classes_).index(1)]
    predictions = probabilities >= 0.5

    def mistakes(label: int, prediction: bool) -> list[dict]:
        return [{"text": text, "label": int(actual), "probability": float(probability)}
                for text, actual, predicted, probability in zip(x_test, y_test, predictions, probabilities)
                if actual == label and predicted == prediction][:10]

    metrics = {
        "dataset": "deepset/prompt-injections", "dataset_url": "https://huggingface.co/datasets/deepset/prompt-injections",
        "dataset_license": "Apache-2.0", "training_date": datetime.now(timezone.utc).isoformat(),
        "random_seed": SEED, "sklearn_version": sklearn.__version__,
        "pipeline": "Word (1–2) + char_wb (3–5) TF-IDF → balanced LogisticRegression, C=4",
        "dataset_sizes": {"official_train": len(original_train), "official_test": len(original_test),
                          "extra_unique": len(extra), "extra_train": len(extra_train), "extra_test": len(extra_test),
                          "train": len(train), "test": len(test),
                          "train_injections": int(sum(y_train)), "test_injections": int(sum(y_test)),
                          "removed_train_duplicates_or_overlap": len(original_train) + len(extra_train) - len(train)},
        "evaluation": evaluate(y_test, probabilities, 0.5),
        "baseline": {"strategy": "most_frequent", **evaluate(y_test, baseline_probabilities, 0.5)},
        "thresholds": {str(t): evaluate(y_test, probabilities, t) for t in [0.3, 0.5, 0.7]},
        "false_positives": mistakes(0, True), "false_negatives": mistakes(1, False),
        "evaluation_note": "Official test split plus stratified 20% local holdout; normalized duplicates removed from training. Local attack examples partly train this model, so app scans are not an independent firewall benchmark.",
    }
    output = ROOT / "ml/firewall.joblib"
    joblib.dump(model, output, compress=3)
    if output.stat().st_size >= 20 * 1024 * 1024:
        output.unlink()
        raise SystemExit("Artifact exceeded 20 MB; reduce features before deployment.")
    metrics["artifact_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    metrics["artifact_bytes"] = output.stat().st_size
    (ROOT / "ml/metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"held_out": metrics["evaluation"], "dummy": metrics["baseline"],
                      "sizes": metrics["dataset_sizes"], "artifact_bytes": metrics["artifact_bytes"]}, indent=2))


if __name__ == "__main__":
    main()
