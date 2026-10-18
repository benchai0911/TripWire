"""Train-only CV, validation-only threshold selection, final test-only reporting."""
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("HF_HOME", str(Path(tempfile.gettempdir()) / "tw-hf") if os.name == "nt"
                      else str(ROOT / ".build-cache/huggingface"))
import joblib
import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC
from core.normalization import normalize

SEED = 42


def canonical(text):
    return normalize(text)


def features(normalized=True):
    options = {"preprocessor": normalize, "lowercase": False} if normalized else {"lowercase": True}
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, **options)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, **options)),
    ])


def candidates():
    lr = Pipeline([("features", features()), ("clf", LogisticRegression(max_iter=2000,
                    class_weight="balanced", C=4.0, random_state=SEED))])
    # Calibrate the entire pipeline in inner train folds, including vocabulary fitting.
    svc = CalibratedClassifierCV(Pipeline([("features", features()),
        ("clf", LinearSVC(class_weight="balanced", random_state=SEED))]),
        cv=StratifiedKFold(3, shuffle=True, random_state=SEED), method="sigmoid")
    nb = Pipeline([("features", features()), ("clf", ComplementNB())])
    return {"LogisticRegression": lr, "Calibrated LinearSVC": svc, "ComplementNB": nb}


def evaluate(labels, probabilities, threshold):
    predictions = np.asarray(probabilities) >= threshold
    matrix = confusion_matrix(labels, predictions, labels=[0, 1]).tolist()
    tn, fp = matrix[0]
    return {"accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "false_positive_rate": fp / (tn + fp) if tn + fp else 0., "confusion_matrix": matrix}


def choose_threshold(labels, probabilities):
    probabilities = np.asarray(probabilities)
    boundaries = np.unique(np.r_[.1, .5, .9, np.clip(probabilities, .1, .9),
        np.clip(np.nextafter(probabilities, np.inf), .1, .9)])
    rows = [(float(t), evaluate(labels, probabilities, float(t))) for t in boundaries]
    feasible = [(t, m) for t, m in rows if m["false_positive_rate"] <= .05]
    if not feasible:
        raise ValueError("No threshold in app range [0.1,0.9] meets validation FPR <=5%; no artifact published.")
    return max(feasible, key=lambda row: (row[1]["recall"], -row[1]["false_positive_rate"], row[0]))


def split_rows(rows):
    development, test = train_test_split(rows, test_size=.2, stratify=[r[1] for r in rows], random_state=SEED)
    train, validation = train_test_split(development, test_size=.25,
        stratify=[r[1] for r in development], random_state=SEED)
    return train, validation, test


def load_splits():
    from datasets import load_dataset
    dataset = load_dataset("deepset/prompt-injections")
    official = [(r["text"], int(r["label"])) for split in ["train", "test"] for r in dataset[split]]
    local = [(r["prompt"], label) for name, label in [("attacks", 1), ("benign_prompts", 0)]
             for r in json.loads((ROOT / f"data/{name}.json").read_text(encoding="utf-8"))]
    local.extend((t, 0) for t in json.loads((ROOT / "data/firewall_benign_extra.json").read_text(encoding="utf-8")))
    custom_sources = []
    for name, label in [("hard_negatives", 0), ("paraphrased_attacks", 1)]:
        values = json.loads((ROOT / f"data/{name}.json").read_text(encoding="utf-8"))
        if len(values) != 30 or any(not isinstance(t, str) or not t.strip() for t in values):
            raise ValueError(f"{name} must contain 30 nonempty strings")
        custom_sources.append([(t, label) for t in values])
    # Global deduplication before partitioning; conflicting labels are dropped.
    grouped = {}
    all_rows = official + local + [row for source in custom_sources for row in source]
    for text, label in all_rows:
        grouped.setdefault(canonical(text), set()).add(label)
    conflicts = {key for key, labels in grouped.items() if len(labels) != 1}
    seen, sources = set(conflicts), []
    for source in [official, local, *custom_sources]:
        rows = []
        for text, label in source:
            key = canonical(text)
            if key not in seen:
                seen.add(key)
                rows.append((text, label))
        sources.append(rows)
    splits = [split_rows(rows) for rows in sources]
    train, validation, test = [[row for split in splits for row in split[i]] for i in range(3)]
    keys = [set(canonical(t) for t, _ in rows) for rows in [train, validation, test]]
    assert not (keys[0] & keys[1] or keys[0] & keys[2] or keys[1] & keys[2])
    manifest = {name: [{"sha256": hashlib.sha256(canonical(t).encode()).hexdigest(), "label": label}
                       for t, label in rows] for name, rows in zip(["train", "validation", "test"], [train, validation, test])}
    return train, validation, test, manifest, {"official_unique": len(sources[0]), "custom_unique": sum(map(len, sources[1:])),
        "conflicting_texts_removed": len(conflicts), "custom_train": sum(len(s[0]) for s in splits[1:]),
        "custom_validation": sum(len(s[1]) for s in splits[1:]), "custom_test": sum(len(s[2]) for s in splits[1:]),
        "per_source_splits": {name: dict(zip(["train", "validation", "test"], map(len, split)))
            for name, split in zip(["official", "existing_custom", "hard_negatives", "paraphrased_attacks"], splits)}}


def main():
    train, validation, test, manifest, sizes = load_splits()
    x_train, y_train = zip(*train)
    x_val, y_val = zip(*validation)
    choices, comparison = candidates(), []
    cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
    for name, estimator in choices.items():
        values = cross_val_score(estimator, x_train, y_train, scoring="f1", cv=cv, n_jobs=1)
        comparison.append({"model": name, "cv_f1_mean": float(values.mean()),
            "cv_f1_std": float(values.std()), "fold_f1": values.tolist()})
        print(f"Train-only 5-fold CV {name}: F1 {values.mean():.4f}", flush=True)
    winner = max(comparison, key=lambda row: row["cv_f1_mean"])["model"]
    model = choices[winner].fit(x_train, y_train)
    validation_probs = model.predict_proba(x_val)[:, list(model.classes_).index(1)]
    threshold, validation_metrics = choose_threshold(y_val, validation_probs)
    print(f"Frozen: {winner}; threshold {threshold:.6f}; validation FPR {validation_metrics['false_positive_rate']:.2%}", flush=True)
    # Refit reference: the old saved artifact has already seen part of the new test split.
    reference = Pipeline([("features", features(normalized=False)), ("clf", LogisticRegression(
        max_iter=2000, class_weight="balanced", C=4.0, random_state=SEED))]).fit(x_train, y_train)
    # Final test access begins only after all selection has been frozen.
    x_test, y_test = zip(*test)
    probabilities = model.predict_proba(x_test)[:, list(model.classes_).index(1)]
    reference_probs = reference.predict_proba(x_test)[:, list(reference.classes_).index(1)]
    dummy = DummyClassifier(strategy="most_frequent").fit(np.zeros((len(train), 1)), y_train)
    dummy_probs = dummy.predict_proba(np.zeros((len(test), 1)))[:, list(dummy.classes_).index(1)]
    output, temporary = ROOT / "ml/firewall.joblib", ROOT / "ml/firewall.pending.joblib"
    joblib.dump(model, temporary, compress=3)
    if temporary.stat().st_size >= 20 * 1024 * 1024:
        temporary.unlink()
        raise ValueError("Artifact exceeds 20 MB")
    temporary.replace(output)
    metrics = {"dataset": "deepset/prompt-injections", "dataset_url": "https://huggingface.co/datasets/deepset/prompt-injections",
        "dataset_license": "Apache-2.0", "training_date": datetime.now(timezone.utc).isoformat(),
        "random_seed": SEED, "sklearn_version": sklearn.__version__, "pipeline": f"Normalised word + char TF-IDF -> {winner}",
        "selected_model": winner, "threshold": threshold, "threshold_selection_split": "validation",
        "model_selection_split": "train (stratified 5-fold CV)", "model_comparison": comparison,
        "validation": validation_metrics, "dataset_sizes": {**sizes, "train": len(train), "validation": len(validation), "test": len(test)},
        "evaluation": evaluate(y_test, probabilities, threshold),
        "before": {"description": "Previous pipeline refit on identical raw training split; threshold 0.5", **evaluate(y_test, reference_probs, .5)},
        "baseline": {"strategy": "most_frequent", **evaluate(y_test, dummy_probs, .5)},
        "thresholds": {str(threshold): validation_metrics}, "thresholds_split": "validation",
        "artifact_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "artifact_bytes": output.stat().st_size,
        "evaluation_note": "Stratified 60/20/20 per source, seed 42; normalized duplicates and conflicting labels removed before split. Official source splits were repartitioned. Train-only CV selects model; validation selects maximum recall at FPR <=5%. Test accessed once after selection. App library partly trains firewall; app scans are not an independent benchmark.",
        "false_positives": [], "false_negatives": []}
    for label, predicted, field in [(0, True, "false_positives"), (1, False, "false_negatives")]:
        metrics[field] = [{"text": t, "label": int(y), "probability": float(p)} for t, y, p in zip(x_test, y_test, probabilities)
            if y == label and (p >= threshold) == predicted][:10]
    historical = ROOT / "ml/metrics_before_accuracy.json"
    if historical.exists():
        metrics["historical"] = {"evaluation": json.loads(historical.read_text(encoding="utf-8"))["evaluation"],
            "note": "Different old holdout; not directly comparable. Use before vs evaluation for same-split comparison."}
    (ROOT / "ml/firewall_split_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (ROOT / "ml/metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"before": metrics["before"], "after": metrics["evaluation"], "threshold": threshold, "sizes": metrics["dataset_sizes"]}, indent=2))


if __name__ == "__main__":
    main()
