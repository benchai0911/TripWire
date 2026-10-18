"""Local, explainable TF-IDF + Logistic Regression prompt firewall."""
import joblib
import streamlit as st
from core.config import ROOT, FIREWALL_THRESHOLD_DEFAULT


@st.cache_resource
def load_model():
    """Load only the trusted bundled artifact, once per server process."""
    path = ROOT / "ml/firewall.joblib"
    if not path.exists():
        raise FileNotFoundError("Firewall model missing. Install requirements-train.txt and run python ml/train_firewall.py.")
    return joblib.load(path)


def score(text: str) -> float:
    """Return the estimated injection probability; this is not calibrated certainty."""
    model = load_model()
    classes = list(model.classes_)
    return float(model.predict_proba([text])[0, classes.index(1)])


def is_blocked(text: str, threshold: float = FIREWALL_THRESHOLD_DEFAULT) -> bool:
    """Decide whether the local model score reaches the chosen threshold."""
    if not 0.1 <= threshold <= 0.9:
        raise ValueError("Threshold must be between 0.1 and 0.9.")
    return score(text) >= threshold


def explain(text: str, top_k: int = 8) -> list[tuple[str, float]]:
    """Present positive feature contributions (linear scores, not calibrated probability)."""
    model = load_model()
    values = feature_evidence(model, text)
    return sorted((v for v in values if v[1] > 0), key=lambda item: item[1], reverse=True)[:max(0, top_k)]


def feature_evidence(model, text):
    """Signed linear feature evidence; calibrated SVC uses mean fold margins."""
    if not hasattr(model, "named_steps"):
        # The SVC candidate calibrates complete pipelines. Average positive evidence
        # across its fitted folds; each fold has its own vocabulary.
        from collections import defaultdict
        combined = defaultdict(float)
        for calibrated in model.calibrated_classifiers_:
            for name, weight in _explain_pipeline(calibrated.estimator, text):
                combined[name] += weight / len(model.calibrated_classifiers_)
        return list(combined.items())
    return _explain_pipeline(model, text)


def _explain_pipeline(model, text):
    features = model.named_steps["features"]
    vector = features.transform([text]).tocsr()
    names = features.get_feature_names_out()
    classifier = model.named_steps["clf"]
    weights = (classifier.coef_[0] if hasattr(classifier, "coef_") else
               classifier.feature_log_prob_[1] - classifier.feature_log_prob_[0])
    contributions = [(str(names[index]), float(value * weights[index]))
                     for index, value in zip(vector.indices, vector.data)]
    return sorted(contributions, key=lambda item: item[1], reverse=True)
