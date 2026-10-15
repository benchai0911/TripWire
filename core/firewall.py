"""Local, explainable TF-IDF + Logistic Regression prompt firewall."""
import joblib
import streamlit as st
from core.config import ROOT


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


def is_blocked(text: str, threshold: float = 0.5) -> bool:
    """Decide whether the local model score reaches the chosen threshold."""
    if not 0.1 <= threshold <= 0.9:
        raise ValueError("Threshold must be between 0.1 and 0.9.")
    return score(text) >= threshold


def explain(text: str, top_k: int = 8) -> list[tuple[str, float]]:
    """Return present word/character n-grams with positive log-odds contributions."""
    model = load_model()
    features = model.named_steps["features"]
    vector = features.transform([text]).tocsr()
    names = features.get_feature_names_out()
    weights = model.named_steps["clf"].coef_[0]
    contributions = [(str(names[index]), float(value * weights[index]))
                     for index, value in zip(vector.indices, vector.data)
                     if value * weights[index] > 0]
    return sorted(contributions, key=lambda item: item[1], reverse=True)[:max(0, top_k)]
