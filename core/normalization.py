"""Stateless text normalisation shared by training, inference and overlap checks."""
import re
import unicodedata

LEET = str.maketrans("013457@$", "oieastas")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = text.translate(LEET)
    text = re.sub(r"(.)\1+", r"\1", text)
    return " ".join(text.split())
