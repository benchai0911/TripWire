"""Shared quick-scan selection and pre-cache request estimates."""
import math
from core.judge import double_enabled
from core.llm import requests_per_minute


def choose(attacks, full=False):
    counts, selected = {}, []
    for item in attacks:
        category = item["category"]
        counts[category] = counts.get(category, 0) + 1
        if full or counts[category] <= 2:
            selected.append(item)
    return selected


def estimate(attack_count, benign_count, settings):
    judges = math.ceil(attack_count / 6) * (2 if double_enabled() else 1) + bool(benign_count)
    targets = attack_count + benign_count
    return {"calls": targets + judges, "minutes": targets / requests_per_minute(settings.model) + judges / requests_per_minute(settings.judge_model)}
