"""Export aggregate comparison evidence without transcripts or private values."""
from core.scoring import summarize

MODE_NAMES = {"baseline": "Baseline", "hardened_prompt": "Hardened prompt",
              "hardened_prompt_firewall": "Hardened + firewall",
              "hardened_prompt_firewall_guard": "Hardened + firewall + output guard"}


def format_rate(value: float | None) -> str:
    """Format percentages, keeping missing evaluations visibly distinct."""
    return "N/A" if value is None else f"{value:.1f}%"


def comparison_report(results: list, threshold: float, use_firewall: bool = True) -> str:
    """Generate Markdown from aggregates only; no canaries, secrets, prompts or API payloads."""
    lines = ["# Tripwire security comparison", "",
             "Simulated chatbot evaluation. No prompts, response transcripts, canaries, or API payloads are included.",
             "", f"Firewall enabled in final mode: {use_firewall}. Threshold: {threshold:.2f}.", "",
             "| Mode | Security | Grade | Over-refusal | Firewall false positives | Attack errors | Benign errors |",
             "|---|---:|:---:|---:|---:|---:|---:|"]
    for result in results:
        metrics = summarize(result)
        lines.append(f"| {MODE_NAMES[result.mode_label]} | {format_rate(metrics['security_score'])} | "
                     f"{metrics['grade']} | {format_rate(metrics['over_refusal_rate'])} | "
                     f"{format_rate(metrics['firewall_false_positive_rate'])} | "
                     f"{metrics['attack_errors']} | {metrics['benign_errors']} |")
    lines += ["", "## Category scores", "", "| Mode | Category | Security |", "|---|---|---:|"]
    for result in results:
        for category, score in summarize(result)["category_scores"].items():
            lines.append(f"| {MODE_NAMES[result.mode_label]} | {category} | {format_rate(score)} |")
    lines += ["", "## Attack verdict changes", "", "| Attack ID | " + " | ".join(MODE_NAMES[r.mode_label] for r in results) + " |",
              "|" + "---|" * (len(results) + 1)]
    if len(results) > 1:
        for rows in zip(*(result.attack_rows for result in results)):
            lines.append(f"| {rows[0]['id']} | " + " | ".join(r['verdict'] for r in rows) + " |")
    lines += ["", "Errors and needs_review disagreements are excluded from scored denominators; incomplete scans may overstate security. blocked_output counts as resisted.",
              "A security gain can increase over-refusal. Local attack examples partly train the firewall; "
              "use the independent held-out model-card metrics when assessing generalisation.",
              "LLM judgements are fallible and simulated bots do not represent all production layers."]
    return "\n".join(lines) + "\n"
