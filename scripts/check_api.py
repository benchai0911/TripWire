"""Probe the configured OpenAI target without printing secrets or API bodies."""
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import openai
from core.config import get_settings


def main() -> None:
    """Make one small request and print only safe diagnostic metadata."""
    settings = get_settings()
    print("Key configured:", bool(settings.api_key))
    print("Target model:", settings.model)
    print("Judge model:", settings.judge_model)
    if not settings.api_key:
        print("Configure OPENAI_API_KEY before checking connectivity.")
        return
    try:
        with openai.OpenAI(api_key=settings.api_key, base_url=settings.base_url, timeout=15, max_retries=0) as client:
            if "--scan" in sys.argv:
                from core.attacks import load_attacks, load_benign
                from core.presets import load_presets
                from core.scanner import run_scan
                bot = load_presets()[0]
                result = run_scan(bot["system_prompt"], bot["rules"], bot["secret_note"],
                                  load_attacks()[:1], load_benign(bot["id"])[:1], False, 0.5, "baseline")
                print("Attack verdict:", result.attack_rows[0]["verdict"])
                print("Verdict source:", result.attack_rows[0]["source"])
                print("Benign answered:", result.benign_rows[0]["answered"])
                print("API attempts:", result.api_calls)
                if result.attack_rows[0]["verdict"] == "error":
                    print("Failure:", result.attack_rows[0]["reason"])
                return
            if "--list-models" in sys.argv:
                models = client.models.list()
                names = sorted(model.id for model in models
                               if re.fullmatch(r"(?:models/)?gemini-[A-Za-z0-9._-]{1,80}", model.id))
                print("Available Gemini models:", ", ".join(names))
                return
            model = sys.argv[sys.argv.index("--model") + 1] if "--model" in sys.argv else settings.model
            print("Probed model:", model)
            client.chat.completions.create(model=model,
                messages=[{"role": "user", "content": "Reply OK"}], temperature=0, max_tokens=5)
        print("API probe succeeded")
    except Exception as error:
        print("Exception type:", type(error).__name__)
        print("HTTP status:", getattr(error, "status_code", None))
        body = getattr(error, "body", None)
        code = body.get("code") if isinstance(body, dict) else None
        # Never print arbitrary API response values; allow only known public codes.
        allowed = {"insufficient_quota", "invalid_api_key", "model_not_found", "rate_limit_exceeded",
                   "credit_balance_exhausted", "organization_usage_limit_exceeded", "billing_hard_limit_reached"}
        print("API error code:", code if code in allowed else "unclassified")
        print("API response format:", type(body).__name__)
        # Classify known provider phrases; never print the underlying message.
        text = str(body).casefold()
        mentioned = sorted(set(re.findall(r"gemini-[a-z0-9]+(?:[._-][a-z0-9]+)*", text)))
        if mentioned:
            print("Models mentioned by provider:", ", ".join(mentioned))
        for phrase, label in [
            ("api key not valid", "Provider rejected the API key"),
            ("api_key_invalid", "Provider rejected the API key"),
            ("not found", "Requested model or route was not found"),
            ("no longer available", "Requested model is no longer available"),
            ("not supported", "Requested model or API operation is unsupported"),
        ]:
            if phrase in text:
                print("Provider diagnosis:", label)
        print("Cause type:", type(error.__cause__).__name__ if error.__cause__ else None)


if __name__ == "__main__":
    main()
