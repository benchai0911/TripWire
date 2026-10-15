"""Actionable, secret-safe error messages for model and transport failures."""
import openai


def safe_error_message(error: Exception) -> str:
    """Classify errors without displaying API bodies, credentials or request text."""
    body = getattr(error, "body", None)
    details = body.get("error", body) if isinstance(body, dict) else {}
    code = details.get("code") if isinstance(details, dict) else None
    if code in {"insufficient_quota", "credit_balance_exhausted", "organization_usage_limit_exceeded",
                "billing_hard_limit_reached"}:
        return "API quota or credits exhausted. Check the API project's billing balance and usage limits."
    if isinstance(error, openai.AuthenticationError):
        return "API authentication failed (401). Check that the key is valid and belongs to the selected model provider."
    if isinstance(error, openai.PermissionDeniedError):
        return "API permission denied (403). Check the key's project permissions and model access."
    if isinstance(error, openai.NotFoundError):
        return "Model or API endpoint not found (404). Check OPENAI_MODEL and JUDGE_MODEL against the models available from your provider, and verify OPENAI_BASE_URL points to its Chat Completions endpoint."
    if isinstance(error, openai.BadRequestError):
        return "API rejected the request (400). Check that the selected model supports Chat Completions, JSON mode, temperature and max_tokens."
    if isinstance(error, openai.RateLimitError):
        return "API rate limit reached (429). Wait before re-running, reduce request volume, or check the project's API limits."
    if isinstance(error, openai.APITimeoutError):
        return "API request timed out. Check network access and retry later."
    if isinstance(error, openai.APIConnectionError):
        return "Could not connect to the API. Check internet access, proxy settings, and firewall access to the model provider."
    if isinstance(error, openai.InternalServerError):
        return "The model provider returned a server error. Retry later."
    if isinstance(error, FileNotFoundError):
        return "Required local file is missing. For the firewall, run python ml/train_firewall.py."
    return "Could not complete this evaluation. Check configuration or retry later."
