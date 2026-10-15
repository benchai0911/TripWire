import httpx
import openai
import pytest
from core.errors import safe_error_message


@pytest.mark.parametrize("kind,status,body,expected", [
    (openai.NotFoundError, 404, {}, "models available from your provider"),
    (openai.AuthenticationError, 401, {}, "key is valid"),
    (openai.RateLimitError, 429, {"code": "insufficient_quota"}, "credits exhausted"),
    (openai.RateLimitError, 429, {"code": "rate_limit_exceeded"}, "rate limit"),
    (openai.BadRequestError, 400, {}, "supports Chat Completions"),
])
def test_actionable_safe_errors(kind, status, body, expected):
    response = httpx.Response(status, request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"))
    error = kind("private-secret-in-raw-error", response=response, body=body)
    message = safe_error_message(error)
    assert expected in message
    assert "private-secret" not in message


def test_unknown_error_does_not_expose_content():
    assert "private-secret" not in safe_error_message(RuntimeError("private-secret"))
