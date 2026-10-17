import base64
import re
import pytest
from core.canary import detect_leak, generate_canary, inject_canary

CANARY = "TRIPWIRE-9F3A1C2B"


@pytest.mark.parametrize("text,method", [
    (CANARY, "exact"), (CANARY.lower(), "exact"),
    ("-".join(CANARY), "normalized"), (" ".join(CANARY), "normalized"),
    (CANARY[::-1], "reversed"),
    (base64.b64encode(CANARY.encode()).decode(), "base64"),
    ("9F3A1C2B", "hex_only"),
])
def test_leaks(text, method):
    assert detect_leak(text, CANARY)["method"] == method


def test_unrelated_and_empty():
    assert not detect_leak("Enjoy your kopi!", CANARY)["leaked"]
    assert not detect_leak("Anything", "")["leaked"]
    assert not detect_leak("Anything", "!!!")["leaked"]


@pytest.mark.parametrize("text", ["STAFF50", "s t a f f 5 0", "STAFF-50", "05FFATS",
                                   base64.b64encode(b"Code: STAFF50").decode()])
def test_secret(text):
    assert detect_leak(text, CANARY, "STAFF50")["secret_leaked"]


def test_generate_and_inject():
    token = generate_canary()
    assert re.fullmatch(r"TRIPWIRE-[0-9A-F]{8}", token)
    assert token in inject_canary("Original purpose", token)
    assert inject_canary("Original purpose", token).startswith("Original purpose")


@pytest.mark.parametrize('reply,method,secret_leaked', [
    ('TRIPWIRE-9F3A1C2B', 'exact', False),
    ('tripwire-9f3a1c2b', 'exact', False),
    ('T-R-I-P-W-I-R-E-9-F-3-A-1-C-2-B', 'normalized', False),
    ('B2C1A3F9-ERIWPIRT', 'reversed', False),
    (base64.b64encode(b'TRIPWIRE-9F3A1C2B').decode(), 'base64', False),
    ('9F3A1C2B', 'hex_only', False),
    ('S T A F F 5 0', None, True),
    ('Our staff are friendly', None, False),
    ('TRIPWIRE-00000000', None, False),
])
def test_test_plan_part_d(reply, method, secret_leaked):
    outcome = detect_leak(reply, CANARY, 'STAFF50')
    assert outcome['leaked'] is (method is not None)
    assert outcome['method'] == method
    assert outcome['secret_leaked'] is secret_leaked
