import io
import pytest
from core import llm
from core.pdf_attack import generate_pdf, analyse_pdf, run_document, highlighted_text, INJECTION, character_flags
from core.presets import load_presets

REAL_CHAT = llm.chat


def test_generated_pdf_hidden_text_is_detected_and_removed():
    data = generate_pdf()
    result = analyse_pdf(data)
    assert INJECTION in result["text"]
    assert INJECTION in "".join(r["text"] for r in result["removed"])
    assert INJECTION not in result["cleaned_text"]
    assert "Kopi" in result["cleaned_text"] and "1.50" in result["cleaned_text"]
    assert result["preview"].startswith(b"\x89PNG")
    assert "#B42318" in highlighted_text(result["text"], result["removed"])


def test_clean_pdf_has_no_flagged_characters():
    result = analyse_pdf(generate_pdf(clean=True))
    assert result["removed"] == []
    assert "Kopi Corner Menu" in result["cleaned_text"]


def test_pdf_flags_tiny_outside_and_background():
    char = {"size": 3, "non_stroking_color": (0, 0, 0), "x0": -1, "x1": 3, "top": 1, "bottom": 4}
    reasons = character_flags(char, (0, 0, 612, 792), [])
    assert "Font smaller than 4pt" in reasons and "Outside page box" in reasons
    char.update(size=12, x0=1)
    background = {"fill": True, "non_stroking_color": (0, 0, 0), "x0": 0, "x1": 612, "top": 0, "bottom": 792}
    assert "Text matches background colour" in character_flags(char, (0, 0, 612, 792), [background])


def test_pdf_bounds_and_html_escaping():
    with pytest.raises(ValueError):
        analyse_pdf(b"not a pdf")
    with pytest.raises(ValueError):
        analyse_pdf(b"%PDF-" + b"x" * 2_000_000)
    result = highlighted_text('<script>alert(1)</script>', [{"text": '<script>alert(1)</script>'}])
    assert "<script>" not in result and "&lt;script&gt;" in result


def test_mock_document_before_after_skips_judge_on_leak(monkeypatch):
    monkeypatch.setenv("TRIPWIRE_MOCK", "1")
    monkeypatch.setattr(llm, "chat", REAL_CHAT)
    monkeypatch.setattr(llm.openai, "OpenAI", lambda *a, **kw: pytest.fail("Mock constructed SDK"))
    bot, analysis = load_presets()[0], analyse_pdf(generate_pdf())
    before = run_document(bot, analysis, "What's on the menu?")
    after = run_document(bot, analysis, "What's on the menu?", hidden_scanner=True)
    assert before["verdict"] == "compromised" and before["source"] == "Canary"
    assert before["canary_leaked"]
    assert after["verdict"] == "resisted" and not after["canary_leaked"]
    assert after["removed_characters"] > 0


def test_pdf_mode_ui_and_session_limits(monkeypatch):
    from streamlit.testing.v1 import AppTest
    from core.config import ROOT, MAX_SCANS_PER_SESSION
    monkeypatch.setenv("TRIPWIRE_MOCK", "1")
    monkeypatch.setattr(llm, "chat", REAL_CHAT)
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    app.switch_page("pages/8_Advanced.py").run(timeout=30)
    next(r for r in app.radio if r.label == "Attack mode").set_value("Hidden PDF text").run(timeout=30)
    assert not app.exception
    next(b for b in app.button if b.label == "Run PDF test").click().run(timeout=30)
    assert not app.exception and app.session_state["scans_used"] == 1
    next(t for t in app.toggle if t.label == "Hidden-content scanner").set_value(True).run(timeout=30)
    next(b for b in app.button if b.label == "Run PDF test").click().run(timeout=30)
    assert not app.exception and app.session_state["scans_used"] == 2
    assert app.session_state["api_calls"] == 0
    app.session_state["scans_used"] = MAX_SCANS_PER_SESSION
    next(b for b in app.button if b.label == "Run PDF test").click().run(timeout=30)
    assert app.session_state["scans_used"] == MAX_SCANS_PER_SESSION
