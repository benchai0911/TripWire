"""The redesign keeps configuration separate from session-backed evidence."""
import json
from streamlit.testing.v1 import AppTest
from core import llm
from core.config import ROOT
from core.ui import SCAN_PAGE, RESULTS_PAGE


def test_empty_results_returns_to_scan(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'test-placeholder')
    app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=30)
    app.switch_page(RESULTS_PAGE).run(timeout=30)
    assert not app.exception
    assert any('No scan yet' in item.value for item in app.markdown)
    next(b for b in app.button if b.label == "Start a scan").click().run(timeout=30)
    assert not app.exception
    assert any(widget.label == 'Bot source' for widget in app.radio)


def test_baseline_redirects_to_results_and_preserves_evidence(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'test-placeholder')
    monkeypatch.delenv('SUPABASE_URL', raising=False)
    def fake(messages, json_mode=False, **kwargs):
        if not json_mode:
            return 'We open at 7am.'
        if 'legitimate user question' in messages[0]['content']:
            return json.dumps({'answered': True, 'reason': 'Answered the question.'})
        return json.dumps({'verdict': 'resisted', 'reason': 'Stayed within the rules.', 'confidence': 0.9, 'violated_rule': None})
    monkeypatch.setattr(llm, 'chat', fake)
    app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=30)
    app.switch_page(SCAN_PAGE).run(timeout=30)
    next(button for button in app.button if button.label == 'Run baseline scan').click().run(timeout=30)
    assert not app.exception
    assert not any(widget.label == 'Bot source' for widget in app.radio)
    assert any('SCAN RESULTS' in item.value for item in app.markdown)
    assert len(app.session_state['baseline'].attack_rows) == 12
    app.switch_page(SCAN_PAGE).run(timeout=30)
    assert not app.dataframe
    assert len(app.session_state['baseline'].attack_rows) == 12


def test_empty_pages_keep_shared_footer(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY', 'test-placeholder')
    monkeypatch.delenv('SUPABASE_URL', raising=False)
    monkeypatch.delenv('SUPABASE_SERVICE_KEY', raising=False)
    app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=30)
    for page in [RESULTS_PAGE, str(next((ROOT / 'pages').glob('2_*')).relative_to(ROOT)).replace('\\', '/'), str(next((ROOT / 'pages').glob('4_*')).relative_to(ROOT)).replace('\\', '/')]:
        app.switch_page(page).run(timeout=30)
        assert not app.exception
        footer_text = '\n'.join(item.value for item in app.markdown)
        assert 'AI Lodge Hackathon 2026' in footer_text
        assert 'Sandbox bots and companies are fictional.' in footer_text
        assert 'GitHub' in footer_text and 'Devpost' in footer_text and 'LinkedIn post' in footer_text
