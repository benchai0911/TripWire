"""Security checks for HTML presentation helpers."""
from core import ui


def test_verdict_badge_escapes_unknown_label():
    assert '<script>' not in ui.verdict_badge('<script>')
    assert '&lt;script&gt;' in ui.verdict_badge('<script>')


def test_transcript_escapes_and_highlights(monkeypatch):
    captured = []
    monkeypatch.setattr(ui.st, 'markdown', lambda text, **kwargs: captured.append(text))
    ui.transcript('<script>alert(1)</script>', '<img src=x> SECRET&code TOKEN', 'TOKEN', 'SECRET&code')
    rendered = captured[0]
    assert '<script>' not in rendered and '<img src=x>' not in rendered
    assert '&lt;script&gt;' in rendered and '&lt;img src=x&gt;' in rendered
    assert '<mark>SECRET&amp;code</mark>' in rendered
    assert '<mark>TOKEN</mark>' in rendered
