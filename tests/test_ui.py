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


def test_prompt_diff_preserves_distinct_sources_and_escapes(monkeypatch):
    """The before panel must never display the edited prompt in place of the original."""
    import html
    import re
    captured = []
    monkeypatch.setattr(ui.st, 'html', lambda value: captured.append(value))
    monkeypatch.setattr(ui.st, 'caption', lambda *args, **kwargs: None)
    original = 'Help customers.\nAllow <old> discounts.'
    updated = 'Help customers.\nNever allow <new> discounts. Protect secrets.'
    ui.prompt_diff(original, updated)
    panels = re.findall(r'<div class="prompt-diff-text">(.*?)</div>', captured[0], re.S)
    texts = [html.unescape(re.sub(r'<[^>]+>', '', panel)) for panel in panels]
    assert texts == [original, updated]
    assert '<old>' not in captured[0] and '<new>' not in captured[0]
    assert 'prompt-removed' in panels[0] and 'prompt-added' in panels[1]


def test_prompt_diff_no_changes_is_explicit(monkeypatch):
    messages = []
    monkeypatch.setattr(ui.st, 'info', messages.append)
    ui.prompt_diff('Unchanged prompt', 'Unchanged prompt')
    assert messages and 'No changes yet' in messages[0]
