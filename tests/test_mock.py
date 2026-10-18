"""Free deterministic pipeline tests; SDK construction is forbidden in mock mode."""
import pytest
from streamlit.testing.v1 import AppTest
from core import llm, firewall
from core.attacks import load_attacks, load_benign
from core.config import ROOT
from core.presets import load_presets, load_test_presets
from core.scanner import run_scan
from scripts.run_scenarios import check_expectations, main

# Capture the real dispatcher before the suite's API-isolation fixture replaces it.
REAL_CHAT = llm.chat


@pytest.fixture
def free_mock(monkeypatch):
    monkeypatch.setenv('TRIPWIRE_MOCK', '1')
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.setattr(llm, 'chat', REAL_CHAT)
    def forbidden(*args, **kwargs):
        raise AssertionError('Mock mode constructed a live API client')
    monkeypatch.setattr(llm.openai, 'OpenAI', forbidden)


def baseline(firewall_enabled=False):
    bot = load_presets()[0]
    return run_scan(bot['system_prompt'], bot['rules'], bot['secret_note'],
                    load_attacks(), load_benign(bot['id']), firewall_enabled, .5, 'baseline')


def test_full_mock_scan_outcomes_and_determinism(free_mock):
    first, second = baseline(), baseline()
    assert {r['verdict'] for r in first.attack_rows} == {'resisted', 'partial', 'compromised', 'not_tested'}
    assert any(r['verdict']=='compromised' and r['source']=='canary' and r['canary_leaked'] for r in first.attack_rows)
    assert any(r['verdict']=='compromised' and r['source']=='judge' and not r['canary_leaked'] for r in first.attack_rows)
    assert any(r['verdict']=='not_tested' and 'invalid JSON' in r['reason'] for r in first.attack_rows)
    assert {r['answered'] for r in first.benign_rows} == {True, False}
    assert first.api_calls == second.api_calls == 0
    # Canary values and timestamps remain fresh; outcome ordering is deterministic.
    keys = ('id', 'verdict', 'source', 'canary_leaked', 'secret_leaked', 'reason')
    assert [[r[k] for k in keys] for r in first.attack_rows] == [[r[k] for k in keys] for r in second.attack_rows]
    assert first.benign_rows == second.benign_rows


def test_full_mock_scan_including_local_blocks(free_mock, monkeypatch):
    # A fixed local classifier makes this test independent of a trained artifact.
    blocked = next(r['prompt'] for r in load_attacks() if r['id']=='RJ-05')
    normal = load_benign('kopi_corner')[0]['prompt']
    monkeypatch.setattr(firewall, 'load_model', lambda: object())
    monkeypatch.setattr(firewall, 'score', lambda text: 1.0 if text in {blocked, normal} else 0.0)
    result = baseline(firewall_enabled=True)
    assert {r['verdict'] for r in result.attack_rows} == {'resisted', 'partial', 'compromised', 'not_tested', 'blocked'}
    assert any(r['source']=='firewall' for r in result.attack_rows)
    assert any(r['blocked'] and r['answered'] is False for r in result.benign_rows)
    assert result.api_calls == 0


def test_all_scenarios_pass_without_api(free_mock, capsys):
    assert main(['--mock']) == 0
    output = capsys.readouterr().out
    assert sum(line.rstrip().endswith('| PASS') for line in output.splitlines()) == 6
    assert 'API attempts: 0' in output
    assert 'LIVE MODE' not in output


def test_failed_expectation_is_reported(free_mock):
    result = baseline()
    _, failures = check_expectations(result, {'canary_leaks_min': 999})
    assert failures and 'canary_leaks' in failures[0]


def test_mock_can_be_enabled_by_secrets(monkeypatch):
    monkeypatch.delenv('TRIPWIRE_MOCK', raising=False)
    monkeypatch.setattr(llm.config, 'read_setting', lambda name, default='': '1' if name=='TRIPWIRE_MOCK' else default)
    assert llm.mock_mode_enabled()


def test_mock_flag_overrides_disabled_secret(monkeypatch):
    monkeypatch.setenv('TRIPWIRE_MOCK', '1')
    monkeypatch.setattr(llm.config, 'read_setting', lambda name, default='': '0')
    assert llm.mock_mode_enabled()


def test_mock_badge_and_test_bot_selector(free_mock):
    app = AppTest.from_file(str(ROOT/'app.py')).run(timeout=30)
    assert not app.exception
    assert any('MOCK MODE' in item.value for item in app.markdown)
    scan_page = str(next((ROOT/'pages').glob('1_*')).relative_to(ROOT)).replace('\\','/')
    app.switch_page(scan_page).run(timeout=30)
    next(w for w in app.toggle if w.label=='Show test bots').set_value(True).run(timeout=30)
    assert len(app.selectbox[0].options) == len(load_presets()) + 6
    preset = next(row for row in load_test_presets() if row['id']=='A1')
    app.selectbox[0].select(preset).run(timeout=30)
    assert not app.exception
    assert any(box.value == preset['system_prompt'] for box in app.text_area if box.label == 'Sandbox system prompt (editable)')
    next(w for w in app.button if w.label=='Run baseline scan').click().run(timeout=30)
    assert not app.exception
    assert app.session_state['scan_context']['secret'] == 'STAFF50'
    assert app.session_state['scan_context']['rules'] == preset['rules']
    assert app.session_state['baseline'].api_calls == 0
    assert any('Security score' in item.value and '0%' in item.value for item in app.markdown)
    assert all(row['source']=='canary' for row in app.session_state['baseline'].attack_rows)


def test_live_runner_requires_key_without_making_calls(monkeypatch, capsys):
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    assert main([]) == 2
    assert 'No API key configured' in capsys.readouterr().out


def test_runner_returns_failure_for_unmet_expectations(free_mock, monkeypatch, capsys):
    from core import presets
    bot = dict(load_test_presets()[0])
    bot['mock_expected'] = {'description': 'Impossible leak count', 'canary_leaks_min': 999}
    monkeypatch.setattr(presets, 'load_test_presets', lambda: [bot])
    assert main(['--mock']) == 1
    assert 'FAIL' in capsys.readouterr().out


def test_mock_hardening_and_unseen_variants_are_free(free_mock):
    from core.hardener import harden
    from core.variants import generate_variants
    result = baseline()
    failed = [row for row in result.attack_rows if row['verdict'] in {'partial', 'compromised'}]
    draft = harden(result.system_prompt, failed)
    variants = generate_variants(failed[:1])
    assert len(variants) == 2 and variants[0]['prompt'] != variants[1]['prompt']
    bot = load_presets()[0]
    retest = run_scan(draft['hardened_prompt'], bot['rules'], bot['secret_note'], variants, load_benign(bot['id']), False, .5, 'unseen_attacks')
    assert all(row['verdict']=='resisted' for row in retest.attack_rows)
    assert all(row['answered'] is True for row in retest.benign_rows)
    assert retest.api_calls == 0


def test_non_mock_dispatch_keeps_live_client_arguments(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv('OPENAI_API_KEY', 'test-placeholder')
    captured = {}
    def create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='test response'))])
    class FakeClient:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    monkeypatch.setattr(llm.openai, 'OpenAI', FakeClient)
    messages = [{'role': 'user', 'content': 'fixture'}]
    assert REAL_CHAT(messages, model='fixture-model', json_mode=True, max_tokens=75) == 'test response'
    assert captured == {'model': 'fixture-model', 'messages': messages, 'temperature': 0.0,
                        'max_tokens': 75, 'response_format': {'type': 'json_object'}}
