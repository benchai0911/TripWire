"""Run small scenario scans. --mock never contacts an external API."""
import argparse
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def sample_attacks():
    from core.attacks import load_attacks
    selected = {}
    for attack in load_attacks():
        selected.setdefault(attack['category'], attack)
    return list(selected.values())


def check_expectations(result, expected):
    """Compare scenario metadata with existing scoring and recorded verdicts."""
    from core.scoring import summarize
    metrics = summarize(result)
    counts = Counter(row['verdict'] for row in result.attack_rows)
    actual = dict(score=metrics['security_score'], canary_leaks=sum(row['canary_leaked'] for row in result.attack_rows),
                  over_refusal=metrics['over_refusal_rate'], attack_errors=metrics['attack_errors'], not_tested=metrics['not_tested'], benign_errors=metrics['benign_errors'],
                  scored_attacks=metrics['scored_attacks'], partial=counts['partial'], resisted=counts['resisted'],
                  judge_compromised=sum(row['verdict']=='compromised' and row['source']=='judge' for row in result.attack_rows),
                  canary_compromised=sum(row['verdict']=='compromised' and row['source']=='canary' for row in result.attack_rows),
                  benign_answered=sum(row.get('answered') is True for row in result.benign_rows),
                  benign_refused=sum(row.get('answered') is False for row in result.benign_rows))
    failures = []
    if 'grades' in expected and metrics['grade'] not in expected['grades']:
        failures.append(f"grade {metrics['grade']} not in {expected['grades']}")
    for key, value in expected.items():
        if key.endswith(('_min', '_max')):
            metric, bound = key.rsplit('_', 1)
            if metric not in actual:
                raise ValueError(f'Unknown expected metric: {metric}')
            observed = actual[metric]
            if observed is None or (bound == 'min' and observed < value) or (bound == 'max' and observed > value):
                failures.append(f'{metric}={observed}; expected {bound} {value}')
    return metrics, failures


def run_scenarios():
    from core import llm
    from core.attacks import load_benign
    from core.errors import safe_error_message
    from core.presets import load_test_presets
    from core.scanner import run_scan
    from core.report import format_rate
    from core.config import get_settings
    mock = llm.mock_mode_enabled()
    if not mock and not get_settings().api_key:
        print('No API key configured. Use --mock for free testing, or configure OPENAI_API_KEY for real calls.')
        return 2
    attacks = sample_attacks()
    print('MOCK MODE - scripted responses; zero API calls.' if mock else 'LIVE MODE - sends the bundled fictional scenarios to the configured model API.')
    print(f'{len(attacks)} attacks (one per category) and 5 normal questions per scenario. Firewall off. No database writes.\n')
    headings = ['Scenario', 'Expected outcome', 'Actual score', 'Grade', 'Canary leaks', 'Over-refusal', 'PASS/FAIL']
    rows, notes = [], []
    api_attempts = 0
    failed = False
    for preset in load_test_presets():
        expected = preset.get('mock_expected', preset['expected']) if mock else preset['expected']
        try:
            benign = load_benign(preset['benign_preset_id'])[:5]
            result = run_scan(preset['system_prompt'], preset['rules'], preset['secret_note'], attacks, benign, False, .5, 'baseline')
            api_attempts += result.api_calls
            metrics, failures = check_expectations(result, expected)
            leak_count = sum(row['canary_leaked'] for row in result.attack_rows)
            rows.append([preset['id'], expected['description'], format_rate(metrics['security_score']), metrics['grade'], str(leak_count), format_rate(metrics['over_refusal_rate']), 'FAIL' if failures else 'PASS'])
            if failures:
                notes.append(preset['id'] + ': ' + '; '.join(failures))
                failed = True
        except Exception as error:
            rows.append([preset['id'], expected['description'], 'N/A', 'N/A', 'N/A', 'N/A', 'FAIL'])
            notes.append(preset['id'] + ': ' + safe_error_message(error))
            failed = True
    widths = [max(len(str(row[i])) for row in [headings, *rows]) for i in range(len(headings))]
    for index, row in enumerate([headings, *rows]):
        print(' | '.join(str(value).ljust(width) for value, width in zip(row, widths)))
        if index == 0:
            print('-+-'.join('-' * width for width in widths))
    print(f'\nAPI attempts: {api_attempts}')
    for note in notes:
        print(note)
    if mock:
        print('Mock PASS verifies pipeline wiring and scripted expectations, not real model security.')
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mock', action='store_true', help='Force deterministic scripted responses; no API key or network required.')
    args = parser.parse_args(argv)
    if args.mock:
        os.environ['TRIPWIRE_MOCK'] = '1'
    return run_scenarios()


if __name__ == '__main__':
    raise SystemExit(main())
