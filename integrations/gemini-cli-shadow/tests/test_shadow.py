"""Maintained Semgate shadow test suite (v4.1).

Covers the supported semgate.gemini-shadow.v4 schema: the install -> hook ->
report workflow, reconciliation identity validation, preflight, evaluation
status counts, and the substantive round 1-4 controls. No network or real
credentials; everything runs in pytest temp dirs with synthetic data.
"""
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from unittest import mock

import pytest

B = Path(__file__).resolve().parents[1]
SCHEMA = 'semgate.gemini-shadow.v4'


def load(name):
    s = importlib.util.spec_from_file_location(name, B / f'{name}.py')
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def clean_env(home, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SEMGATE_', 'TYPESAFE_', 'GEMINI_'))}
    env.update(HOME=str(home), USERPROFILE=str(home), SEMGATE_SHADOW_JEV='0')
    env.update(extra)
    return env


def install(home, settings_text=None):
    settings = home / '.gemini/settings.json'
    settings.parent.mkdir(parents=True, exist_ok=True)
    if settings_text is not None:
        settings.write_text(settings_text, encoding='utf-8')
    result = subprocess.run([sys.executable, str(B / 'install.py')], cwd=home,
                            env=clean_env(home), capture_output=True, text=True, timeout=15)
    return result, settings


def native_input(home):
    return {'session_id': 'A', 'hook_event_name': 'BeforeTool', 'cwd': str(home),
            'transcript_path': str(home / 'synthetic-transcript.json'),
            'tool_name': 'read_file', 'tool_input': {'file_path': 'a.py', 'start_line': 1, 'end_line': 1}}


def proposal(eid='A1', session='A'):
    return {'schema': SCHEMA, 'version': 'shadow-v4', 'record_type': 'before_tool_proposal',
            'session_id': session, 'event_id': eid, 'tool_name': 'read_file',
            'tool_input': {'file_path': 'a.py', 'start_line': 1, 'end_line': 1}}


def evaluation(eid='A1', session='A', status='disabled', decision='ask'):
    return {'schema': SCHEMA, 'version': 'shadow-v4', 'record_type': 'shadow_evaluation',
            'session_id': session, 'event_id': eid, 'candidate_decision': decision,
            'evaluation': {'status': status, 'decision': decision}}


def telemetry():
    return [{'function_name': 'read_file', 'function_args': None, 'session_id': 'A'}]


def run_preflight(home, *, key='synthetic-not-a-real-key', context_text=None):
    context = home / 'context.json'
    if context_text is None:
        context_text = json.dumps({'A': {'trusted_intent': 'Review source',
                                         'trusted_constraints': {'read_files': True}}})
    context.write_text(context_text, encoding='utf-8')
    env = clean_env(home, SEMGATE_SHADOW_JEV='1', SEMGATE_JEV_MODEL='jev-1.13.0',
                    SEMGATE_TRUSTED_CONTEXT_FILE=str(context), TYPESAFE_API_KEY=key,
                    GEMINI_SESSION_ID='A')
    result = subprocess.run([sys.executable, str(B / 'preflight.py')], env=env,
                            capture_output=True, text=True, timeout=10)
    return result, json.loads(result.stdout)


# --- Original v4 baseline tests (kept) ---
def test_static_shape_and_regular_file():
    h = load('semgate_shadow_hook')
    with __import__('tempfile').TemporaryDirectory() as d:
        Path(d, 'a.py').write_text('x\n', encoding='utf-8')
        a = {'file_path': 'a.py', 'start_line': 1, 'end_line': 1}
        assert h.static_fast_path('read_file', a, d)['match']
        Path(d, 'b.py').mkdir()
        a['file_path'] = 'b.py'
        assert not h.static_fast_path('read_file', a, d)['match']


def test_invalid_payload_is_neutral_without_event(tmp_path):
    log = tmp_path / 'log'
    r = subprocess.run([sys.executable, str(B / 'semgate_shadow_hook.py')], input='[]',
                       text=True, capture_output=True, env=clean_env(tmp_path, SEMGATE_SHADOW_LOG=str(log)))
    assert r.returncode == 0 and json.loads(r.stdout) == {} and not log.exists()


@pytest.mark.parametrize('value', ['print("https://example.test")', 'print("/*keep*/")', '\\\\" // keep', 'á /*literal*/'])
def test_comment_markers_inside_strings(value):
    i = load('install')
    text = json.dumps({'x': value})
    assert json.loads(i.strip_json_comments(text))['x'] == value


# --- R4-01: install, hook, and report agree on the versioned log ---
def test_install_hook_report_end_to_end(tmp_path):
    (tmp_path / 'a.py').write_text('x=1\n')
    result, settings = install(tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(settings.read_text())
    command = data['hooks']['BeforeTool'][-1]['hooks'][0]['command']
    legacy = settings.parent / 'semgate-shadow.jsonl'
    legacy.write_text('legacy stays unchanged\n')
    # Run the installed command through the platform shell, as Gemini does.
    argv = ['/bin/bash', '-c', command] if os.name == 'posix' else command
    run = subprocess.run(argv, cwd=tmp_path, shell=(os.name != 'posix'),
                         input=json.dumps(native_input(tmp_path)), text=True,
                         capture_output=True, env=clean_env(tmp_path, SEMGATE_SHADOW_LOG=str(tmp_path / 'inherited.jsonl')), timeout=10)
    assert not (tmp_path / 'inherited.jsonl').exists()   # an inherited override never redirects the installed hook
    assert run.returncode == 0 and json.loads(run.stdout) == {}
    assert legacy.read_text() == 'legacy stays unchanged\n'
    rows = [json.loads(line) for line in (settings.parent / 'semgate-shadow-v4.jsonl').read_text().splitlines()]
    assert len(rows) == 2 and all(row['schema'] == SCHEMA for row in rows)
    assert rows[0]['event_id'] == rows[1]['event_id']
    report = load('correlate_shadow').build_report(rows, telemetry())
    assert report['summary']['paired_event_ids'] == 1
    assert report['summary']['measurement_status'] == 'prototype_partial'


def test_readme_report_path_matches_installed_hook_path(tmp_path):
    result, settings = install(tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(settings.read_text())
    command = data['hooks']['BeforeTool'][-1]['hooks'][0]['command']
    if os.name == 'posix':
        installed_path = shlex.split(command)[0].split('=', 1)[1]
    else:
        parts = command.replace('"', '').split(' --log ')
        installed_path = parts[1].strip()
    match = re.search(r'--shadow\s+(\S+)', (B / 'README.md').read_text())
    assert match
    documented_path = match.group(1).replace('~', str(tmp_path), 1)
    assert os.path.normpath(documented_path) == os.path.normpath(installed_path), (documented_path, installed_path)


def test_direct_hook_default_writes_versioned_log_not_legacy(tmp_path):
    legacy = tmp_path / '.gemini/semgate-shadow.jsonl'
    legacy.parent.mkdir(parents=True)
    original = '{"schema":"semgate.gemini-shadow.v3","record_type":"old-fixture"}\n'
    legacy.write_text(original)
    (tmp_path / 'a.py').write_text('x=1\n')
    result = subprocess.run([sys.executable, str(B / 'semgate_shadow_hook.py')],
                            input=json.dumps(native_input(tmp_path)), text=True,
                            capture_output=True, env=clean_env(tmp_path), timeout=10)
    assert result.returncode == 0 and json.loads(result.stdout) == {}
    assert legacy.read_text() == original, 'Direct hook appended v4 records to the legacy log'
    assert (tmp_path / '.gemini/semgate-shadow-v4.jsonl').exists()


def test_custom_log_override_is_respected(tmp_path):
    target = tmp_path / 'custom.jsonl'
    (tmp_path / 'a.py').write_text('x\n')
    result = subprocess.run([sys.executable, str(B / 'semgate_shadow_hook.py')],
                            input=json.dumps(native_input(tmp_path)), text=True, capture_output=True,
                            env=clean_env(tmp_path, SEMGATE_SHADOW_LOG=str(target)), timeout=10)
    assert result.returncode == 0 and target.exists()
    assert not (tmp_path / '.gemini/semgate-shadow.jsonl').exists()
    assert not (tmp_path / '.gemini/semgate-shadow-v4.jsonl').exists()


# --- R4-02: reconciliation validates identity values, not just presence ---
@pytest.mark.parametrize('bad_id', [None, 42, [], '', '   '])
def test_invalid_event_ids_make_coverage_incomplete(bad_id):
    summary = load('correlate_shadow').build_report([proposal(bad_id), evaluation(bad_id)], telemetry())['summary']
    assert summary['paired_event_ids'] == 0, 'Invalid identity counted as a valid pair'
    assert summary['proposals_invalid_event_id'] == 1
    assert summary['evaluations_invalid_event_id'] == 1
    assert summary['proposals_missing_event_id'] == 0
    assert summary['measurement_status'] == 'incomplete_shadow_event_pairs'


def test_same_event_id_with_conflicting_sessions_is_not_paired():
    summary = load('correlate_shadow').build_report(
        [proposal('same', 'A'), evaluation('same', 'B')], telemetry())['summary']
    assert summary['paired_event_ids'] == 0
    assert summary['proposals_missing_evaluation'] == 1
    assert summary['orphan_evaluations'] == 1
    assert summary['measurement_status'] == 'incomplete_shadow_event_pairs'


def test_invalid_session_id_is_reported():
    row = proposal()
    row['session_id'] = None
    summary = load('correlate_shadow').build_report([row, evaluation()], telemetry())['summary']
    assert summary['paired_event_ids'] == 0
    assert summary['proposals_invalid_session_id'] == 1
    assert summary['measurement_status'] == 'incomplete_shadow_event_pairs'


def test_valid_local_pair_reconciliation():
    summary = load('correlate_shadow').build_report([proposal(), evaluation()], telemetry())['summary']
    assert summary['paired_event_ids'] == 1
    assert summary['measurement_status'] == 'prototype_partial'


def test_missing_and_orphan_evaluations_are_distinguished():
    summary = load('correlate_shadow').build_report(
        [proposal('A1'), proposal('A2'), evaluation('A1'), evaluation('orphan')], telemetry())['summary']
    assert summary['paired_event_ids'] == 1
    assert summary['proposals_missing_evaluation'] == 1
    assert summary['orphan_evaluations'] == 1
    assert summary['measurement_status'] == 'incomplete_shadow_event_pairs'


@pytest.mark.parametrize('kind', ['proposal', 'evaluation'])
def test_duplicate_ids_are_reported(kind):
    rows = [proposal(), evaluation(), proposal() if kind == 'proposal' else evaluation()]
    summary = load('correlate_shadow').build_report(rows, telemetry())['summary']
    assert summary[f'duplicate_{kind}_event_ids'] == 1
    assert summary['paired_event_ids'] == 0
    assert summary['measurement_status'] == 'incomplete_shadow_event_pairs'


def test_absent_event_id_field_is_reported():
    row = proposal()
    row.pop('event_id')
    summary = load('correlate_shadow').build_report([row], telemetry())['summary']
    assert summary['proposals_missing_event_id'] == 1
    assert summary['measurement_status'] == 'incomplete_shadow_event_pairs'


def test_legacy_excluded_without_content_export():
    marker = 'SYNTHETIC_LEGACY_PRIVATE_CONTENT'
    legacy = {'schema': 'semgate.gemini-shadow.v3', 'record_type': 'permission_prompt',
              'notification_type': 'ToolPermission', 'details': {'newContent': marker}}
    report = load('correlate_shadow').build_report([legacy, proposal(), evaluation()], telemetry())
    assert marker not in json.dumps(report)
    assert report['summary']['legacy_records_excluded'] == 1
    assert report['summary']['paired_event_ids'] == 1


# --- O4-01: evaluation status counts are visible and separate from capture health ---
def test_evaluation_status_counts_distinguish_statuses():
    corr = load('correlate_shadow')
    reports = [corr.build_report([proposal(), evaluation(status=status)], telemetry())
               for status in ['disabled', 'error', 'unscorable_missing_trusted_context']]
    counts = [r['summary']['shadow_evaluation_status_counts'] for r in reports]
    assert counts == [{'disabled': 1}, {'error': 1}, {'unscorable_missing_trusted_context': 1}]
    assert len({json.dumps(c, sort_keys=True) for c in counts}) == 3
    assert all(r['summary']['paired_event_ids'] == 1 for r in reports)
    mixed = corr.build_report([proposal('A1'), proposal('A2'), evaluation('A1', status='ok'),
                               evaluation('A2', status='error')], telemetry())['summary']
    assert mixed['shadow_evaluation_status_counts'] == {'ok': 1, 'error': 1}


def test_evaluation_status_counts_flag_missing_status():
    row = evaluation()
    row['evaluation'] = 'not-an-object'
    summary = load('correlate_shadow').build_report([proposal(), row], telemetry())['summary']
    assert summary['shadow_evaluation_status_counts'] == {'missing_or_invalid_status': 1}


# --- R4-03: preflight key normalization and readiness fields ---
def test_preflight_rejects_whitespace_api_key(tmp_path):
    result, status = run_preflight(tmp_path, key=' \t ')
    assert result.returncode != 0, status
    assert status['typesafe_api_key_present'] is False


def test_preflight_rejects_missing_api_key(tmp_path):
    result, status = run_preflight(tmp_path, key='')
    assert result.returncode == 2
    assert status['typesafe_api_key_present'] is False


def test_preflight_does_not_expose_secret(tmp_path):
    key = 'ONLY_A_SYNTHETIC_KEY_MARKER'
    result, status = run_preflight(tmp_path, key=key)
    assert result.returncode == 0
    assert key not in result.stdout + result.stderr
    assert status['typesafe_api_key_present'] is True


@pytest.mark.parametrize('context_text', ['not JSON', '{}', '{"A":{"trusted_intent":42,"trusted_constraints":{}}}'])
def test_preflight_readiness_fields_report_unusable_context(tmp_path, context_text):
    # Exit 0 remains a readability gate; the readiness fields carry the detail.
    result, status = run_preflight(tmp_path, context_text=context_text)
    assert result.returncode == 0
    assert status['trusted_context_file_readable'] is True
    assert status['trusted_context_session_usable'] is False
    assert 'typesafe_sdk_available' in status and 'effective_session_id_configured' in status


def test_preflight_readiness_fields_confirm_usable_context(tmp_path):
    result, status = run_preflight(tmp_path)
    assert result.returncode == 0
    assert status['trusted_context_json_valid'] is True
    assert status['trusted_context_session_usable'] is True


# --- Round 1-3 substantive controls (promoted, supported schema) ---
def test_atomic_private_report_no_final_reopen(tmp_path, monkeypatch):
    corr = load('correlate_shadow')
    target = tmp_path / 'report.json'
    target.write_text('{"old":true}')
    original_open = Path.open
    def forbid_final_write(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get('mode', 'r')
        if path == target and 'w' in mode:
            raise AssertionError('Final report must not be reopened in write mode')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', forbid_final_write)
    corr.write_private(target, '{"new":true}')
    assert target.read_text() == '{"new":true}'
    if os.name == 'posix':   # Windows has no POSIX mode bits; privacy there comes from the user-profile ACL
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_failed_replace_keeps_old_report_and_cleans_temp(tmp_path, monkeypatch):
    corr = load('correlate_shadow')
    target = tmp_path / 'report.json'
    target.write_text('{"old":true}')
    def fail(*args):
        raise OSError('synthetic replacement failure')
    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OSError):
        corr.write_private(target, '{"new":true}')
    assert target.read_text() == '{"old":true}'
    assert [p.name for p in tmp_path.iterdir()] == ['report.json']


def test_report_temp_private_before_replace(tmp_path, monkeypatch):
    corr = load('correlate_shadow')
    dest = tmp_path / 'report.json'
    observed = []
    replace = os.replace
    def inspect(src, dst):
        if Path(dst) == dest:
            observed.append((stat.S_IMODE(Path(src).stat().st_mode), Path(src).read_text()))
        return replace(src, dst)
    monkeypatch.setattr(os, 'replace', inspect)
    old_umask = os.umask(0o022)
    try:
        corr.write_private(dest, '{"ok":true}')
    finally:
        os.umask(old_umask)
    assert [text for _, text in observed] == ['{"ok":true}']
    if os.name == 'posix':   # Windows has no POSIX mode bits; privacy there comes from the user-profile ACL
        assert observed == [(0o600, '{"ok":true}')]
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_append_requests_fsync(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(os, 'fsync', lambda fd: seen.append(fd))
    load('semgate_shadow_hook').append(tmp_path / 'log.jsonl', {'synthetic': True})
    assert len(seen) == 1


@pytest.mark.parametrize('value', ['a' * 4096, 'ñ' * 2048])
def test_long_notification_strings_become_hashes(value):
    result = load('semgate_shadow_hook').bounded_metadata(value)
    assert result['truncated'] is True
    assert result['utf8_bytes'] == len(value.encode('utf-8'))
    assert len(result['sha256']) == 64


def test_small_notification_metadata_unchanged():
    assert load('semgate_shadow_hook').bounded_metadata('ñ' * 1024) == 'ñ' * 1024


def test_pretty_telemetry_is_parsed(tmp_path):
    path = tmp_path / 'telemetry.log'
    event = {'attributes': {'event.name': 'gemini_cli.tool_call', 'function_name': 'read_file',
                            'session.id': 'A'}, 'body': 'Tool call summary'}
    path.write_text(json.dumps(event, indent=2) + '\n' + json.dumps(event, indent=2))
    assert len(load('correlate_shadow').telemetry_events(path)) == 2


def test_disabled_jev_never_imports_sdk(tmp_path):
    hook = load('semgate_shadow_hook')
    with mock.patch.dict(os.environ, clean_env(tmp_path), clear=True):
        result = hook.jev_shadow({'session_id': 'A'}, 'run_shell_command',
                                 {'command': 'echo synthetic'}, str(tmp_path), {'match': False})
    assert result == {'status': 'disabled', 'decision': 'ask'}


def test_proposal_is_visible_before_evaluation_crashes(tmp_path, monkeypatch):
    hook = load('semgate_shadow_hook')
    log = tmp_path / 'shadow.jsonl'
    seen = []
    def crash(*args):
        seen.extend(json.loads(line) for line in log.read_text().splitlines())
        raise RuntimeError('evaluation crash')
    inp = {'session_id': 'A', 'hook_event_name': 'BeforeTool', 'cwd': str(tmp_path),
           'tool_name': 'run_shell_command', 'tool_input': {'command': 'echo synthetic'}}
    monkeypatch.setattr(hook, 'jev_shadow', crash)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(inp)))
    monkeypatch.setenv('SEMGATE_SHADOW_LOG', str(log))
    stdout = io.StringIO()
    with mock.patch('sys.stdout', stdout), mock.patch('sys.stderr', io.StringIO()):
        assert hook.main() == 0
    assert json.loads(stdout.getvalue()) == {}
    assert [r['record_type'] for r in seen] == ['before_tool_proposal']


def test_valid_proposal_and_evaluation_share_event_id(tmp_path, monkeypatch):
    hook = load('semgate_shadow_hook')
    log = tmp_path / 'shadow.jsonl'
    (tmp_path / 'a.py').write_text('x')
    inp = {**proposal(), 'hook_event_name': 'BeforeTool', 'cwd': str(tmp_path)}
    monkeypatch.setenv('SEMGATE_SHADOW_LOG', str(log))
    monkeypatch.setenv('SEMGATE_SHADOW_JEV', '0')
    monkeypatch.delenv('SEMGATE_TRUSTED_CONTEXT_FILE', raising=False)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(inp)))
    with mock.patch('sys.stdout', io.StringIO()):
        hook.main()
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r['record_type'] for r in rows] == ['before_tool_proposal', 'shadow_evaluation']
    assert rows[0]['event_id'] == rows[1]['event_id']


def test_edit_notification_omits_body_content(tmp_path, monkeypatch):
    hook = load('semgate_shadow_hook')
    log = tmp_path / 'shadow.jsonl'
    sentinel = 'SYNTHETIC_PRIVATE_FILE'
    inp = {'session_id': 'A', 'hook_event_name': 'Notification', 'notification_type': 'ToolPermission',
           'message': sentinel, 'details': {'type': 'edit', 'title': 'Edit', 'fileDiff': sentinel,
                                            'originalContent': sentinel, 'newContent': sentinel}}
    monkeypatch.setenv('SEMGATE_SHADOW_LOG', str(log))
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(inp)))
    with mock.patch('sys.stdout', io.StringIO()):
        hook.main()
    assert sentinel not in log.read_text()
    assert json.loads(log.read_text())['omitted_content_sha256']


@pytest.mark.parametrize('text', [
    '{"telemetry":{"enabled":tru/**/e}}',
    '{"mcpServers":{"demo":{"command":"python","timeout":1/**/0}}}',
])
def test_installer_rejects_comment_spliced_tokens(tmp_path, text):
    result, path = install(tmp_path, text)
    assert result.returncode != 0, 'Installer accepted token-spliced JSON rejected by Gemini'
    assert path.read_text() == text
    assert not list((path.parent / 'hooks').glob('semgate_shadow_hook-*.py'))


@pytest.mark.parametrize('constant', ['NaN', 'Infinity', '-Infinity'])
def test_installer_rejects_non_json_numeric_constants(tmp_path, constant):
    text = '{"mcpServers":{"demo":{"command":"python","timeout":' + constant + '}}}'
    result, path = install(tmp_path, text)
    assert result.returncode != 0, f'Installer preserved invalid ECMAScript JSON constant {constant}'
    assert path.read_text() == text


@pytest.mark.parametrize('value', ['print("https://example.test")', 'print("/*keep*/")', '\\\\" // literal', 'ñ /* literal */'])
def test_valid_escaped_settings_are_preserved(tmp_path, value):
    data = {'mcpServers': {'demo': {'command': 'python', 'args': ['-c', value]}}}
    text = '/* actual comment */\n' + json.dumps(data) + '\n// ending comment'
    result, path = install(tmp_path, text)
    assert result.returncode == 0, result.stderr
    assert json.loads(path.read_text())['mcpServers'] == data['mcpServers']


def test_settings_commit_failure_preserves_active_install(tmp_path, monkeypatch):
    result, settings = install(tmp_path, '{}')
    assert result.returncode == 0
    original_settings = settings.read_bytes()
    original_files = {p.name: p.read_bytes() for p in (settings.parent / 'hooks').glob('*.py')}
    mod = load('install')
    real = os.replace
    injected = []
    def selective_failure(src, dst):
        if Path(dst) == settings:
            injected.append(True)
            raise OSError('settings commit only')
        return real(src, dst)
    # Path.home() reads HOME on POSIX but USERPROFILE on Windows. Set both, and
    # refuse to go on unless home really is the temp dir: this test calls the
    # installer in-process, and a wrong home would edit the real ~/.gemini.
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('USERPROFILE', str(tmp_path))
    assert Path.home().resolve() == tmp_path.resolve(), 'refusing to run the installer against the real home directory'
    monkeypatch.setattr(os, 'replace', selective_failure)
    with pytest.raises(OSError, match='settings commit only'):
        mod.main()
    assert injected == [True]
    assert settings.read_bytes() == original_settings
    assert {p.name: p.read_bytes() for p in (settings.parent / 'hooks').glob('*.py')} == original_files
