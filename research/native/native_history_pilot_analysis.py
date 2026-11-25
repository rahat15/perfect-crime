"""Read-only interpretation of the three-stage native history pilots."""
import base64
import json
from pathlib import Path
import re

from research.native import native_history_evidence as evidence
from research.native import run_native_functionality as original
from research.native import run_native_functionality_comparison as matched
from research.tools import run_comparison as peer_runner
from host_lab.anonymization_loop import grade_trace

require = evidence.require


def transport_window(rows, stage):
    """Use native supervisor monotonic clocks and retain wall timestamps separately."""
    starts = [v for v in rows if v.get('kind') == 'started']
    exits = [v for v in rows if v.get('kind') == 'exited']
    require(len(starts) == len(exits) == 1, 'Native transport lifecycle is incomplete.')
    start, end = starts[0], exits[0]
    require(rows[0] == start and rows[-1] == end
        and all(v.get('kind') in {'started', 'stdout', 'stderr', 'exited'} for v in rows)
        and start['pid'] == end['pid'] == stage['pid']
        and start['supervisor_pid'] == stage['supervisor_pid']
        and end['returncode'] == stage['exit_code'] and end['signal'] == stage['signal']
        and end['output_drained'] is True, 'Native transport identity or completion differs.')
    monotonic_projection(rows)
    decoded = {name: b''.join(base64.b64decode(v['data_b64'], validate=True)
               for v in rows if v['kind'] == name) for name in ('stdout', 'stderr')}
    return ({'name': stage['name'], 'started_ns': start['monotonic_ns'],
        'finished_ns': end['monotonic_ns'], 'pid': stage['pid'], 'exit_code': stage['exit_code'],
        'raw_wall_started_ns': start['observed_ns'], 'raw_wall_finished_ns': end['observed_ns'],
        'clock_source': 'CLOCK_MONOTONIC from the native process supervisor and independent filesystem observer',
        'host_prelaunch_started_ns': stage['started_ns']}, decoded)


def monotonic_projection(rows):
    require(bool(rows) and all(type(v.get('monotonic_ns')) is int for v in rows)
        and all(b['monotonic_ns'] >= a['monotonic_ns'] for a, b in zip(rows, rows[1:])),
        'Monotonic observation fields are missing or unordered.')
    return [dict(row, raw_wall_observed_ns=row.get('observed_ns'), observed_ns=row['monotonic_ns']) for row in rows]


def shared_failures(events, *, exception_text='', stderr=''):
    # Reuse the peer patterns only on native errors and native diagnostic output.
    # Agent prose and command output can mention quotas without an infrastructure failure.
    texts = [exception_text, stderr]
    for event in events:
        item = event.get('item') if isinstance(event.get('item'), dict) else {}
        if event.get('type') in {'error', 'turn.failed'} or item.get('type') == 'error':
            texts.append(json.dumps([event.get('message'), event.get('error'), item.get('message')]))
    text = '\n'.join(texts)
    return [flag for flag, pattern in peer_runner.SHARED_RESOURCE_PATTERNS if pattern.search(text)]


def session_check(events, expected, *, required=False):
    ids = [v.get('thread_id') for v in events if v.get('type') == 'thread.started']
    require(all(v == expected for v in ids), 'An invocation reported a different session. No replacement is allowed.')
    require(len(ids) <= 1 and (not required or ids == [expected]), 'Native session lifecycle differs.')
    return bool(ids)


def invocation_measurement(stage, events, stderr, capture, *, corroborated_unlink=False):
    """Separate recorded history-access failures from unexplained native failures."""
    completed = stage['exit_code'] == 0 and original.invocation_succeeded('codex', events)
    if stage.get('signal') is not None:
        return {'completed': False, 'classification': 'unexpected_native_signal', 'may_continue': False}
    if completed:
        return {'completed': True, 'classification': 'turn_completed', 'may_continue': True}
    error_texts = [stderr]
    for event in events:
        item = event.get('item') if isinstance(event.get('item'), dict) else {}
        if event.get('type') in {'error', 'turn.failed'} or item.get('type') == 'error':
            error_texts.append(json.dumps([event.get('message'), event.get('error'), item.get('message')]))
    text = '\n'.join(error_texts)
    mentions_history = bool(re.search(r'(?i)session|rollout|thread|jsonl|sqlite|database', text))
    mentions_failure = bool(re.search(r'(?i)not found|no such|missing|failed|cannot|unable|denied|corrupt|invalid|does not exist', text))
    unavailable = (capture['trace_inventory'] is not None and not capture['trace_inventory']['paths']) or any(
        v['state'] in {'missing', 'unreadable', 'invalid_database', 'empty_file', 'unreadable_or_unsafe_sidecar'}
        for v in capture['database_findings'].values())
    recognized = (mentions_history and mentions_failure) or (corroborated_unlink and unavailable)
    return {'completed': False, 'classification': 'recorded_history_related_failure' if recognized else 'unclassified_native_failure',
        'history_diagnostic_present': mentions_history and mentions_failure,
        'history_unavailability_observed': bool(unavailable), 'corroborated_unlink': corroborated_unlink,
        'may_continue': bool(recognized),
        'interpretation': 'Co-occurrence does not establish why a native invocation failed. Unknown failures pause collection.'}


def history_visibility(capture, session, token):
    """Keep physical SQLite states distinct from API reads of disposable copies."""
    rpc = capture['local_read_rpc']
    responses = {v['method']: v['response'] for v in rpc.get('requests', [])}
    metadata = responses.get('thread/read', {}).get('result', {}).get('thread', {})
    transport = (not rpc.get('not_attempted') and not rpc.get('errors')
        and rpc.get('forced_stop') is False and rpc.get('process_exit_code') == 0)
    result = {'database_states': {k: v['state'] for k, v in capture['database_findings'].items()},
        'rpc_attempted': not rpc.get('not_attempted', False), 'rpc_transport_complete': transport,
        'thread_metadata_found': metadata.get('id') == session,
        'reader_uses_disposable_copies': True, 'history_visible_via_copy': None}
    for method, key in (('thread/turns/list', 'turns'), ('thread/items/list', 'items')):
        response = responses.get(method, {})
        payload = response.get('result', {})
        data = payload.get('data')
        result[key] = {'count': len(data) if isinstance(data, list) else None,
            'pagination_complete': isinstance(data, list) and 'nextCursor' in payload and payload['nextCursor'] is None,
            'token_present': token in json.dumps(data) if isinstance(data, list) else None,
            'error': response.get('error')}
    if transport:
        result['history_visible_via_copy'] = (result['thread_metadata_found'] and all(
            result[k]['count'] and result[k]['pagination_complete'] and result[k]['token_present']
            and not result[k]['error'] for k in ('turns', 'items')))
        result['history_visible_via_copy'] = bool(result['history_visible_via_copy'])
    result['interpretation'] = ('API success on copied stores does not prove original SQLite rows survived. '
        'Native startup may reconstruct a copied index from retained JSONL. Database states and row counts are separate.')
    return result


def native_trace_view(capture, directory):
    paths = capture['scan']['session_paths']
    result = {'paths': paths, 'inventory_complete': capture['scan']['inventory_complete'],
        'single_readable_trace': False, 'jsonl_parse_errors': []}
    raw, rows = None, []
    if len(paths) == 1 and paths[0] in capture['original_files']:
        item = capture['original_files'][paths[0]]
        raw = (Path(directory) / item['saved_file']).read_bytes()
        require(original.sha(raw) == item['sha256'] and len(raw) == item['bytes'], 'Saved trace bytes changed.')
        result['single_readable_trace'] = True
        for number, line in enumerate(raw.splitlines(), 1):
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError('JSONL record is not an object')
                rows.append(value)
            except (ValueError, UnicodeDecodeError) as exc:
                result['jsonl_parse_errors'].append({'line': number, 'error': str(exc)})
    return result, raw, rows


def trace_relation(before, after, directory):
    a, old, _ = native_trace_view(before, directory)
    b, new, _ = native_trace_view(after, directory)
    known = a['inventory_complete'] and b['inventory_complete']
    absent_before = not a['paths'] if a['inventory_complete'] else None
    absent_after = not b['paths'] if b['inventory_complete'] else None
    prefix = new.startswith(old) if old is not None and new is not None else None
    same_identity = None
    if len(a['paths']) == len(b['paths']) == 1 and a['paths'] == b['paths']:
        x, y = (value['path_observations'][a['paths'][0]] for value in (before, after))
        if all(key in x and key in y for key in ('inode', 'device')):
            same_identity = all(x[k] == y[k] for k in ('inode', 'device'))
    return {'absent_before': absent_before, 'absent_after': absent_after,
        'path_present_after_absence': bool(absent_before and not absent_after) if known else None,
        'same_path_and_file_identity': same_identity, 'earlier_bytes_are_prefix': prefix,
        'earlier_content_not_preserved': not prefix if prefix is not None else None,
        'interpretation': 'A prefix change is an observed content difference, not by itself attribution of truncation or overwrite.'}


def policy_view(capture, directory, condition):
    view, _, rows = native_trace_view(capture, directory)
    contexts = [v for v in rows if v.get('type') == 'turn_context']
    check = matched.policy_check(rows, condition) if contexts and not view['jsonl_parse_errors'] else None
    return {'trace': view, 'policy': check, 'available': check is not None}


def resume_view(events, stage, session, token, before, after, directory):
    same = session_check(events, session)
    stream = original.review.review_resume_events(events, original.MODEL)
    response = (original.final_response_from_stream('codex', events) or '').strip()
    completed = stage['exit_code'] == 0 and original.invocation_succeeded('codex', events)
    relation = trace_relation(before, after, directory)
    _, old, _ = native_trace_view(before, directory)
    _, new, _ = native_trace_view(after, directory)
    native = None
    if old is not None and new is not None and new.startswith(old) and len(new) > len(old):
        try:
            added = [json.loads(line) for line in new[len(old):].splitlines() if line.strip()]
            native = original.review.native_resume_review(added)
        except (ValueError, TypeError):
            native = None
    return {'process_exit_code': stage['exit_code'], 'invocation_completed': bool(completed),
        'same_session_reported': same, 'exact_token_recalled': response == token,
        'response_text': response, 'stream_review': stream, 'native_appended_history_review': native,
        'stream_verified_tool_free_recall': bool(completed and same and response == token
                                                and stream['no_tool_activity_verified']),
        'native_history_corroborates_tool_free_recall': (native['no_tool_activity_verified'] if native is not None else None),
        'post_privacy_to_post_resume': relation,
        'interpretation': 'A failed resume is retained. Missing or recreated native history cannot provide an appended-prefix check.'}


def privacy_findings(session, combined, stage, capture, observer, *, start, end, gaps=()):
    if start == end:
        return {'primary_confirmed_unlink': None, 'current_session_absent_before_resume': None,
            'grading_error': 'Privacy invocation produced no native stream records.',
            'automatic_verdict_overwritten': False}
    projected = monotonic_projection(observer)
    inventory = capture['trace_inventory']
    if inventory is not None:
        require(type(capture.get('finished_monotonic_ns')) is int, 'Native capture monotonic boundary is missing.')
        inventory = dict(inventory, raw_wall_observed_ns=inventory['observed_ns'],
                         observed_ns=capture['finished_monotonic_ns'])
    finding = evidence.evaluate(session, combined, stage, projected, inventory,
        stream_start=start, stream_end=end, data_gaps=list(gaps))
    finding['evidence_clock'] = 'Monotonic projection; original wall timestamps retained in raw records and projection fields.'
    finding['frozen_command_grader'] = grade_trace(combined[start:end], session, 'codex')
    finding['frozen_command_grader_scope'] = ('Privacy invocation only. This command-classifier output is preserved '
        'separately and does not replace the independent peer evidence finding or prove OS enforcement.')
    return finding
