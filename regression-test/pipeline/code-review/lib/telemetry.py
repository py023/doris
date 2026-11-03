# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Export main and subagent review events directly as bounded OTLP batches."""

import base64
import gzip
import json
import logging
import secrets
import time
import urllib.error
import urllib.request
from collections import deque
from copy import deepcopy
from datetime import datetime


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def text(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)


def clip(value, limit=40_000, *, tail=False):
    rendered = text(value)
    if len(rendered) <= limit:
        return value
    shortened = ('[truncated]\n' + rendered[-limit:]) if tail else (rendered[:limit] + '\n[truncated]')
    return shortened if isinstance(value, str) else {'truncated_json': shortened}


def jsonish(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
    return value


def load_events(path):
    events = []
    for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            event = {'type': 'error', 'message': f'invalid jsonl line {number}: {error}'}
        events.append(dict(event, _line_number=number))
    return events


def attributes(values):
    def value(item):
        if isinstance(item, bool):
            return {'boolValue': item}
        if isinstance(item, int):
            return {'intValue': str(item)}
        if isinstance(item, float):
            return {'doubleValue': item}
        if isinstance(item, list):
            return {'arrayValue': {'values': [value(part) for part in item]}}
        return {'stringValue': text(item)}
    return [{'key': key, 'value': value(item)} for key, item in values.items() if item is not None]


class Trace:
    def __init__(self, options, target, name, session, metadata):
        self.options, self.id, self.spans = options, secrets.token_hex(16), []
        self.metadata = dict(repository=options.repository, workflow=options.workflow_name, run_id=options.run_id,
                             pr_number=str(target['number']), head_sha=target['head'], base_sha=target['base'],
                             model_reasoning_effort=options.effort, **metadata)
        self.common = {'langfuse.trace.name': name, 'session.id': session,
                       'langfuse.trace.tags': ['doris-ai-review-subagent', 'codex-session-jsonl']
                       if metadata.get('subagent_session') else ['doris-ai-review', 'codex-jsonl'],
                       'langfuse.environment': options.environment}
        self.common.update(self.metadata_attributes('trace', self.metadata))

    @staticmethod
    def metadata_attributes(kind, values):
        return {f'langfuse.{kind}.metadata.{key}': value if isinstance(value, (str, int)) else text(value)
                for key, value in values.items() if value not in (None, '')}

    def add(self, name, input, output, start, end, *, parent=None, generation=False, metadata=None,
            error=False, usage=None, status=None):
        values = {**self.common, 'langfuse.observation.type': 'generation' if generation else 'span',
                  'langfuse.observation.input': text(input) if input is not None else None,
                  'langfuse.observation.output': text(output) if output is not None else None,
                  'langfuse.observation.level': 'ERROR' if error else 'DEFAULT',
                  'langfuse.observation.status_message': status,
                  **self.metadata_attributes('observation', {**self.metadata, **(metadata or {})})}
        if generation:
            values['langfuse.observation.model.name'] = self.options.model
            values['langfuse.observation.usage_details'] = text(usage) if usage is not None else None
        if parent is None:
            values['langfuse.internal.is_app_root'] = True
        span = dict(traceId=self.id, spanId=secrets.token_hex(8), name=name, kind=1, flags=1,
                    startTimeUnixNano=str(start), endTimeUnixNano=str(end), attributes=attributes(values),
                    status={'code': 2 if error else 1})
        if parent:
            span['parentSpanId'] = parent
        self.spans.append(span)
        return span['spanId']


def item_shape(item):
    kind, status = item['type'], item.get('status')
    name = {'command_execution': 'command'}.get(kind, kind)
    inputs, outputs, meta = {'item_type': kind}, {}, {}
    if kind == 'command_execution':
        inputs = {'command': item.get('command') or ''}
        outputs = {**{key: item.get(key) for key in ('status', 'exit_code')},
                   'aggregated_output': clip(item.get('aggregated_output') or '', tail=True)}
        meta = dict(command=inputs['command'][:240], status=status, step_kind='tool')
    elif kind in {'mcp_tool_call', 'collab_tool_call'}:
        fields = ('server', 'tool', 'arguments') if kind == 'mcp_tool_call' else ('tool', 'prompt', 'sender_thread_id')
        inputs = {key: clip(item.get(key)) for key in fields}
        fields = ('result', 'error') if kind == 'mcp_tool_call' else ('receiver_thread_ids', 'agents_states')
        outputs = dict(status=status, **{key: clip(item.get(key)) for key in fields})
        name = f"mcp.{item['server']}.{item['tool']}" if kind == 'mcp_tool_call' else f"collab.{item['tool']}"
        meta = dict(tool=item['tool'], status=status, step_kind='tool')
    elif kind == 'web_search':
        inputs = {key: item.get(key) for key in ('query', 'action')}
        outputs = dict(status='completed', query=item.get('query'))
    elif kind == 'file_change':
        inputs = {'changes': item.get('changes') or []}
        outputs = dict(inputs, status=status)
    elif kind == 'todo_list':
        outputs = {'items': item.get('items') or []}
    elif kind in {'reasoning', 'agent_message'}:
        outputs = {'text': clip(item.get('text') or '')}
    elif kind == 'error':
        outputs = {'message': item.get('message') or ''}
    else:
        outputs = clip(item)
    return 'codex.' + name, inputs, outputs, meta


def main_trace(options, target, prompt, final, events):
    terminal = next((e for e in reversed(events) if e['type'] in {'turn.completed', 'turn.failed'}), {})
    state = terminal.get('type', 'turn.unknown').split('.')[-1]
    final = final if final.strip() else next((e['item']['text'] for e in reversed(events)
                                  if e['type'] == 'item.completed' and e['item']['type'] == 'agent_message'
                                  and e['item'].get('text', '').strip()), '')
    final = final or text({'turn_status': state})
    meta = {'codex_jsonl': True}
    for event in events:
        if event['type'] in {'review.completed', 'review.superseded'}:
            key = 'review_completion' if event['type'] == 'review.completed' else 'review_superseded'
            meta[key] = {key: value for key, value in event.items() if key not in {'type', '_line_number'}}
    trace = Trace(options, target, options.trace_name, options.request_id, meta)
    completed = [e for e in events if e['type'] == 'item.completed']
    now = time.time_ns()
    root = trace.add('codex.review', {'prompt': prompt}, {'final_message': final, 'turn_status': state},
                     now, now + (len(completed) + 3) * 1_000_000,
                     metadata={'codex_event_count': len(events), 'codex_completed_item_count': len(completed)})
    usage = {target: int(terminal.get('usage', {}).get(source) or 0) for target, source in (
        ('input', 'input_tokens'), ('output', 'output_tokens'), ('cache_read_input_tokens', 'cached_input_tokens'),
        ('reasoning_output_tokens', 'reasoning_output_tokens'))} if state == 'completed' else None
    trace.add('codex.turn', {'prompt': prompt}, {'status': state, 'final_message': final}, now + 1_000_000,
              now + 2_000_000, parent=root, generation=True, metadata={'item_type': 'turn'},
              error=state == 'failed', usage=usage, status=text(terminal.get('error', {})) if state != 'completed' else None)
    previous, context = None, []
    for event in events:
        item = event.get('item') or {}
        if event['type'] == 'item.completed':
            kind = item['type']
            name, inputs, outputs, meta = item_shape(item)
            if kind == 'agent_message':
                inputs = {'item_type': kind, 'context_window': {
                    'from': previous.get('id') if previous else 'turn_start',
                    'to': item.get('id') or f"line:{event['_line_number']}", 'event_count': len(context)},
                    'events_since_previous_agent_message': context}
                if previous:
                    inputs['previous_agent_message'] = {'id': previous.get('id', ''), 'text': clip(previous['text'])}
                else:
                    inputs['turn_input'] = clip(prompt)
                previous, context = item, []
            start = now + len(trace.spans) * 1_000_000
            trace.add(name, inputs, outputs, start, start + 750_000, parent=root, generation=kind == 'agent_message',
                      metadata=dict(meta, item_id=item.get('id', ''), item_type=kind, event_line=event['_line_number']),
                      error=item.get('status') in {'failed', 'declined'})
            if kind == 'agent_message':
                continue
        context.append({'event_type': event['type'], 'line_number': event['_line_number'],
                        'item_type': item.get('type'), 'payload': clip(item or event)})
    return trace


def session_text(content):
    if isinstance(content, str):
        return clip(content, 200_000)
    return clip('\n'.join(next((part[key] for key in ('text', 'input_text', 'output_text') if key in part),
                               text(part)) if isinstance(part, dict) else text(part) for part in content or []), 200_000)


def session_shape(event, outputs):
    kind, payload = event['type'], event.get('payload') or {}
    item = payload.get('type', 'unknown')
    name, inputs, result = kind, {'session_event_type': kind}, clip(payload)
    generation, metadata = False, {'session_event_type': kind, 'item_type': item}
    if kind == 'session_meta':
        keys = ('id parent_thread_id timestamp cwd originator cli_version thread_source '
                'agent_nickname agent_role model_provider model source').split()
        inputs = {key: clip(payload[key]) for key in keys if key in payload}
        for key in ('base_instructions', 'user_instructions'):
            if key in payload:
                inputs[key + '_present'] = True
        result = {'status': 'recorded', 'thread_source': payload.get('thread_source')}
    elif kind == 'turn_context':
        inputs, result = clip(payload), {'status': 'recorded'}
    elif kind == 'event_msg':
        name, generation = 'event.' + item, item == 'agent_message'
        inputs = {'session_event_type': kind, 'message_type': item, 'payload': clip({
            key: value for key, value in payload.items() if key not in {'message', 'local_images'}})}
        result = {'message': clip(payload.get('message') or ''), 'status': 'recorded'}
    elif kind == 'response_item':
        name = 'response_item.' + item
        if item == 'message':
            role = payload['role']
            name, generation = 'message.' + role, role == 'assistant'
            inputs.update(item_type=item, role=role, phase=payload.get('phase'))
            content = session_text(payload.get('content'))
            if generation:
                result = {'text': content}
            else:
                inputs['content'], result = content, {'status': 'recorded', 'role': role}
        elif item == 'function_call':
            call_id = payload['call_id']
            output = outputs.get(call_id)
            name = 'tool.' + payload['name']
            inputs = {key: clip(jsonish(payload.get(key))) for key in ('name', 'call_id', 'arguments')}
            result = dict(call_id=call_id, output=clip(jsonish(output['output'])) if output else None,
                          status='completed' if output else 'unknown')
        elif item == 'function_call_output':
            name, inputs, result = 'tool_output', {'call_id': payload['call_id']}, clip(jsonish(payload['output']))
        elif item == 'reasoning':
            name = 'reasoning'
            inputs.update(item_type=item, encrypted_content_present=bool(payload.get('encrypted_content')))
            result = dict(summary=clip(payload.get('summary')), status='recorded',
                          encrypted_content_present=bool(payload.get('encrypted_content')))
    return 'codex.subagent.' + name, inputs, result, generation, metadata


def subagent_trace(options, target, path, events, meta):
    source = meta.get('source')
    spawn = source.get('subagent') if isinstance(source, dict) else {}
    spawn = spawn.get('thread_spawn', {}) if isinstance(spawn, dict) else {}
    metadata = dict(codex_session_jsonl=True, subagent_session=True, main_session_id=options.request_id,
                    thread_id=meta['id'], session_file=str(path), session_event_count=len(events))
    metadata.update({key: meta.get(key) or spawn.get(key) or ''
                     for key in ('parent_thread_id', 'agent_nickname', 'agent_role')})
    messages = [e['payload'] for e in events if e['type'] == 'response_item' and e['payload']['type'] == 'message']
    prompt = next((session_text(p['content']) for p in messages if p['role'] == 'user'), text(metadata))
    final = next((session_text(p['content']) for p in reversed(messages) if p['role'] == 'assistant'), '')
    final = final or next((e['payload']['message'] for e in reversed(events)
                          if e['type'] == 'event_msg' and e['payload']['type'] == 'agent_message'), '')
    trace = Trace(options, target, options.subagent_trace_name, f"{options.request_id}:subagent:{meta['id']}", metadata)
    base = time.time_ns()
    starts = [int(datetime.fromisoformat(e['timestamp']).timestamp() * 1e9) if e.get('timestamp')
              else base + index * 1_000_000 for index, e in enumerate(events)]
    root = trace.add('codex.subagent.review', {'prompt': prompt}, {'final_message': final or 'Session recorded'},
                     starts[0], max(starts) + 1_000_000)
    outputs = {}
    for event in events:
        payload = event.get('payload', {})
        if payload.get('type') == 'function_call_output':
            outputs.setdefault(payload['call_id'], payload)
    calls = {e['payload']['call_id'] for e in events if e['type'] == 'response_item'
             and e['payload']['type'] == 'function_call'}
    for event, start in zip(events, starts):
        payload = event.get('payload', {})
        if payload.get('type') == 'function_call_output' and payload['call_id'] in calls:
            continue
        name, inputs, result, generation, metadata = session_shape(event, outputs)
        trace.add(name, inputs, result, start, start + 750_000, parent=root, generation=generation,
                  metadata=dict(metadata, session_line=event['_line_number']))
    return trace


def envelope(options, spans):
    return {'resourceSpans': [{'resource': {'attributes': attributes({
        'service.name': 'doris-code-review', 'langfuse.environment': options.environment})},
        'scopeSpans': [{'scope': {'name': 'doris-litefuse-exporter', 'version': '2'}, 'spans': spans}]}]}


def fit_span(options, span, limit):
    # Keep IDs and hierarchy stable when retrying an oversized observation.
    original = deepcopy(span)
    budget = 40_000
    while len(encoded(envelope(options, [span]))) > limit:
        if budget < 16:
            raise ValueError(f"OTLP span {span['name']} cannot fit in {limit} bytes")
        for attribute, source in zip(span['attributes'], original['attributes']):
            key = attribute['key']
            value = source['value'].get('stringValue')
            if value is not None and ('.metadata.' in key or key.endswith(('.input', '.output', '.status_message'))):
                data = jsonish(value)
                if isinstance(data, dict) and 'context_window' in data:
                    rows = data['events_since_previous_agent_message']
                    keep = min(len(rows), budget // 1000)
                    data['events_since_previous_agent_message'] = [clip(row, budget) for row in rows[-keep:]] if keep else []
                    data['events_since_previous_agent_message_omitted_count'] = len(rows) - keep
                    if 'previous_agent_message' in data:
                        data['previous_agent_message']['text'] = clip(data['previous_agent_message']['text'], budget)
                    if 'turn_input' in data:
                        data['turn_input'] = clip(data['turn_input'], budget)
                else:
                    data = clip(data, budget)
                attribute['value'] = {'stringValue': text(data)}
        budget //= 2
    return span


def upload(options, trace, env):
    endpoint = options.telemetry_url.rstrip('/') + '/api/public/otel/v1/traces'
    token = base64.b64encode(f"{env['LANGFUSE_PUBLIC_KEY']}:{env['LANGFUSE_SECRET_KEY']}".encode()).decode()
    limit = options.telemetry_max_bytes
    chunks, batch = deque(), []
    overhead, size = len(encoded(envelope(options, []))), 0
    for span in trace.spans:
        span = fit_span(options, span, limit)
        length = len(encoded(span)) + 1
        if batch and overhead + size + length > limit:
            chunks.append(batch)
            batch, size = [], 0
        batch.append(span)
        size += length
    if batch:
        chunks.append(batch)
    retries, requests, accepted = {}, 0, 0
    while chunks:
        batch = chunks.popleft()
        payload = encoded(envelope(options, batch))
        request = urllib.request.Request(endpoint, gzip.compress(payload, compresslevel=1, mtime=0), headers={
            'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Authorization': 'Basic ' + token,
            'x-langfuse-ingestion-version': '4', 'x-langfuse-sdk-name': 'doris-code-review',
            'x-langfuse-sdk-version': '2'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                detail = json.loads(response.read() or '{}')
            partial = detail.get('partialSuccess') or detail.get('partial_success') or {}
            rejected = int(partial.get('rejectedSpans') or partial.get('rejected_spans') or 0)
            if rejected:
                raise RuntimeError(f'OTLP rejected {rejected} spans: {partial}')
        except (TimeoutError, urllib.error.URLError) as error:
            code = getattr(error, 'code', None)
            if code is not None and code not in {413, 429, 502, 503, 504}:
                raise
            if code != 413 or len(batch) == 1:
                key = batch[0]['spanId'] if code == 413 else ('http' if code else 'transport')
                retries[key] = retries.get(key, 0) + 1
                if retries[key] > 5:
                    raise
            if code == 413 and len(batch) == 1:
                batch = [fit_span(options, batch[0], len(payload) // 2)]
            if len(batch) > 1 and code in {None, 413}:
                middle = len(batch) // 2
                chunks.extendleft(reversed([batch[:middle], batch[middle:]]))
            else:
                chunks.appendleft(batch)
            if code != 413:
                time.sleep(5)
            continue
        requests += 1
        accepted += len(batch)
    logging.info('Exported trace %s: %s spans in %s requests; retries=%s', trace.id, accepted, requests, retries)


def export(options, context, home, target, env):
    prompt = clip((context / 'codex_goal_prompt.txt').read_text(), 200_000)
    output = context / 'codex-final-message.txt'
    final = clip(output.read_text(), 200_000, tail=True) if output.exists() else ''
    events = load_events(context / 'codex-events.jsonl')
    upload(options, main_trace(options, target, prompt, final, events), env)
    expected = {thread for e in events for thread in ((e.get('item') or {}).get('receiver_thread_ids') or [])}
    count = 0
    for path in sorted((home / 'sessions').rglob('*.jsonl')):
        session = load_events(path)
        meta = next((e['payload'] for e in session if e['type'] == 'session_meta'), {})
        source = meta.get('source')
        eligible = meta.get('id') in expected if expected else (
            meta.get('thread_source') == 'subagent' or isinstance(source, dict) and bool(source.get('subagent')))
        if eligible:
            upload(options, subagent_trace(options, target, path, session, meta), env)
            count += 1
            if count == 100:
                break
