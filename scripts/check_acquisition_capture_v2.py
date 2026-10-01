#!/usr/bin/env python3
"""Independent retained-byte integrity check, NOT an authorization/replay grant."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

MODEL = 'openrouter/deepseek/deepseek-v4.1-flash'
THINKING = 'high'
MAX_BYTES = 32 * 1024 * 1024
MAX_GRAPH_LEAVES = 40
MAX_GRAPH_REQUEST_BYTES = 32 * 1024
MAX_GRAPH_RESPONSE_BYTES = 64 * 1024
MAX_GRAPH_TOTAL_BYTES = 1024 * 1024
MAX_GRAPH_DEPENDENCIES = 300
MAX_CONTEXT_GRAPHS = 12
LEGACY_EXTRACTION_FILES = [
    'extensions/ctxql-ontology-tool.ts', 'profiles/acquisition.toml',
    'prompts/ctxql-acquisition-v1.md', 'prompts/ctxql-acquisition-v2.md',
    'prompts/provider-system-v2.md', 'prompts/provider-system.md',
    'skills/graph-workspace/SKILL.md',
    'skills/read-loan-agreement-v2/SKILL.md',
    'skills/read-loan-agreement/SKILL.md',
]
EXTRACTION_FILES = sorted(LEGACY_EXTRACTION_FILES + [
    'skills/ctxql-ontology/SKILL.md', 'skills/ctxql-query/SKILL.md'])


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    """Match CanonicalValue's UTF-8, compact, lexicographically keyed JSON."""
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()


def closed(value, required, message):
    require(type(value) is dict and set(value) == set(required), message)


def text(value, message, allow_empty=False):
    require(type(value) is str and (allow_empty or value) and len(value.encode()) <= 2048
            and not any(ord(char) < 32 or ord(char) == 127 for char in value), message)
    return value


def integer(value, message):
    require(type(value) is int and value >= 0, message)
    return value


def hash_value(value, message):
    require(type(value) is str and len(value) == 71 and value.startswith('sha256:')
            and all(char in '0123456789abcdef' for char in value[7:]), message)
    return value


def sorted_unique_strings(values, message, maximum=None):
    require(type(values) is list and all(type(value) is str for value in values), message)
    require(values == sorted(set(values)), message)
    if maximum is not None:
        require(len(values) <= maximum, message)
    return values


def check_asset_context(manifest):
    assets = manifest['assets']
    bundle = manifest['asset_manifest']
    require(bundle['model'] == manifest['model'] and bundle['thinking'] == manifest['thinking'],
            'model/bundle binding')
    require(bundle['model'] == MODEL and bundle['thinking'] == THINKING,
            'unsupported recorded provider identity')
    files = []
    seen = set()
    for entry in bundle['files']:
        path = entry['path']
        require(path not in seen, 'duplicate asset')
        seen.add(path)
        data = assets[path].encode('utf-8')
        require(len(data) == entry['size'] and digest(data) == entry['sha256'],
                'asset bytes: ' + path)
        files.append({'path': path, 'sha256': entry['sha256'], 'size': entry['size']})
    require(seen == set(assets), 'asset closure')
    require([entry['path'] for entry in files] == sorted(seen), 'asset ordering')
    if bundle['schema'] == 'ctxql.pi-agent-bundle/v1':
        require(set(bundle) == {'schema', 'model', 'thinking', 'files'},
                'legacy asset manifest shape')
        require([entry['path'] for entry in files] == LEGACY_EXTRACTION_FILES,
                'legacy extraction asset closure')
        profile = 'extraction'
        ordered = {'schema': bundle['schema'], 'model': bundle['model'],
                   'thinking': bundle['thinking'], 'files': files}
    elif bundle['schema'] == 'ctxql.pi-agent-bundle/v2':
        require(set(bundle) == {'schema', 'profile', 'model', 'thinking', 'files'},
                'profiled asset manifest shape')
        profile = bundle['profile']
        require(profile == 'extraction', 'capture asset profile')
        require([entry['path'] for entry in files] == EXTRACTION_FILES,
                'profiled extraction asset closure')
        ordered = {'schema': bundle['schema'], 'profile': profile, 'model': bundle['model'],
                   'thinking': bundle['thinking'], 'files': files}
    else:
        raise ValueError('asset manifest schema')
    encoded = json.dumps(ordered, ensure_ascii=False, separators=(',', ':')).encode()
    require(digest(encoded) == manifest['agent_bundle_hash'], 'executed bundle commitment')
    return bundle['schema'], profile


def check_provider(manifest):
    require(manifest['schema'] == 'ctxql-provider-capture-manifest/v2', 'manifest schema')
    request_bytes = manifest['request'].encode('utf-8')
    require(digest(request_bytes) == manifest['request_root'], 'request bytes')
    require(digest(manifest['response'].encode('utf-8')) == manifest['response_root'], 'response bytes')
    request = decode(manifest['request'])
    require(request['schema'] == 'ctxql-acquisition-request/v2', 'request schema')
    response_protocol = request.get('response_protocol')
    require(response_protocol is None or response_protocol == 'ctxql-extraction-text/v1',
            'response protocol binding')
    for key in ('window_id', 'locator', 'text_version'):
        require(request[key] == manifest[key], 'request binding: ' + key)
    require(request['ontology_capture'] == manifest['ontology_lookup'], 'ontology capture binding')
    source = manifest['source_text'].encode('utf-8')
    start, end = manifest['window_start'], manifest['window_end']
    require(type(start) is int and type(end) is int and 0 <= start < end <= len(source), 'window bounds')
    window_text = source[start:end].decode('utf-8')
    seed, window_id = manifest['coordinate_seed'], manifest['window_id']
    window_handle = digest(f'ctxql-range-map/v2\0{seed}\0{window_id}\0{start}\0{end}'.encode())
    expected = [{'range': window_handle, 'kind': 'window', 'text': window_text}]
    offset = 0
    ordinal = 0
    # Match Rust split_inclusive('\n'), not Python splitlines (which also splits CR).
    segments = source.split(b'\n')
    for line_number, segment in enumerate(segments, 1):
        if line_number < len(segments):
            segment += b'\n'
        left, right = max(offset, start), min(offset + len(segment), end)
        if left < right:
            handle = digest(f'ctxql-line-map/v1\0{seed}\0{window_id}\0{ordinal}'.encode())
            expected.append({'range': handle, 'kind': 'line', 'line_number': line_number,
                             'text': source[left:right].decode('utf-8')})
            ordinal += 1
        offset += len(segment)
    require(request['ranges'] == expected, 'issued ranges or exact source bytes')
    require(manifest['issued_ranges'] == [row['range'] for row in expected], 'range inventory')
    bundle_schema, profile = check_asset_context(manifest)
    return {'schema': 'ctxql-capture-integrity-check/v1', 'request_root': manifest['request_root'],
            'asset_manifest_schema': bundle_schema, 'asset_profile': profile,
            'response_root': manifest['response_root'], 'source_text_root': digest(source),
            'agent_bundle_hash': manifest['agent_bundle_hash'], 'range_count': len(expected),
            'authorization': 'not-established-by-integrity-check'}


def check_graph_payload(value, issuer, session_id, limits):
    closed(value, ('schema', 'issuer', 'session_id', 'snapshot', 'nodes', 'claims'),
           'graph payload shape')
    require(value['schema'] == 'ctxql.graph-workspace/v1', 'graph payload schema')
    require(value['issuer'] == issuer and value['session_id'] == session_id,
            'graph payload owner/session')
    text(value['snapshot'], 'graph payload snapshot')
    require(len(value['snapshot'].encode()) <= limits['max_identifier_bytes'],
            'graph payload snapshot limit')
    require(type(value['nodes']) is list and type(value['claims']) is list, 'graph payload records')
    require(len(value['nodes']) <= limits['max_nodes_per_graph'], 'graph payload node limit')
    require(len(value['claims']) <= limits['max_claims_per_graph'], 'graph payload claim limit')
    keys = set()
    for node in value['nodes']:
        closed(node, ('key', 'canonical_iri', 'label', 'metadata', 'dependencies'), 'graph node shape')
        key = text(node['key'], 'graph node key')
        require(key not in keys, 'duplicate graph node key')
        keys.add(key)
        text(node['canonical_iri'], 'graph node IRI')
        require(len(key.encode()) <= limits['max_identifier_bytes']
                and len(node['canonical_iri'].encode()) <= limits['max_identifier_bytes'],
                'graph node identifier limit')
        require(type(node['label']) is str and 0 < len(node['label'].encode()) <= limits['max_label_bytes']
                and type(node['metadata']) is dict, 'graph node fields')
        require(len(node['metadata']) <= limits['max_metadata_entries']
                and all(type(k) is str and type(v) is str
                        and 0 < len(k.encode()) <= limits['max_identifier_bytes']
                        and len(v.encode()) <= limits['max_note_bytes']
                        for k, v in node['metadata'].items()), 'graph node metadata')
        require(type(node['dependencies']) is list
                and all(type(v) is str and 0 < len(v.encode()) <= limits['max_identifier_bytes']
                        for v in node['dependencies']), 'graph node dependencies')
    claim_ids = set()
    for claim in value['claims']:
        closed(claim, ('claim_id', 'subject_key', 'predicate', 'object', 'metadata', 'dependencies'),
               'graph claim shape')
        claim_id = text(claim['claim_id'], 'graph claim id')
        require(claim_id not in claim_ids, 'duplicate graph claim id')
        claim_ids.add(claim_id)
        require(claim['subject_key'] in keys, 'graph claim subject')
        text(claim['predicate'], 'graph claim predicate')
        require(len(claim_id.encode()) <= limits['max_identifier_bytes']
                and len(claim['predicate'].encode()) <= limits['max_identifier_bytes'],
                'graph claim identifier limit')
        endpoint = claim['object']
        require(type(endpoint) is dict and endpoint.get('kind') in ('node', 'literal'),
                'graph claim object')
        if endpoint['kind'] == 'node':
            closed(endpoint, ('kind', 'key'), 'graph node endpoint shape')
            require(endpoint['key'] in keys, 'graph claim object node')
        else:
            closed(endpoint, ('kind', 'value'), 'graph literal endpoint shape')
            literal = endpoint['value']
            closed(literal, ('lexical', 'datatype', 'language'), 'graph literal shape')
            require(type(literal['lexical']) is str and type(literal['datatype']) is str
                    and (literal['language'] is None or type(literal['language']) is str)
                    and len(literal['lexical'].encode()) <= limits['max_literal_bytes']
                    and 0 < len(literal['datatype'].encode()) <= limits['max_identifier_bytes']
                    and (literal['language'] is None
                         or 0 < len(literal['language'].encode()) <= limits['max_identifier_bytes']),
                    'graph literal fields')
        require(type(claim['metadata']) is dict
                and len(claim['metadata']) <= limits['max_metadata_entries']
                and all(type(k) is str and type(v) is str for k, v in claim['metadata'].items())
                and type(claim['dependencies']) is list
                and all(type(v) is str and 0 < len(v.encode()) <= limits['max_identifier_bytes']
                        for v in claim['dependencies']), 'graph claim fields')
    return value


def check_graph(manifest):
    closed(manifest, ('schema', 'provider', 'graph'), 'graph manifest shape')
    require(manifest['schema'] in ('ctxql-provider-graph-capture-manifest/v1',
                                   'ctxql-provider-graph-capture-manifest/v2'),
            'graph manifest schema')
    provider_result = check_provider(manifest['provider'])
    graph = manifest['graph']
    closed(graph, ('schema', 'capability', 'workspace', 'context', 'transcript_leaves',
                   'graph_payloads', 'index'), 'graph capture shape')
    require((manifest['schema'], graph['schema']) in (
                ('ctxql-provider-graph-capture-manifest/v1', 'ctxql-provider-graph-capture/v2'),
                ('ctxql-provider-graph-capture-manifest/v2', 'ctxql-provider-graph-capture/v3')),
            'graph capture schema')

    capability_bytes = canonical(graph['capability'])
    workspace_bytes = canonical(graph['workspace'])
    context_bytes = canonical(graph['context'])
    index = graph['index']
    closed(index, ('schema', 'stable_session_seed', 'capability_summary_root',
                   'semantic_snapshot', 'source_version', 'source_range_root', 'leaf_roots',
                   'transcript_root', 'final_workspace_root', 'graph_context_root',
                   'final_revision', 'claim_dependencies'), 'graph index shape')
    require(index['schema'] in ('ctxql-graph-capture-index/v1',
                                'ctxql-graph-capture-index/v2'), 'graph index schema')
    session_id = text(index['stable_session_seed'], 'graph session seed')
    hash_value(index['capability_summary_root'], 'capability root')
    hash_value(index['transcript_root'], 'transcript root')
    hash_value(index['final_workspace_root'], 'workspace root')
    hash_value(index['graph_context_root'], 'context root')
    integer(index['final_revision'], 'final revision')
    dependencies = sorted_unique_strings(index['claim_dependencies'], 'index dependencies',
                                         MAX_GRAPH_DEPENDENCIES)
    require(digest(capability_bytes) == index['capability_summary_root'], 'capability binding')
    require(digest(workspace_bytes) == index['final_workspace_root'], 'workspace binding')
    require(digest(context_bytes) == index['graph_context_root'], 'context binding')

    context = graph['context']
    context_v2 = context.get('schema') == 'ctxql-graph-context/v2'
    context_fields = ('schema', 'issuer', 'session_id', 'attempt_id', 'source_version',
                      'source_range_root', 'semantic_snapshot', 'disclosed_claim_ids', 'graphs')
    if context_v2:
        context_fields += ('initial_context',)
    closed(context, context_fields, 'graph context shape')
    require(context['schema'] in ('ctxql-graph-context/v1', 'ctxql-graph-context/v2'),
            'graph context schema')
    require(context_v2 == (index['schema'] == 'ctxql-graph-capture-index/v2')
            and context_v2 == (graph['schema'] == 'ctxql-provider-graph-capture/v3'),
            'graph context version binding')
    for key in ('issuer', 'session_id', 'attempt_id', 'source_version', 'source_range_root',
                'semantic_snapshot'):
        text(context[key], 'graph context ' + key)
    require(context['session_id'] == session_id
            and context['semantic_snapshot'] == index['semantic_snapshot']
            and context['source_version'] == index['source_version']
            and context['source_range_root'] == index['source_range_root'], 'index/context binding')
    disclosed = sorted_unique_strings(context['disclosed_claim_ids'], 'context dependencies',
                                      MAX_GRAPH_DEPENDENCIES)
    require(type(context['graphs']) is list and len(context['graphs']) <= MAX_CONTEXT_GRAPHS,
            'context graph limit')
    graph_handles, dependency_union, initial_dependencies = [], set(), set()
    if context_v2:
        initial = context['initial_context']
        require(type(initial) is list and len(initial) == 1, 'initial graph context')
        gazetteer = initial[0]
        closed(gazetteer, ('kind', 'commitment', 'claim_ids', 'snapshot'), 'gazetteer context shape')
        require(gazetteer['kind'] == 'entity_gazetteer', 'gazetteer context kind')
        hash_value(gazetteer['commitment'], 'gazetteer commitment')
        initial_dependencies.update(sorted_unique_strings(
            gazetteer['claim_ids'], 'gazetteer dependencies', MAX_GRAPH_DEPENDENCIES))
        require(type(gazetteer['snapshot']) is str and len(gazetteer['snapshot'].encode()) <= MAX_GRAPH_TOTAL_BYTES,
                'retained gazetteer snapshot size')
        snapshot = decode(gazetteer['snapshot'])
        closed(snapshot, ('schema', 'entities', 'approved', 'approval_root', 'class_supports', 'commitment', 'dependencies'),
               'retained gazetteer shape')
        require(snapshot['schema'] == 'ctxql-retained-gazetteer/v1', 'retained gazetteer schema')
        require(snapshot['commitment'] == gazetteer['commitment'], 'retained gazetteer commitment')
        require(sorted_unique_strings(snapshot['dependencies'], 'retained gazetteer dependencies', MAX_GRAPH_DEPENDENCIES)
                == gazetteer['claim_ids'], 'retained gazetteer dependency binding')
        require(type(snapshot['entities']) is dict and type(snapshot['class_supports']) is dict,
                'retained gazetteer entities/supports')
        hash_value(snapshot['approval_root'], 'retained approval root')
        approved = sorted_unique_strings(snapshot['approved'], 'retained gazetteer approvals')
        require(set(snapshot['entities']).issubset(approved), 'retained gazetteer approval binding')
        for iri, entity in snapshot['entities'].items():
            closed(entity, ('iri', 'labels', 'classes', 'identifiers'), 'retained entity shape')
            require(entity['iri'] == iri, 'retained entity identity')
        dependency_union.update(initial_dependencies)
    for entry in context['graphs']:
        closed(entry, ('graph_handle', 'claim_ids'), 'context graph shape')
        graph_handles.append(text(entry['graph_handle'], 'context graph handle'))
        dependency_union.update(sorted_unique_strings(entry['claim_ids'], 'context graph dependencies'))
    require(graph_handles == sorted(set(graph_handles)), 'context graph ordering')
    require(disclosed == sorted(dependency_union) == dependencies, 'context dependency union')
    require(len(context_bytes) <= MAX_GRAPH_TOTAL_BYTES, 'graph context byte limit')

    provider = manifest['provider']
    request = decode(provider['request'])
    require(request.get('graph_workspace') == graph['capability'], 'provider capability binding')
    expected_skills = (['read-loan-agreement-v2', 'graph-workspace']
                       if provider_result['asset_manifest_schema'] == 'ctxql.pi-agent-bundle/v1'
                       else ['read-loan-agreement-v2', 'ctxql-ontology', 'ctxql-query', 'graph-workspace'])
    require(graph['capability'].get('skills') == expected_skills,
            'provider recorded skill context')
    require(request.get('entity_gazetteer_capture') == (context['initial_context'][0]['commitment'] if context_v2 else None),
            'provider gazetteer binding')
    require(context['source_version'] == provider['text_version'], 'provider source binding')
    range_root = digest(json.dumps(provider['issued_ranges'], ensure_ascii=False,
                                   separators=(',', ':')).encode())
    require(context['source_range_root'] == range_root, 'provider range binding')

    workspace = graph['workspace']
    closed(workspace, ('schema', 'issuer', 'session_id', 'revision', 'limits', 'graphs', 'records',
                       'idempotency', 'counters', 'next'), 'workspace shape')
    require(workspace['schema'] == 'ctxql-graph-workspace-state/v1'
            and workspace['issuer'] == context['issuer']
            and workspace['session_id'] == session_id
            and integer(workspace['revision'], 'workspace revision') == index['final_revision'],
            'workspace index binding')
    limits = workspace['limits']
    limit_fields = ('max_nodes_per_graph', 'max_claims_per_graph', 'max_live_graphs',
                    'max_imported_nodes', 'max_imported_claims', 'max_draft_nodes',
                    'max_draft_edges', 'max_edits_per_batch', 'max_tool_calls',
                    'max_graph_queries', 'max_request_bytes', 'max_response_bytes',
                    'max_overview_bytes', 'max_aggregate_bytes', 'max_state_bytes',
                    'max_idempotency_records', 'max_label_bytes', 'max_identifier_bytes',
                    'max_literal_bytes', 'max_note_bytes', 'max_evidence_per_record',
                    'max_metadata_entries')
    closed(limits, limit_fields, 'workspace limits shape')
    require(all(type(limits[key]) is int and limits[key] > 0 for key in limit_fields),
            'workspace limits')
    require(limits['max_tool_calls'] <= MAX_GRAPH_LEAVES
            and limits['max_request_bytes'] <= MAX_GRAPH_REQUEST_BYTES
            and limits['max_response_bytes'] <= MAX_GRAPH_RESPONSE_BYTES
            and limits['max_aggregate_bytes'] <= MAX_GRAPH_TOTAL_BYTES
            and len(workspace_bytes) <= limits['max_state_bytes'],
            'workspace/capture limits')
    require(type(workspace['counters']) is dict
            and integer(workspace['counters'].get('tool_calls'), 'workspace tool calls')
            == len(graph['transcript_leaves']), 'workspace tool call binding')

    leaves = graph['transcript_leaves']
    require(type(leaves) is list and len(leaves) <= MAX_GRAPH_LEAVES, 'graph leaf limit')
    leaf_roots, previous_root, previous_revision, leaf_dependencies, payload_roots = [], None, None, set(), set()
    issued_handles = set()
    total_bytes = 0
    for ordinal, leaf in enumerate(leaves):
        closed(leaf, ('schema', 'ordinal', 'previous_leaf_root', 'capability', 'request',
                      'request_root', 'response', 'response_root', 'revision_before',
                      'revision_after', 'result_kind', 'issued_handles', 'graph_payload_root',
                      'claim_dependencies'), 'graph leaf shape')
        require(leaf['schema'] == 'ctxql-graph-transcript-leaf/v1'
                and integer(leaf['ordinal'], 'leaf ordinal') == ordinal, 'leaf ordinal')
        request_bytes, response_bytes = leaf['request'].encode(), leaf['response'].encode()
        require(len(request_bytes) <= MAX_GRAPH_REQUEST_BYTES, 'leaf request byte limit')
        require(len(response_bytes) <= MAX_GRAPH_RESPONSE_BYTES, 'leaf response byte limit')
        require(digest(request_bytes) == leaf['request_root'], 'leaf request root')
        require(digest(response_bytes) == leaf['response_root'], 'leaf response root')
        request_value, response_value = decode(leaf['request']), decode(leaf['response'])
        require(type(request_value) is dict and type(response_value) is dict,
                'graph transcript JSON shape')
        require(leaf['previous_leaf_root'] == previous_root, 'leaf previous root')
        before, after = integer(leaf['revision_before'], 'leaf revision'), integer(leaf['revision_after'], 'leaf revision')
        require(after >= before and (previous_revision is None or before == previous_revision),
                'leaf revision sequence')
        require(leaf['capability'] in ('graph_query', 'graph_playground'), 'leaf capability')
        require(leaf['result_kind'] in ('graph', 'diagnostic', 'view', 'mutation', 'check', 'error'),
                'leaf result kind')
        if leaf['result_kind'] == 'error':
            closed(response_value, ('schema', 'status', 'code'), 'graph tool error shape')
            require(response_value['schema'] == 'ctxql-graph-tool-error/v1'
                    and response_value['status'] == 'error'
                    and response_value['code'] in ('access_denied', 'policy_changed',
                                                   'preparation_failed'),
                    'graph tool public error')
        if leaf['capability'] == 'graph_query':
            require(leaf['result_kind'] in ('graph', 'diagnostic', 'error') and after == before,
                    'graph query result/revision')
        else:
            require(leaf['result_kind'] not in ('graph', 'diagnostic'), 'playground result kind')
            operation = request_value.get('operation')
            require(operation in ('import', 'release_graph', 'apply', 'view', 'inspect', 'check'),
                    'graph replay operation')
            successful = response_value.get('status') == 'ok'
            mutating = successful and operation in ('import', 'release_graph', 'apply')
            require((mutating and after - before <= 1) or (not mutating and after == before),
                    'graph replay revision')
            if successful and operation == 'apply':
                require(type(response_value.get('result')) is dict
                        and response_value['result'].get('revision') == after,
                        'graph replay apply revision')
        handles = leaf['issued_handles']
        require(type(handles) is list and len(handles) == len(set(handles))
                and all(type(handle) is str and handle.endswith('~' + session_id) for handle in handles)
                and issued_handles.isdisjoint(handles), 'leaf issued handles')
        issued_handles.update(handles)
        leaf_dependencies.update(sorted_unique_strings(leaf['claim_dependencies'], 'leaf dependencies',
                                                       MAX_GRAPH_DEPENDENCIES))
        payload_root = leaf['graph_payload_root']
        if leaf['result_kind'] == 'graph':
            hash_value(payload_root, 'leaf graph payload root')
            require(any(handle.startswith('g') for handle in handles), 'leaf graph handle')
            payload_roots.add(payload_root)
        else:
            require(payload_root is None, 'non-query graph payload')
        if leaf['result_kind'] in ('diagnostic', 'error'):
            require(not handles and after == before, 'diagnostic published graph state')
        leaf_bytes = canonical(leaf)
        total_bytes += len(leaf_bytes)
        require(total_bytes <= MAX_GRAPH_TOTAL_BYTES, 'graph capture byte limit')
        root = digest(leaf_bytes)
        leaf_roots.append(root)
        previous_root, previous_revision = root, after
    require(index['leaf_roots'] == leaf_roots, 'index leaf roots')
    require(digest(canonical(leaf_roots)) == index['transcript_root'], 'transcript root')
    require((previous_revision if previous_revision is not None else 0) == index['final_revision'],
            'index final revision')
    require(sorted(leaf_dependencies.union(initial_dependencies)) == dependencies,
            'leaf and initial/index dependencies')

    payloads = graph['graph_payloads']
    require(type(payloads) is dict and set(payloads) == payload_roots, 'graph payload set')
    for root, payload in payloads.items():
        hash_value(root, 'graph payload key')
        payload_bytes = canonical(payload)
        total_bytes += len(payload_bytes)
        require(total_bytes <= MAX_GRAPH_TOTAL_BYTES and digest(payload_bytes) == root,
                'graph payload root or byte limit')
        check_graph_payload(payload, workspace['issuer'], session_id, limits)
    for leaf in leaves:
        root = leaf['graph_payload_root']
        if root is None:
            continue
        response = decode(leaf['response'])
        payload = payloads[root]
        require(response.get('status') == 'graph' and response.get('complete') is True
                and response.get('handle') in leaf['issued_handles']
                and response.get('handle') in graph_handles
                and response.get('snapshot') == payload['snapshot']
                and response.get('node_count') == len(payload['nodes'])
                and response.get('claim_count') == len(payload['claims']),
                'graph transcript payload binding')
    require(digest(capability_bytes) == index['capability_summary_root'], 'capability binding')
    return dict(provider_result, graph_capture_root=digest(canonical(index)),
                graph_transcript_root=index['transcript_root'], graph_leaf_count=len(leaves))


def check_multi(manifest):
    require(manifest['schema'] == 'ctxql-provider-multipassage-capture-manifest/v1',
            'multi manifest schema')
    bundle_schema, profile = check_asset_context(manifest)
    source = manifest['source_text'].encode('utf-8')
    leaves = manifest['leaves']
    require(type(manifest['passage_count']) is int and 0 < manifest['passage_count'] <= 256
            and type(leaves) is list and len(leaves) == manifest['passage_count'],
            'multi passage count')
    previous = None
    for ordinal, leaf in enumerate(leaves):
        require(leaf['ordinal'] == ordinal, 'multi passage order')
        require(previous is None or leaf['context_before'] == previous,
                'multi context chain')
        require(digest(leaf['request'].encode()) == leaf['request_root'],
                'multi request bytes')
        require(digest(leaf['response'].encode()) == leaf['response_root'],
                'multi response bytes')
        request = decode(leaf['request'])
        require(request['schema'] == 'ctxql-acquisition-request/v2'
                and request.get('response_protocol') == 'ctxql-extraction-text/v1',
                'multi request protocol')
        require(request['window_id'] == leaf['window_id']
                and request['locator'] == manifest['locator']
                and request['text_version'] == manifest['text_version']
                and request['ontology_capture'] == manifest['ontology_lookup'],
                'multi request binding')
        require(0 <= leaf['window_start'] < leaf['window_end'] <= len(source),
                'multi window bounds')
        require(leaf['issued_ranges'] == [row['range'] for row in request['ranges']],
                'multi range inventory')
        committed = copy.deepcopy(leaf)
        committed['leaf_root'] = ''
        require(digest(json.dumps(committed, ensure_ascii=False,
                                  separators=(',', ':')).encode()) == leaf['leaf_root'],
                'multi leaf commitment')
        previous = leaf['context_after']
    require(previous == manifest['entity_checkpoint'], 'multi final context')
    committed = copy.deepcopy(manifest)
    committed['capture_root'] = ''
    require(digest(json.dumps(committed, ensure_ascii=False,
                              separators=(',', ':')).encode()) == manifest['capture_root'],
            'multi aggregate commitment')
    return {'schema': 'ctxql-capture-integrity-check/v1',
            'asset_manifest_schema': bundle_schema, 'asset_profile': profile,
            'source_text_root': digest(source),
            'agent_bundle_hash': manifest['agent_bundle_hash'],
            'passage_count': len(leaves), 'capture_root': manifest['capture_root'],
            'authorization': 'not-established-by-integrity-check'}


def check(manifest):
    schema = manifest.get('schema') if type(manifest) is dict else None
    if schema in ('ctxql-provider-graph-capture-manifest/v1',
                  'ctxql-provider-graph-capture-manifest/v2'):
        return check_graph(manifest)
    if schema == 'ctxql-provider-multipassage-capture-manifest/v1':
        return check_multi(manifest)
    return check_provider(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    with args.manifest.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'capture size limit')
    print(json.dumps(check(decode(data)), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
