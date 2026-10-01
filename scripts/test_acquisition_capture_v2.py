import copy
import json
import unittest
from scripts.check_acquisition_capture_v2 import (
    EXTRACTION_FILES, LEGACY_EXTRACTION_FILES, MODEL, THINKING, canonical, check, decode, digest,
)


def fixture():
    source = 'Orion borrows £1000.\r\nExecuted 2022-12-06.\n'
    seed, window = 'attempt:test', 'window:test'
    raw = source.encode()
    window_handle = digest(f'ctxql-range-map/v2\0{seed}\0{window}\0{0}\0{len(raw)}'.encode())
    ranges = [{'range': window_handle, 'kind': 'window', 'text': source}]
    for n, text in enumerate(source.splitlines(keepends=True)):
        ranges.append({'range': digest(f'ctxql-line-map/v1\0{seed}\0{window}\0{n}'.encode()),
                       'kind': 'line', 'line_number': n + 1, 'text': text})
    assets = {path: 'Recorded historical bytes for ' + path for path in LEGACY_EXTRACTION_FILES}
    files = [{'path': path, 'sha256': digest(assets[path].encode()),
              'size': len(assets[path].encode())} for path in LEGACY_EXTRACTION_FILES]
    bundle = {'schema': 'ctxql.pi-agent-bundle/v1', 'model': MODEL, 'thinking': THINKING, 'files': files}
    request = {'schema': 'ctxql-acquisition-request/v2', 'window_id': window, 'locator': 'urn:source:test',
               'text_version': digest(raw), 'ontology_capture': {'cid': 'captured'}, 'ranges': ranges,
               'ontology_briefing': {'terms': [{'definition': 'exact definition'}]}}
    encoded = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
    response = '{"schema":"ctxql-extraction-proposals/v2","no_claims":true}'
    return {'schema': 'ctxql-provider-capture-manifest/v2', 'source_id': 'source:test',
            'locator': request['locator'], 'text_version': request['text_version'], 'window_id': window,
            'request_root': digest(encoded.encode()), 'request': encoded, 'source_text': source,
            'coordinate_seed': seed, 'window_start': 0, 'window_end': len(raw), 'asset_manifest': bundle,
            'assets': assets, 'response_root': digest(response.encode()), 'response': response,
            'model': MODEL, 'thinking': THINKING,
            'agent_bundle_hash': digest(json.dumps(bundle, ensure_ascii=False, separators=(',', ':')).encode()),
            'ontology_lookup': request['ontology_capture'], 'issued_ranges': [r['range'] for r in ranges]}


def multi_fixture():
    provider = fixture()
    leaves = []
    previous = '{"schema":"ctxql-document-entity-table/v2","entities":[]}'
    for ordinal in range(2):
        request = decode(provider['request'])
        request['window_id'] = f'window:{ordinal}'
        request['response_protocol'] = 'ctxql-extraction-text/v1'
        request['ranges'] = []
        encoded = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
        after = previous + str(ordinal)
        leaf = {'ordinal': ordinal, 'window_id': request['window_id'],
                'request_seed': f'seed:{ordinal}', 'context_before': previous,
                'request_root': digest(encoded.encode()), 'request': encoded,
                'response_root': digest(b'NO_CLAIMS'), 'response': 'NO_CLAIMS',
                'context_after': after, 'window_start': 0,
                'window_end': len(provider['source_text'].encode()),
                'issued_ranges': [], 'leaf_root': ''}
        committed = copy.deepcopy(leaf)
        leaf['leaf_root'] = digest(json.dumps(
            committed, ensure_ascii=False, separators=(',', ':')).encode())
        leaves.append(leaf)
        previous = after
    manifest = {'schema': 'ctxql-provider-multipassage-capture-manifest/v1',
                'source_id': provider['source_id'], 'locator': provider['locator'],
                'text_version': provider['text_version'], 'source_text': provider['source_text'],
                'document_seed': 'sha256:' + '0' * 64,
                'asset_manifest': provider['asset_manifest'], 'assets': provider['assets'],
                'model': provider['model'], 'thinking': provider['thinking'],
                'agent_bundle_hash': provider['agent_bundle_hash'],
                'ontology_lookup': provider['ontology_lookup'], 'passage_count': 2,
                'leaves': leaves, 'entity_checkpoint': previous, 'capture_root': '',
                'source_representation': None}
    committed = copy.deepcopy(manifest)
    manifest['capture_root'] = digest(json.dumps(
        committed, ensure_ascii=False, separators=(',', ':')).encode())
    return manifest


def graph_fixture(with_payload=False):
    provider = fixture()
    capability = {
        'schema': 'ctxql-graph-query-capability/v1', 'query_language': 'ctxql-inline/v1',
        'read_only': True, 'max_nodes': 50, 'max_claims': 100, 'max_live_graphs': 3,
        'max_tool_calls': 40, 'max_graph_queries': 12, 'query_timeout_seconds': 30,
        'complete_results_only': True, 'skills': ['read-loan-agreement-v2', 'graph-workspace']}
    request = decode(provider['request'])
    request['graph_workspace'] = capability
    provider['request'] = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
    provider['request_root'] = digest(provider['request'].encode())
    session = 'session:test'
    limits = {
        'max_nodes_per_graph': 50, 'max_claims_per_graph': 100, 'max_live_graphs': 3,
        'max_imported_nodes': 150, 'max_imported_claims': 300, 'max_draft_nodes': 100,
        'max_draft_edges': 200, 'max_edits_per_batch': 20, 'max_tool_calls': 40,
        'max_graph_queries': 12, 'max_request_bytes': 32768, 'max_response_bytes': 65536,
        'max_overview_bytes': 8192, 'max_aggregate_bytes': 1048576,
        'max_state_bytes': 2097152, 'max_idempotency_records': 64, 'max_label_bytes': 512,
        'max_identifier_bytes': 2048, 'max_literal_bytes': 16384, 'max_note_bytes': 2048,
        'max_evidence_per_record': 32, 'max_metadata_entries': 64}
    workspace = {
        'schema': 'ctxql-graph-workspace-state/v1', 'issuer': 'issuer:test',
        'session_id': session, 'revision': 0, 'limits': limits, 'graphs': {}, 'records': {},
        'idempotency': {}, 'counters': {'tool_calls': 1, 'graph_queries': 1,
                                        'aggregate_request_bytes': 18,
                                        'aggregate_response_bytes': 18},
        'next': {'graph': 2 if with_payload else 1, 'node': 1, 'claim': 1, 'reference': 1,
                 'hypothesis': 1, 'question': 1, 'operation': 1}}
    graph_payloads = {}
    handle = 'g1~' + session
    if with_payload:
        payload = {'schema': 'ctxql.graph-workspace/v1', 'issuer': 'issuer:test',
                   'session_id': session, 'snapshot': 'semantic:1:test',
                   'nodes': [{'key': 'urn:node:a', 'canonical_iri': 'urn:node:a', 'label': 'A',
                              'metadata': {}, 'dependencies': []}], 'claims': []}
        payload_root = digest(canonical(payload))
        graph_payloads[payload_root] = payload
        response = json.dumps({'status': 'graph', 'handle': handle, 'complete': True,
                               'snapshot': payload['snapshot'], 'node_count': 1, 'claim_count': 0},
                              separators=(',', ':'))
        result_kind, issued = 'graph', [handle]
        context_graphs = [{'graph_handle': handle, 'claim_ids': []}]
    else:
        payload_root = None
        response = ('{"schema":"ctxql-graph-tool-error/v1","status":"error",'
                    '"code":"preparation_failed"}')
        workspace['counters']['aggregate_response_bytes'] = len(response.encode())
        result_kind, issued, context_graphs = 'error', [], []
    leaf = {'schema': 'ctxql-graph-transcript-leaf/v1', 'ordinal': 0,
            'previous_leaf_root': None, 'capability': 'graph_query',
            'request': '{"query":"narrow"}', 'request_root': digest(b'{"query":"narrow"}'),
            'response': response, 'response_root': digest(response.encode()),
            'revision_before': 0, 'revision_after': 0, 'result_kind': result_kind,
            'issued_handles': issued, 'graph_payload_root': payload_root, 'claim_dependencies': []}
    leaf_root = digest(canonical(leaf))
    context = {'schema': 'ctxql-graph-context/v1', 'issuer': 'issuer:test',
               'session_id': session, 'attempt_id': provider['coordinate_seed'],
               'source_version': provider['text_version'],
               'source_range_root': digest(json.dumps(provider['issued_ranges'],
                                                       separators=(',', ':')).encode()),
               'semantic_snapshot': 'semantic:1:test', 'disclosed_claim_ids': [],
               'graphs': context_graphs}
    index = {'schema': 'ctxql-graph-capture-index/v1', 'stable_session_seed': session,
             'capability_summary_root': digest(canonical(capability)),
             'semantic_snapshot': context['semantic_snapshot'],
             'source_version': context['source_version'],
             'source_range_root': context['source_range_root'], 'leaf_roots': [leaf_root],
             'transcript_root': digest(canonical([leaf_root])),
             'final_workspace_root': digest(canonical(workspace)),
             'graph_context_root': digest(canonical(context)), 'final_revision': 0,
             'claim_dependencies': []}
    return {'schema': 'ctxql-provider-graph-capture-manifest/v1', 'provider': provider,
            'graph': {'schema': 'ctxql-provider-graph-capture/v2', 'capability': capability,
                      'workspace': workspace, 'context': context, 'transcript_leaves': [leaf],
                      'graph_payloads': graph_payloads, 'index': index}}


class CaptureIntegrity(unittest.TestCase):
    def test_retained_gazetteer_version_and_bindings(self):
        value = graph_fixture()
        value['schema'] = 'ctxql-provider-graph-capture-manifest/v2'
        graph = value['graph']
        graph['schema'] = 'ctxql-provider-graph-capture/v3'
        context = graph['context']
        context['schema'] = 'ctxql-graph-context/v2'
        graph['index']['schema'] = 'ctxql-graph-capture-index/v2'
        commitment = digest(b'initial gazetteer')
        snapshot = {'schema': 'ctxql-retained-gazetteer/v1', 'entities': {}, 'approved': [], 'approval_root': digest(b'[]'),
                    'class_supports': {}, 'commitment': commitment, 'dependencies': []}
        context['initial_context'] = [{'kind': 'entity_gazetteer', 'commitment': commitment,
                                       'claim_ids': [], 'snapshot': json.dumps(snapshot)}]
        graph['index']['graph_context_root'] = digest(canonical(context))
        request = decode(value['provider']['request'])
        request['entity_gazetteer_capture'] = commitment
        value['provider']['request'] = json.dumps(request, separators=(',', ':'))
        value['provider']['request_root'] = digest(value['provider']['request'].encode())
        check(value)
        snapshot['commitment'] = digest(b'forged')
        context['initial_context'][0]['snapshot'] = json.dumps(snapshot)
        graph['index']['graph_context_root'] = digest(canonical(context))
        with self.assertRaises(ValueError):
            check(value)

    def test_independent_reconstruction(self):
        result = check(fixture())
        self.assertEqual(result['range_count'], 3)
        self.assertEqual(result['authorization'], 'not-established-by-integrity-check')

    def test_text_response_protocol_and_exact_bytes_are_bound(self):
        manifest = fixture()
        request = decode(manifest['request'])
        request['response_protocol'] = 'ctxql-extraction-text/v1'
        manifest['request'] = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
        manifest['request_root'] = digest(manifest['request'].encode())
        manifest['response'] = 'NO_CLAIMS'
        manifest['response_root'] = digest(manifest['response'].encode())
        check(manifest)

        manifest['response'] += '\n'
        with self.assertRaisesRegex(ValueError, 'response bytes'):
            check(manifest)

    def test_unknown_response_protocol_fails_closed(self):
        manifest = fixture()
        request = decode(manifest['request'])
        request['response_protocol'] = 'ctxql-extraction-text/v999'
        manifest['request'] = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
        manifest['request_root'] = digest(manifest['request'].encode())
        with self.assertRaisesRegex(ValueError, 'response protocol binding'):
            check(manifest)

    def test_mutations_fail(self):
        original = fixture()
        for key, value in [('coordinate_seed', 'changed'), ('window_end', 3),
                           ('source_text', 'Other source'), ('request', '{}'),
                           ('response', 'changed'), ('model', 'other'),
                           ('ontology_lookup', {'cid': 'other'}), ('issued_ranges', [])]:
            with self.subTest(key=key):
                changed = copy.deepcopy(original)
                changed[key] = value
                with self.assertRaises((ValueError, KeyError, UnicodeError)):
                    check(changed)
        changed = copy.deepcopy(original)
        changed['assets']['prompts/provider-system.md'] = 'Changed definition'
        with self.assertRaises(ValueError):
            check(changed)

    def test_profiled_extraction_manifest_and_swapped_profile(self):
        manifest = fixture()
        assets = {path: 'Current profiled bytes for ' + path for path in EXTRACTION_FILES}
        files = [{'path': path, 'sha256': digest(assets[path].encode()),
                  'size': len(assets[path].encode())} for path in EXTRACTION_FILES]
        bundle = {'schema': 'ctxql.pi-agent-bundle/v2', 'profile': 'extraction',
                  'model': MODEL, 'thinking': THINKING, 'files': files}
        manifest['assets'] = assets
        manifest['asset_manifest'] = bundle
        manifest['agent_bundle_hash'] = digest(json.dumps(
            bundle, ensure_ascii=False, separators=(',', ':')).encode())
        check(manifest)

        missing = copy.deepcopy(manifest)
        del missing['assets'][EXTRACTION_FILES[0]]
        with self.assertRaises((ValueError, KeyError)):
            check(missing)

        manifest['asset_manifest']['profile'] = 'chat'
        manifest['agent_bundle_hash'] = digest(json.dumps(
            manifest['asset_manifest'], ensure_ascii=False, separators=(',', ':')).encode())
        with self.assertRaisesRegex(ValueError, 'profile'):
            check(manifest)

    def test_rehashed_unsupported_provider_identity_is_rejected(self):
        for version, paths in [('v1', LEGACY_EXTRACTION_FILES), ('v2', EXTRACTION_FILES)]:
            for field, unsupported in [('model', 'other/model'), ('thinking', 'low')]:
                with self.subTest(version=version, field=field):
                    manifest = fixture()
                    assets = {path: 'test bytes for ' + path for path in paths}
                    files = [{'path': path, 'sha256': digest(assets[path].encode()),
                              'size': len(assets[path].encode())} for path in paths]
                    bundle = {'schema': 'ctxql.pi-agent-bundle/' + version}
                    if version == 'v2':
                        bundle['profile'] = 'extraction'
                    bundle.update(model=MODEL, thinking=THINKING, files=files)
                    manifest.update(assets=assets, asset_manifest=bundle)
                    manifest['agent_bundle_hash'] = digest(json.dumps(
                        bundle, ensure_ascii=False, separators=(',', ':')).encode())
                    check(manifest)
                    manifest[field] = bundle[field] = unsupported
                    manifest['agent_bundle_hash'] = digest(json.dumps(
                        bundle, ensure_ascii=False, separators=(',', ':')).encode())
                    with self.assertRaisesRegex(ValueError, 'unsupported recorded provider identity'):
                        check(manifest)

    def test_source_range_tamper_even_with_rehashed_request(self):
        manifest = fixture()
        request = decode(manifest['request'])
        request['ranges'][1]['text'] = 'not source bytes'
        manifest['request'] = json.dumps(request)
        manifest['request_root'] = digest(manifest['request'].encode())
        with self.assertRaisesRegex(ValueError, 'exact source bytes'):
            check(manifest)

    def test_duplicate_json_is_rejected(self):
        with self.assertRaises(ValueError):
            decode('{"root":1,"root":2}')

    def test_multi_manifest_dispatch_and_context_binding(self):
        manifest = multi_fixture()
        result = check(manifest)
        self.assertEqual(result['passage_count'], 2)
        changed = copy.deepcopy(manifest)
        changed['leaves'][1]['context_before'] = 'forged'
        with self.assertRaisesRegex(ValueError, 'context chain'):
            check(changed)

    def test_graph_manifest_dispatch_and_payload_binding(self):
        for with_payload in (False, True):
            with self.subTest(with_payload=with_payload):
                result = check(graph_fixture(with_payload))
                self.assertEqual(result['graph_leaf_count'], 1)
                self.assertEqual(result['authorization'], 'not-established-by-integrity-check')

    def test_graph_skill_context_is_bound_to_recorded_bundle_version(self):
        value = graph_fixture()
        value['graph']['capability']['skills'] = [
            'read-loan-agreement-v2', 'ctxql-ontology', 'ctxql-query', 'graph-workspace']
        request = decode(value['provider']['request'])
        request['graph_workspace'] = value['graph']['capability']
        value['provider']['request'] = json.dumps(request, separators=(',', ':'))
        value['provider']['request_root'] = digest(value['provider']['request'].encode())
        value['graph']['index']['capability_summary_root'] = digest(
            canonical(value['graph']['capability']))
        with self.assertRaisesRegex(ValueError, 'skill context'):
            check(value)

    def test_graph_error_requires_exact_public_envelope(self):
        for response in (
                {"schema": "ctxql-graph-tool-error/v1", "status": "error", "code": "private"},
                {"schema": "ctxql-graph-tool-error/v1", "status": "error",
                 "code": "preparation_failed", "message": "private detail"}):
            with self.subTest(response=response):
                value = graph_fixture()
                encoded = json.dumps(response, separators=(',', ':'))
                leaf = value['graph']['transcript_leaves'][0]
                leaf['response'], leaf['response_root'] = encoded, digest(encoded.encode())
                leaf_root = digest(canonical(leaf))
                value['graph']['index']['leaf_roots'] = [leaf_root]
                value['graph']['index']['transcript_root'] = digest(canonical([leaf_root]))
                with self.assertRaises(ValueError):
                    check(value)

    def test_graph_transcript_tampering_fails(self):
        mutations = (
            ('ordinal', lambda value: value['graph']['transcript_leaves'][0].update(ordinal=1)),
            ('previous root', lambda value: value['graph']['transcript_leaves'][0].update(
                previous_leaf_root=digest(b'forged'))),
            ('request bytes', lambda value: value['graph']['transcript_leaves'][0].update(
                request='{"query":"other"}')),
            ('response bytes', lambda value: value['graph']['transcript_leaves'][0].update(
                response='{"status":"ok"}')),
            ('leaf index', lambda value: value['graph']['index']['leaf_roots'].__setitem__(
                0, digest(b'forged'))),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                value = graph_fixture()
                mutate(value)
                with self.assertRaises(ValueError):
                    check(value)

    def test_graph_binding_and_limit_tampering_fails(self):
        mutations = (
            ('capability', lambda value: value['graph']['capability'].update(max_nodes=49)),
            ('workspace', lambda value: value['graph']['workspace'].update(revision=1)),
            ('context', lambda value: value['graph']['context'].update(
                semantic_snapshot='semantic:2:forged')),
            ('source', lambda value: value['graph']['context'].update(source_version=digest(b'other'))),
            ('range', lambda value: value['graph']['context'].update(source_range_root=digest(b'other'))),
            ('request capability', lambda value: value['provider'].update(request='{}')),
            ('request limit', lambda value: value['graph']['workspace']['limits'].update(
                max_request_bytes=32769)),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                value = graph_fixture()
                mutate(value)
                with self.assertRaises((ValueError, KeyError)):
                    check(value)

        value = graph_fixture()
        request = decode(value['provider']['request'])
        request['graph_workspace'] = dict(request['graph_workspace'], max_nodes=49)
        value['provider']['request'] = json.dumps(request, ensure_ascii=False, separators=(',', ':'))
        value['provider']['request_root'] = digest(value['provider']['request'].encode())
        with self.assertRaisesRegex(ValueError, 'provider capability binding'):
            check(value)

        value = graph_fixture()
        forged_source = digest(b'other source version')
        value['graph']['context']['source_version'] = forged_source
        value['graph']['index']['source_version'] = forged_source
        value['graph']['index']['graph_context_root'] = digest(canonical(value['graph']['context']))
        with self.assertRaisesRegex(ValueError, 'provider source binding'):
            check(value)

        value = graph_fixture()
        forged_ranges = digest(b'other ranges')
        value['graph']['context']['source_range_root'] = forged_ranges
        value['graph']['index']['source_range_root'] = forged_ranges
        value['graph']['index']['graph_context_root'] = digest(canonical(value['graph']['context']))
        with self.assertRaisesRegex(ValueError, 'provider range binding'):
            check(value)

    def test_graph_payload_set_and_root_tampering_fails(self):
        original = graph_fixture(with_payload=True)
        changed = copy.deepcopy(original)
        root = next(iter(changed['graph']['graph_payloads']))
        changed['graph']['graph_payloads'][root]['nodes'][0]['label'] = 'forged'
        with self.assertRaisesRegex(ValueError, 'payload root'):
            check(changed)

        changed = copy.deepcopy(original)
        changed['graph']['graph_payloads'][digest(b'extra')] = changed['graph']['graph_payloads'][root]
        with self.assertRaisesRegex(ValueError, 'payload set'):
            check(changed)

        changed = copy.deepcopy(original)
        response = decode(changed['graph']['transcript_leaves'][0]['response'])
        response['node_count'] = 2
        encoded = json.dumps(response, separators=(',', ':'))
        leaf = changed['graph']['transcript_leaves'][0]
        leaf['response'], leaf['response_root'] = encoded, digest(encoded.encode())
        new_leaf_root = digest(canonical(leaf))
        changed['graph']['index']['leaf_roots'] = [new_leaf_root]
        changed['graph']['index']['transcript_root'] = digest(canonical([new_leaf_root]))
        with self.assertRaisesRegex(ValueError, 'payload binding'):
            check(changed)


if __name__ == '__main__':
    unittest.main()
