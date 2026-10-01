"""Independent finite golden authoring: Python Decimal and hashlib, no Rust output input.
Run from repository root. This is a fixture oracle, not a CTXQL runtime.
"""
import json
import hashlib
from decimal import Decimal
from pathlib import Path


def canonical(v):
    if isinstance(v, Decimal):
        s = format(v, 'f')
        return s.rstrip('0').rstrip('.') if '.' in s else s
    if isinstance(v, dict):
        return '{' + ','.join(canonical(k) + ':' + canonical(v[k]) for k in sorted(v)) + '}'
    if isinstance(v, list):
        return '[' + ','.join(map(canonical, v)) + ']'
    return json.dumps(v, ensure_ascii=False, separators=(',', ':'))


h = 'sha256:' + hashlib.sha256(b'fixture').hexdigest()
a = dict(iri='ctxql:fixture/config', version='1', hash=h)
pin = dict(authority='memory:fixture', graph='g', revision='r0', receipt='receipt0')
t = '1969-12-31T23:59:59.999Z'
bounds = dict(as_of=t, max_depth=3, seed_limit=2, fanout_limit=4, max_claims=16, path_limit=8)
selection = dict(claims=True, paths=True, evidence=False, explain=False)
query = dict(about=[dict(from_=['urn:seed'], to=None, match='exact')], bounds=bounds, walk=dict(direction='outgoing', predicates=[]), filter=dict(predicates=[]), return_=selection)
query['about'][0]['from'] = query['about'][0].pop('from_')
query['return'] = query.pop('return_')
config = dict(name='fixture/config', version='1', runtime=dict(candidate_order=['ctxql:order/v1'], path_ranking=['ctxql:rank/v1'], cycle_policy='no_repeated_claim'), fields={'meta:ext:threshold': {'value': Decimal('0.125')}}, external_functions={}, defaults=dict(seed_limit=2, fanout_limit=4, max_claims=16, path_limit=8))
plan = dict(query=query, artifacts=dict(query=None, profile=None, config=a), config=config, as_of=t)
response = dict(selection=selection, graph_status='ready', semantic_flags=[], notices=[], claims=[], paths=[], explain=None)
root = dict(name='fixture/f', version='1', manifest_hash=h, hashes=[])
input_ = dict(name='fixture/f', version='1', manifest_hash=h, call_index=0, value=Decimal('0.1000000000000000000000000001'))
snapshot = dict(table_uuid='table-1', snapshot_id='42', metadata_hash=h, files=[dict(path='data/part.parquet', hash=h, size=42)], schema_id=1, mapping_hash=h, provider_version='1')
identity = dict(mode='live', source_id='source-1', snapshot=snapshot, row_key=[dict(datatype='http://www.w3.org/2001/XMLSchema#integer', value=9007199254740993, language=None)], mapping_hash=h, slot=dict(name='relation', ordinal=0), occurrence=None)
assembly = dict(iri='ctxql:fixture/assembly', name='fixture/assembly', version='1', hash=h)
product_input = dict(name='primary', query=None, profile=None, plan_hash=h, run_id='run-1', response_hash=h, as_of=t, db_time=pin, claim_ids=[], availability='present')
product = dict(assembly=assembly, product_type='structured', inputs=[product_input], sources=[], notices=[], citations=[], content=dict(decimal=Decimal('123.00000000000000000001')))
text_product = {**product, 'product_type': 'text', 'content': 'café\n東京\n'}
values = [('plan', 'ctxql.plan', plan), ('response', 'ctxql.response', response), ('input-root', 'ctxql.function.input-root', root), ('output-root', 'ctxql.function.output-root', root), ('decimal-input', 'ctxql.function.input', input_), ('decimal-output', 'ctxql.function.output', input_), ('structured-product', 'ctxql.product.structured', product), ('text-product', 'ctxql.product.text', text_product), ('structured-claim', 'ctxql.structured-claim', identity)]
literal = dict(kind='literal', datatype='http://www.w3.org/1999/02/22-rdf-syntax-ns#langString', value='café', language='fr-CA')
meta = dict(claim_id='claim-α', subject_id='urn:seed', subject_type='urn:Subject', relation='urn:relation', relation_type='urn:Relation', object_id=literal, object_type='urn:Text', claim_type='urn:Claim', confidence=Decimal('0.125'), grounding_level='claim_only', lineage=dict(schema='ctxql.lineage.v1', sources=[]), ext={'ctxql.core.temporal/v1': {'source_observed_at': t}}, transaction_time=t, lifecycle_state='contradicted')
path = dict(seed_id='urn:seed', node_ids=['urn:seed'], endpoints=[dict(kind='iri', value='urn:seed'), literal], claim_ids=['claim-α'], depth=1, reached_target=None, block_index=0, scores=dict(accumulated_confidence=Decimal('0.125'), grounding_level='claim_only'))
explain = dict(evaluation_context=dict(as_of=t, db_time=pin, profile=None, bounds=bounds), seeds=[dict(block_index=0, role='from', anchor='urn:seed', id='urn:seed', score=1)], ontology_resolution=[dict(predicate_index=0, operator='isa', requested='urn:Type', matched=['urn:Type'], rule='ctxql:ontology/v1')], traversal_stats=dict(examined=1, eligible=1, traversed=1, unique_traversed=1, returned_paths=1), lifecycle=[dict(claim_id='claim-α', rule='ctxql-execution/v1:lifecycle', state='contradicted', supporting_ids=['event-1'])])
rich_response = dict(selection={**selection, 'explain': True}, graph_status='ready_with_warnings', semantic_flags=['observed'], notices=[dict(code='live_source', details=dict(source_id='source-1'))], claims=[dict(meta=meta)], paths=[path], explain=explain)
values.append(('literal-response', 'ctxql.response', rich_response))
vectors = []
for name, domain, payload in values:
    envelope = dict(domain=domain, version='ctxql-canonical/v1', payload=payload)
    wire = canonical(envelope)
    vectors.append(dict(id=name, canonical_utf8=wire, sha256='sha256:' + hashlib.sha256(wire.encode()).hexdigest()))
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true', help='verify without rewriting goldens')
args = parser.parse_args()
path = Path(__file__).with_name('bytes-v1.json')
text = json.dumps(dict(oracle='Python Decimal/plain-token + scalar sorted keys + hashlib; independently authored', vectors=vectors), ensure_ascii=False, indent=2) + '\n'
if args.check:
    if path.read_text() != text:
        raise SystemExit('independent P1 vectors differ')
    print(f'Independent oracle verified {len(vectors)} vectors without writes.')
else:
    path.write_text(text)
