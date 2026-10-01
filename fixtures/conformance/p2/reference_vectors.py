"""Independent finite response oracle, not a CTXQL engine or captured Rust output."""
import argparse
from decimal import Decimal
import hashlib
import json
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

literal = dict(kind='literal', datatype='http://www.w3.org/2001/XMLSchema#string', value='https://literal.example/', language=None)
# One literal edge is terminal at depth one under max_depth=3: no capped frontier,
# no zero-hop, no synthetic literal node, and no hydration or explain section.
path = dict(seed_id='s', node_ids=['s'], endpoints=[dict(kind='iri', value='s'), literal],
            claim_ids=['lit'], depth=1, reached_target=None, block_index=0,
            scores=dict(accumulated_confidence=Decimal('0.125'), grounding_level='claim_only'))
payload = dict(selection=dict(claims=False, paths=True, evidence=False, explain=False),
               graph_status='ready', semantic_flags=[], notices=[], claims=None, paths=[path], explain=None)
wire = canonical(dict(domain='ctxql.response', version='ctxql-canonical/v1', payload=payload))
data = dict(oracle='Hand-derived literal path; independent Python Decimal/scalar-key ordering/hashlib',
            vectors=[dict(id='P2-H001', canonical_utf8=wire, sha256='sha256:' + hashlib.sha256(wire.encode()).hexdigest())])
text = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
output = Path(__file__).with_name('bytes-v1.json')
if args.check:
    if output.read_text() != text:
        raise SystemExit('Independent P2 vector differs')
    print('Independent P2 response vector verified without writes.')
else:
    output.write_text(text)
