# Extraction text fixtures

`valid-all.txt` and `no-claims.txt` exercise the current `ctxql-extraction-text/v1` grammar.

`markdown-06-v3.json` is retained model-output regression input. The `text_baseline` test derives text in memory and checks equality of all normalized components, including source evidence, ontology choices, local references and generated IDs. It is a parser compatibility fixture, not a semantic-accuracy gold standard.
