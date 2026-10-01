# Text language v1 — production frontend contract

`ctxql_engine::frontend::parse(ArtifactKind, &[u8], Limits)` returns a
`ParsedDocument { value, source_map, diagnostics }`. Values use the same exact
`CanonicalValue` representation as JSON. No float conversion, numeric rewriting,
CURIE expansion, bound substitution, profile merging or Rhai evaluation occurs
here. Published artifact hashes must continue to use original bytes.

## Recognition and grammar

UTF-8 accepts one initial BOM. The first nonempty, non-comment logical line must
be exactly `QUERY` or `PROFILE`, matching the requested artifact kind. Every
other input takes the strict JSON route; JSON parse failures never retry as text.
Config is always strict JSON (with optional BOM). JSON comments are not accepted.
LF, CRLF and CR are logical line breaks. Text clauses are case-sensitive;
indentation is multiples of two spaces and tabs reject.

```ebnf
document = header, { top } ;
header = "QUERY" | "PROFILE" ;
top = "NAME ", artifact-name                 (* PROFILE only *)
    | "USE PROFILE ", artifact-name
    | "CONTEXT", assignments@2
    | "BOUNDS", assignments@2
    | "ABOUT", { landing@2 }
    | "WALK", [ " ", direction ], { phase-entry@2 }
    | "FILTER", { phase-entry@2 }
    | "RETURN", { selection@2 } ;
landing = "FROM ", anchors, [ " TO ", anchors ], [ " MATCH ", match ] ;
anchors = string-or-bare-token | JSON-string-array ;
phase-entry = "WHERE", triple@4, { triple@4 }
            | "PREDICATE ", name, { custom-section@4 }
            | "DROP PREDICATES ", JSON-string-array
            | "PREDICATES []" ;
custom-section = "INIT", literal-assignments@6
               | "BIND", assignments@6
               | "LET", expression-assignments@6
               | "NEXT", expression-assignments@6
               | "KEEP ", expression
               | "WHERE", triple@6 ;
triple = field, whitespace, operator, whitespace, value ;
assignment = key, " = ", value ;
selection = response-name, [ " = ", JSON-boolean ] ;
```

`@N` means N leading spaces, not literal syntax. Assignment whitespace around
`=` is optional. Structural values are strict JSON or a single bare string token.
INIT accepts only JSON literals/containers. BIND values are strings; semantic
field/reference validation remains in compilation. LET/NEXT/KEEP retain the
single-line authored expression, including comments, numbers, URLs and Unicode;
assignment edge whitespace is removed. Rhai parsing and native Decimal execution
are native-host responsibilities, not a frontend approximation.

Full-line `#`/`//` comments and blank lines are ignored. Structural trailing
comments start at a whitespace-delimited `#`/`//` outside JSON quotes. URLs are
not globally stripped. Expressions are never comment-stripped.

Top sections, assignments and custom sections reject duplicates. Multiple WHERE
blocks append in source order. Named predicates reject duplicate names. A named
builtin has exactly one WHERE triple and no custom fields. Custom predicates
require KEEP. Clearing predicates cannot coexist with entries. DROP names are
passed unchanged to existing phase-local merge. RETURN omission remains omission,
not false. PROFILE ABOUT remains represented for compiler ignore/warning behavior.

## Bounds and source metadata

Limits bound original input bytes, scan work, retained line/path metadata,
constructed value count/depth and retained string/key output. Each literal also
uses the core bounded exact JSON parser. No token or expression may exceed the
bounded input. Source spans are half-open original UTF-8 byte offsets including
BOM; locations are one-based logical line and **byte** column. Map keys are JSON
pointers with `~0`/`~1` escaping. JSON values have precise spans; text assignments,
predicates and sections have line spans, with nearest-ancestor lookup for other
paths. No normalized-offset substitution table is needed because offsets refer
directly to original bytes.

The compiler must retain these maps separately when merging provenance. Metadata
is not canonical execution identity or authorization. Protected-source permission
checks must precede parsing or content-specific error release.

## Integration and current validation boundary

Register `pub mod frontend` in engine; route compiler query/profile inputs,
catalog validation and service profile-name inspection through `parse`. Keep
semantic merge and exact published-source hashing unchanged. Config callers may
use this entrypoint without enabling text. No new dependencies are required.

`tests/text_frontend.rs` directly exercises production parsing, complete clause
JSON/text structural parity, exact large/scientific values, unchanged native
program text, names/bounds, BOM/newlines, source offsets, duplicates, malformed
input and zero budgets. Parent owns serialized Cargo execution and authenticated
publication/query/reopen/replay coverage. These tests do not certify execution or
native replay.

`parse_detailed` reports a stable source role, bounded half-open byte span and
one-based logical line/byte column while `parse` preserves the original core
`Result` API. Successful compilation can retain `SourceOrigins` through
`compile_with_source_origins`; this sidecar resolves merged query/profile/default
locations without entering canonical execution identity. Catalog and compiler
validation use this same frontend. Inline JSON/text executable plans have equal
normalized values and hashes; separately published equivalent sources retain
their distinct raw artifact references and therefore distinct complete hashes.
