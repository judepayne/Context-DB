# Predicate numbers — ctxql-predicate-numeric/v2

**Status: current bounded predicate arithmetic contract.** This governs predicate arithmetic, not authoritative data or the exact core model. See the [Rhai numbers chapter](https://rhai.rs/book/language/numbers.html#floating-point-vs-decimal).

## Native execution model

Use pinned Rhai with **`decimal` and `no_float`**, backed by its compatible pinned `rust_decimal`. Do not enable `unchecked`. Decimal literals are handled by the native parser; integer literals that fit i64, counters and indices remain native `INT` (i64 in this POC). An unsuffixed integer literal overflowing i64 can parse as Decimal if it fits that type; schema-selected bound INT conversion still rejects overflow. No custom exact-number type, numeric-token rewriting, switch desugaring or counter rewriting is selected for production.

Decimal has a signed 96-bit coefficient and scale 0–28: maximum magnitude 79,228,162,514,264,337,593,543,950,335; smallest nonzero decimal quantum 10^-28. It cannot represent every value accepted by the exact core. This is a finite-precision arithmetic model, **not** arbitrary-precision or universally exact calculation.

The user accepts the pinned runtime's native operation-specific rounding/rescaling for predicate calculations, including nonterminating decimal division. Do not claim that all operators use one rounding mode. Native integer division retains integer semantics: authors use decimal operands such as `1.0 / 3.0` for decimal division rather than `1 / 3`. Mixed-type operations, explicit conversions, decimal literal parsing and optimization must have executed examples pinned to the tested build. Unsupported native operations remain explicit errors; no f64 fallback.

A decimal expression literal is part of the executable program and follows the pinned parser's finite-precision acceptance/rounding rules. Its original text remains in the exact artifact identity. It is not an authority-ingestion conversion. Test overprecision, tiny literals, exponent limits and overflow explicitly; do not advertise a parse failure as a supported calculation.

### Pinned observations (Rhai 1.26.0, rust_decimal 1.40.0)

- `0.1 + 0.2` yields Decimal 0.3; `1.0 / 3.0` yields 0.3333333333333333333333333333, while `1 / 3` yields INT 0. Mixed INT/Decimal arithmetic and comparisons are supported.
- Tested division midpoint cases round nearest/ties-even; plain decimal literal parsing rounds discarded midpoint digits away from zero. Plain `0.00000000000000000000000000005` becomes 10^-28 and a smaller plain literal can become zero. The same unrepresentable authoritative bound values reject.
- **Scientific literals such as `1e-28` reject in this pinned `no_float` build**, despite the book's feature table. Exponent tokenization is conditionally disabled. Plain decimal literals or bound representable Decimal values work; no source rewriting is selected to hide this limitation.
- Native arrays, integer counters/ranges/indices and ordinary INT/Decimal switch cases work. Decimal indices/ranges and numeric switch cases after range cases reject under native semantics.
- `parse_float` and `sin` have Decimal-returning implementations in this feature configuration; their names do not imply an exposed FLOAT path. Nonfinite strings and host-injected binary floats are rejected by the tested numeric boundary.

These pinned cases do not prove every native numeric function or a complete process sandbox.

## Lossless boundary, not a storage migration

- Keep [numeric-v1](numeric-v1.md), `ExactNumber`, authoritative input parsing, typed literal provenance and canonical hashes unchanged. A large stored number can remain valid even if it cannot be used by the selected predicate runtime.
- Default graph/INIT/bound/function-result numeric values enter the script as Decimal. An explicitly declared integer parameter may use checked i64 conversion; never choose an integer type merely because a decimal value happens to be integral. Native script counters and literals need no host rewriting.
- Check conversion **before** exposing a value to the script: reject out-of-range, excess-scale or rounded ingress. Use an exact parser/conversion and verify the result against the original exact value. Normalizing insignificant trailing zeros is allowed; changing mathematical value is not.
- Graph/INIT/model values outside the runtime's range fail the dependent evaluation explicitly. Do not clamp, round, stringify as a covert numeric fallback, prune the claim or modify stored bytes. Binary floating-point inputs are not silently relabelled Decimal; any separate adapter conversion requires its own declared typed semantics.
- Export the exact represented native INT/Decimal result into `ExactNumber`/canonical values. This preserves the result of a possibly rounded calculation; it does not assert the calculation was exact. Reject unsupported native types and nonfinite values; preserve Missing versus null.
- Bound source, value-tree, state and conversion work/bytes. Finite numeric precision does not itself bound containers or provide a hard process-memory sandbox.

## Failures and sandbox

Use native syntax for ranges, indices, switch and integer counters. Preserve the existing INIT/BIND/LET/NEXT/KEEP state and dependency contract. Pure native arithmetic may fail according to Rhai's documented checked behavior (e.g. overflow or divide by zero); uncaught errors fail evaluation. Native script error catching is not permission to clear host-sticky broker, denial, cancellation or resource-limit failures. Arithmetic rounding is an approved semantic result, not an infrastructure error.

Permission checks, immutable parent/sibling state, LET cycle/scope validation, callback registration, reflection restrictions and execution budgets remain required.

## Identity and replay

Use the explicit identifier **`ctxql-predicate-numeric/v2`** in the new execution configuration/prepared plan and executor ABI. Commit the pinned Rhai/rust_decimal versions, relevant features and conversion implementation through existing plan/build/recording identity mechanisms. No tenth canonical hash domain is introduced.

Old exact executions and fixtures retain their original identities. Never replay an old exact-number execution with this runtime while claiming equivalence. An unavailable compatible old executor is `not_replayable`. Existing stored run bytes remain unchanged, and executable recording envelopes must bind the numeric identity. Operational worker counts are not numeric semantics.

Conformance covers optimization modes, ordinary decimal arithmetic, rounded division, INT/Decimal differences, mixed values, native loops/indexing/switch, exact ingress and result roundtrip, Decimal extrema, unrepresentable core numbers, literal boundaries, overflow/divide-by-zero, and sticky caught callback failures. This does not weaken scoped LET analysis, deep state isolation, callback controls, or predicate-host bounds.
