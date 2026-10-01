# POC numeric defaults — ctxql-numeric/v1

This v1 contract governs exact core values and lossless authority/canonical storage. [Native Rhai predicate arithmetic v2](predicate-numeric-v2.md) is a separately versioned finite-precision execution boundary; it does not reinterpret or migrate existing values, hashes, fixtures, or replay identities.

Status: current exact-number contract. Hash projections, timestamp rules, and predicate execution retain their separate versioned contracts.

## Configuration boundary

Under the accepted [POC configuration contract](configuration-v1.md), this numeric model and its 128-digit/range limits remain versioned engine semantics, not mutable startup precision settings. Operational work/byte budgets are injectable and may fail execution explicitly, never enable rounding or lossy input. A future explicitly rounded calculation would require its own declared semantic settings and replay hashing; display/assembly formatting is separate. No new rounding operator is implied by the configuration contract.

## Value model and limits

Use exact finite base-10 values for engine integer/decimal arithmetic. An implementation may represent a value as a signed integer coefficient and base-10 exponent; its library types are not the wire contract. No binary64 conversion is permitted on this path.

- Normalize zero to `0`; remove unnecessary coefficient trailing zeros while adjusting the exponent.
- Nonzero values have at most **128 significant decimal digits** after normalization and an **adjusted exponent between −1024 and 1024 inclusive**. The adjusted exponent is `floor(log10(abs(value)))`, computed from decimal digits, not floating-point logarithms. Zero is exempt from that exponent range.
- Limit an input numeric lexeme to **8 KiB** before parsing. Validate exponent magnitude and resulting size before allocating an expanded representation. Normalization does not excuse unbounded input or intermediate work.
- Bound intermediate arithmetic and work in the implementation; return a resource-limit error rather than allocate without limit. No claim of hard process-memory isolation follows from these logical bounds.
- Values/results outside the accepted range fail explicitly. Never clamp, wrap, round or convert an error to a false predicate or an empty successful result.

128 digits provides generous headroom for a small POC while keeping exact operations finite. It is a versioned resource/semantic default, not a claim that CTXQL universally imposes this precision.

## Arithmetic and comparisons

Addition, subtraction and multiplication are exact when their normalized result fits the limits. Division must terminate in base 10 and fit the limits; otherwise return a specific unsupported-exact-result/range error. Division by zero is an explicit arithmetic error. There is no implicit rounding mode: `1 / 3` errors, while `1 / 8` is exactly `0.125`.

Numeric equality compares mathematical integer/decimal values: `1`, `1.0` and `1e0` are equal; `-0` and `0` are equal. Distinct exact values remain distinct, including adjacent integers above 2^53 and precise decimal fractions. This does not erase an authoritative RDF datatype or source lexical provenance, which may be retained separately in the typed record.

No automatic string/boolean-to-number coercion is introduced. Full heterogeneous/missing/null predicate behavior remains C3. Additional operators and transcendental functions require their own declared semantics; this contract does not invent query syntax or a rounding function.

## Numeric rendering

The normalized **numeric token** uses exact plain decimal notation: no exponent, leading `+`, unnecessary leading zeros, unnecessary fractional trailing zeros or redundant decimal point. Preserve significant integer zeros. Examples: `1e3` → `1000`; `1.2300` → `1.23`; `-0.0` → `0`; `0.0010` → `0.001`.

This selects the numeric token rule only. It does not freeze object key ordering, hash domains/envelopes, timestamp precision, response projection or whole-object golden hashes. Authoritative integer/decimal input lexemes must be parsed losslessly; a generic JSON parser that first rounds them to binary64 is not acceptable.

## Source floats and runtime integration

An external binary-float value is not silently relabelled an exact decimal. Preserve its source datatype/value identity. If arithmetic requires conversion, the adapter must produce the exact represented finite value within the limits or explicitly report an unsupported/range error. A shortest round-trip decimal string is not proof of exact numerical conversion from binary floating point. Reject nonfinite values; do not conceal missing source precision.

The implementation must validate its decimal/numeric dependency and typed serialization. Rhai host integration must use its separately declared numeric contract; default binary-float arithmetic is not an implementation of this exact boundary. Unsupported integration fails explicitly rather than weakening the semantics.

## Declarative acceptance vectors

The [numeric defaults fixture](../../fixtures/conformance/canonical/numeric-defaults.json) covers large adjacent integers, equivalent spellings, negative zero, exact/non-terminating/zero division, precision/exponent bounds, and normalization.
