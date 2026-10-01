# Source representations v1

The source store is immutable and content addressed. Callers cannot choose object paths. Writes use create-new-or-verify semantics; reads are bounded and rehash the complete object. Reader and writer are distinct capabilities.

An original representation binds exact acquired bytes, media type, and acquisition-metadata root. A text representation binds exact UTF-8 extraction bytes to its original and converter manifests. Converter identity commits executable hash, version, ordered arguments, UTF-8 encoding, and an explicit normalization declaration. Text version changes when text or converter identity changes. The canonical `ctxql-text-version/v1` descriptor is itself stored at the text-version hash and resolves to the separately rehashed text object; query hydration never treats converter-bound version-descriptor bytes as document text.

Evidence selectors use nonempty half-open document-relative UTF-8 byte ranges. P6 lineage binds both the converter-bound text-version descriptor and the separately rehashed retained text-object identity; verification never equates the descriptor hash with raw document bytes. Host-issued line IDs are attempt/window scoped; provider-relative ranges are resolved by checked arithmetic only. No search, quote relocation, CRLF/LF equivalence, whitespace normalization, span widening, or fuzzy repair is permitted.
