//! Deterministic, document-scoped entity identity state.
//!
//! This is a backend-neutral table contract. It does not make an entity global,
//! rewrite an already issued key, or admit a proposed identity link.

use cdb_core::evidence::Utf8Span;
use cdb_core::id::{ContentHash, EntityId, SourceId};
use cdb_core::{CanonicalValue as V, Error, ErrorKind, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const DOCUMENT_ENTITY_ALGORITHM: &str = "ctxql-document-entity/v2";
pub const MAX_COMPONENTS: usize = 4096;
pub const MAX_PROMPT_ENTRIES: usize = 64;
pub const MAX_PROMPT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorKind {
    ExactMention,
    ContextualAnchor,
}
impl AnchorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactMention => "exact_mention",
            Self::ContextualAnchor => "contextual_anchor",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "exact_mention" => Ok(Self::ExactMention),
            "contextual_anchor" => Ok(Self::ContextualAnchor),
            _ => Err(Error::invalid("unknown document entity anchor kind")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityKeySeed {
    pub source_id: SourceId,
    pub text_version: ContentHash,
    pub anchor_kind: AnchorKind,
    pub start: usize,
    pub end: usize,
    /// Empty for an unambiguous exact mention. Contextual identities use the
    /// length-framed request seed and local ID.
    pub discriminator: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DocumentEntityHandle(String);
impl DocumentEntityHandle {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroundedMention {
    pub span: Utf8Span,
    pub selected_hash: ContentHash,
}
impl GroundedMention {
    /// Verify an absolute UTF-8 byte span against retained source text.
    pub fn from_source(source_text: &str, span: Utf8Span) -> Result<Self> {
        let selected = span.select(source_text)?;
        if selected.is_empty() {
            return Err(Error::invalid("document entity evidence cannot be empty"));
        }
        Ok(Self {
            span,
            selected_hash: ContentHash::of_bytes(selected.as_bytes()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentifierEvidence {
    pub scheme: String,
    pub value: String,
    pub evidence: GroundedMention,
}
impl IdentifierEvidence {
    pub fn from_source(
        source_text: &str,
        scheme: impl Into<String>,
        value: impl Into<String>,
        span: Utf8Span,
    ) -> Result<Self> {
        let scheme = scheme.into();
        let value = value.into();
        validate_token(&scheme, "identifier scheme")?;
        validate_token(&value, "identifier value")?;
        Ok(Self {
            scheme,
            value,
            evidence: GroundedMention::from_source(source_text, span)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasEvidence {
    pub alias: String,
    pub evidence: GroundedMention,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalBinding {
    pub request_seed: String,
    pub local_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentEntity {
    pub handle: DocumentEntityHandle,
    pub iri: EntityId,
    pub key_hash: ContentHash,
    pub key_seed: EntityKeySeed,
    pub mentions: Vec<GroundedMention>,
    pub aliases: Vec<AliasEvidence>,
    pub identifiers: Vec<IdentifierEvidence>,
    pub bindings: Vec<LocalBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityLinkReview {
    pub left: DocumentEntityHandle,
    pub right: DocumentEntityHandle,
    pub evidence: Vec<GroundedMention>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptProjection {
    pub bytes: Vec<u8>,
    pub checkpoint_hash: ContentHash,
    pub entry_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentEntityTable {
    source_id: SourceId,
    text_version: ContentHash,
    source_hash: ContentHash,
    entities: BTreeMap<DocumentEntityHandle, DocumentEntity>,
    keys: BTreeMap<ContentHash, (EntityKeySeed, DocumentEntityHandle)>,
    bindings: BTreeMap<(String, String), DocumentEntityHandle>,
    identity_reviews: Vec<IdentityLinkReview>,
    components: usize,
}

impl DocumentEntityTable {
    pub fn new(source_id: SourceId, text_version: ContentHash, source_text: &str) -> Self {
        Self {
            source_id,
            text_version,
            source_hash: ContentHash::of_bytes(source_text.as_bytes()),
            entities: BTreeMap::new(),
            keys: BTreeMap::new(),
            bindings: BTreeMap::new(),
            identity_reviews: Vec::new(),
            components: 0,
        }
    }

    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }
    pub fn text_version(&self) -> &ContentHash {
        &self.text_version
    }
    pub fn source_hash(&self) -> &ContentHash {
        &self.source_hash
    }
    pub fn len(&self) -> usize {
        self.entities.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }
    pub fn component_count(&self) -> usize {
        self.components
    }
    pub fn identity_reviews(&self) -> &[IdentityLinkReview] {
        &self.identity_reviews
    }
    pub fn entities(&self) -> impl Iterator<Item = &DocumentEntity> {
        self.entities.values()
    }

    /// Resolve only a handle issued by this table (or restored from its
    /// authenticated canonical checkpoint).
    pub fn resolve_reference(&self, handle: &DocumentEntityHandle) -> Result<&DocumentEntity> {
        self.entities
            .get(handle)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "unknown document entity handle"))
    }

    pub fn resolve_local(
        &self,
        request_seed: &str,
        local_id: &str,
    ) -> Option<&DocumentEntityHandle> {
        self.bindings
            .get(&(request_seed.to_owned(), local_id.to_owned()))
    }

    /// Resolve or mint from grounded absolute UTF-8 spans. A single exact name
    /// occurrence gets an exact anchor; otherwise the smallest earliest span is
    /// contextual and is discriminated by `(request_seed, local_id)`.
    pub fn resolve_or_mint(
        &mut self,
        source_text: &str,
        request_seed: &str,
        local_id: &str,
        name: &str,
        spans: &[Utf8Span],
        identifiers: &[IdentifierEvidence],
    ) -> Result<DocumentEntityHandle> {
        self.verify_source(source_text)?;
        validate_token(request_seed, "request seed")?;
        validate_token(local_id, "local entity ID")?;
        validate_token(name, "entity name")?;
        if spans.is_empty() {
            return Err(Error::invalid("document entity requires grounded evidence"));
        }
        let mentions = spans
            .iter()
            .copied()
            .map(|span| GroundedMention::from_source(source_text, span))
            .collect::<Result<Vec<_>>>()?;
        self.verify_identifiers(source_text, identifiers)?;

        let binding_key = (request_seed.to_owned(), local_id.to_owned());
        if let Some(handle) = self.bindings.get(&binding_key).cloned() {
            if !identifiers_compatible(&self.entities[&handle].identifiers, identifiers) {
                return Err(conflict(
                    "local reference has contradictory identifier evidence",
                ));
            }
            self.append_observations(&handle, name, mentions, identifiers.to_vec(), None)?;
            return Ok(handle);
        }

        let exact = exact_occurrences(source_text, name, spans)?;
        let (kind, start, end, mut discriminator) = if exact.len() == 1 {
            (
                AnchorKind::ExactMention,
                exact[0].0,
                exact[0].1,
                String::new(),
            )
        } else {
            let (start, end) = spans
                .iter()
                .map(|span| (span.start(), span.end()))
                .min()
                .ok_or_else(|| Error::invalid("document entity evidence"))?;
            (
                AnchorKind::ContextualAnchor,
                start,
                end,
                contextual_discriminator(request_seed, local_id),
            )
        };

        // A compatible, uniquely overlap-matched spelling is safe to reuse.
        let matches = self
            .entities
            .values()
            .filter(|entity| {
                kind == AnchorKind::ExactMention
                    && identifiers_compatible(&entity.identifiers, identifiers)
                    && entity.aliases.iter().any(|alias| {
                        alias.alias == name
                            && exact_occurrences(source_text, name, &[alias.evidence.span])
                                .is_ok_and(|anchors| anchors == vec![(start, end)])
                    })
            })
            .map(|entity| entity.handle.clone())
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            let handle = matches[0].clone();
            self.append_observations(
                &handle,
                name,
                mentions,
                identifiers.to_vec(),
                Some(binding_key),
            )?;
            return Ok(handle);
        }
        if matches.len() > 1 && kind == AnchorKind::ExactMention {
            discriminator = contextual_discriminator(request_seed, local_id);
        }

        let mut seed = EntityKeySeed {
            source_id: self.source_id.clone(),
            text_version: self.text_version.clone(),
            anchor_kind: if discriminator.is_empty() {
                kind
            } else {
                AnchorKind::ContextualAnchor
            },
            start,
            end,
            discriminator,
        };
        let mut key_hash = hash_seed(&seed);
        if let Some((existing_seed, handle)) = self.keys.get(&key_hash) {
            if existing_seed != &seed {
                return Err(conflict("document entity cryptographic key collision"));
            }
            if identifiers_compatible(&self.entities[handle].identifiers, identifiers) {
                let handle = handle.clone();
                self.append_observations(
                    &handle,
                    name,
                    mentions,
                    identifiers.to_vec(),
                    Some(binding_key),
                )?;
                return Ok(handle);
            }
            // Contradictory support must never merge. Capture this as an
            // explicitly discriminated competing identity.
            seed.anchor_kind = AnchorKind::ContextualAnchor;
            seed.discriminator = contextual_discriminator(request_seed, local_id);
            key_hash = hash_seed(&seed);
            if let Some((other_seed, _)) = self.keys.get(&key_hash) {
                if other_seed != &seed {
                    return Err(conflict("document entity cryptographic key collision"));
                }
                return Err(conflict(
                    "contradictory identity already minted for local reference",
                ));
            }
        }

        self.reserve(1 + mentions.len() + identifiers.len() + 2)?; // entity, alias, binding
        let iri = entity_iri(&key_hash)?;
        let handle = issued_handle(&self.source_hash, &key_hash);
        if self.entities.contains_key(&handle) {
            return Err(conflict("document entity handle collision"));
        }
        let entity = DocumentEntity {
            handle: handle.clone(),
            iri,
            key_hash: key_hash.clone(),
            key_seed: seed.clone(),
            mentions,
            aliases: vec![AliasEvidence {
                alias: name.to_owned(),
                evidence: GroundedMention::from_source(source_text, Utf8Span::new(start, end)?)?,
            }],
            identifiers: identifiers.to_vec(),
            bindings: vec![LocalBinding {
                request_seed: request_seed.to_owned(),
                local_id: local_id.to_owned(),
            }],
        };
        self.keys.insert(key_hash, (seed, handle.clone()));
        self.bindings.insert(binding_key, handle.clone());
        self.entities.insert(handle.clone(), entity);
        Ok(handle)
    }

    /// Append an evidence-backed alias to a previously issued handle.
    pub fn bind_alias(
        &mut self,
        source_text: &str,
        handle: &DocumentEntityHandle,
        alias: impl Into<String>,
        span: Utf8Span,
    ) -> Result<()> {
        self.verify_source(source_text)?;
        self.resolve_reference(handle)?;
        let alias = alias.into();
        validate_token(&alias, "entity alias")?;
        let selected = span.select(source_text)?;
        if !selected.contains(&alias) {
            return Err(Error::invalid("alias is not present in grounded evidence"));
        }
        self.reserve(2)?;
        let evidence = GroundedMention::from_source(source_text, span)?;
        let entity = self.entities.get_mut(handle).expect("checked handle");
        entity.mentions.push(evidence.clone());
        entity.aliases.push(AliasEvidence { alias, evidence });
        Ok(())
    }

    /// Append identifier support. Contradictory values are retained as support
    /// for review, but never trigger merging or key replacement.
    pub fn add_identifier(
        &mut self,
        source_text: &str,
        handle: &DocumentEntityHandle,
        identifier: IdentifierEvidence,
    ) -> Result<()> {
        self.verify_source(source_text)?;
        self.resolve_reference(handle)?;
        self.verify_identifiers(source_text, std::slice::from_ref(&identifier))?;
        self.reserve(1)?;
        self.entities
            .get_mut(handle)
            .expect("checked handle")
            .identifiers
            .push(identifier);
        Ok(())
    }

    /// A link between two issued keys is review-only. It never rewrites either
    /// key, handle, IRI, binding, or previously committed claim.
    pub fn propose_identity_link(
        &mut self,
        source_text: &str,
        left: &DocumentEntityHandle,
        right: &DocumentEntityHandle,
        spans: &[Utf8Span],
        reason: impl Into<String>,
    ) -> Result<()> {
        self.verify_source(source_text)?;
        self.resolve_reference(left)?;
        self.resolve_reference(right)?;
        if left == right {
            return Err(Error::invalid(
                "identity link requires two distinct issued keys",
            ));
        }
        let reason = reason.into();
        validate_token(&reason, "identity link reason")?;
        if spans.is_empty() {
            return Err(Error::invalid("identity link requires grounded evidence"));
        }
        let evidence = spans
            .iter()
            .copied()
            .map(|span| GroundedMention::from_source(source_text, span))
            .collect::<Result<Vec<_>>>()?;
        self.reserve(1 + evidence.len())?;
        self.identity_reviews.push(IdentityLinkReview {
            left: left.clone(),
            right: right.clone(),
            evidence,
            reason,
        });
        Ok(())
    }

    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>> {
        self.checkpoint_value().canonical_bytes(Limits::default())
    }

    pub fn checkpoint_hash(&self) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.checkpoint_bytes()?))
    }

    pub fn from_checkpoint(bytes: &[u8], source_text: &str) -> Result<Self> {
        let value = V::parse(bytes, Limits::default())?;
        if value.canonical_bytes(Limits::default())? != bytes {
            return Err(Error::invalid(
                "document entity checkpoint is not canonical",
            ));
        }
        value.closed(
            &[
                "version",
                "source_id",
                "text_version",
                "source_hash",
                "entities",
                "identity_reviews",
            ],
            &[],
        )?;
        if value.field("version")?.as_str()? != DOCUMENT_ENTITY_ALGORITHM {
            return Err(Error::invalid("document entity checkpoint version"));
        }
        let source_id = SourceId::new(value.field("source_id")?.as_str()?)?;
        let text_version = ContentHash::parse(value.field("text_version")?.as_str()?)?;
        let source_hash = ContentHash::parse(value.field("source_hash")?.as_str()?)?;
        if ContentHash::of_bytes(source_text.as_bytes()) != source_hash {
            return Err(Error::invalid("document entity checkpoint source mismatch"));
        }
        let mut table = Self::new(source_id, text_version, source_text);
        for item in value.field("entities")?.as_array()? {
            let entity = parse_entity(item, source_text)?;
            table.restore_entity(entity)?;
        }
        for item in value.field("identity_reviews")?.as_array()? {
            let review = parse_review(item, source_text)?;
            table.resolve_reference(&review.left)?;
            table.resolve_reference(&review.right)?;
            table.reserve(1 + review.evidence.len())?;
            table.identity_reviews.push(review);
        }
        Ok(table)
    }

    /// Canonical prompt data for earlier issued handles. The full checkpoint
    /// hash commits omitted entries; the projection is capped at 64 entries and
    /// 16 KiB, including its envelope.
    pub fn prompt_projection(&self) -> Result<PromptProjection> {
        let checkpoint_hash = self.checkpoint_hash()?;
        let mut entries = Vec::new();
        for entity in self.entities.values().take(MAX_PROMPT_ENTRIES) {
            let aliases = entity
                .aliases
                .iter()
                .map(|alias| V::string(alias.alias.clone()))
                .collect();
            let entry = object([
                ("handle", V::string(entity.handle.as_str())),
                ("iri", V::string(entity.iri.as_str())),
                ("aliases", V::Array(aliases)),
            ]);
            let mut candidate = entries.clone();
            candidate.push(entry);
            let value = projection_value(&checkpoint_hash, candidate);
            let bytes = value.canonical_bytes(Limits::default())?;
            if bytes.len() > MAX_PROMPT_BYTES {
                break;
            }
            entries = value.field("entries")?.as_array()?.to_vec();
        }
        let entry_count = entries.len();
        let bytes = projection_value(&checkpoint_hash, entries).canonical_bytes(prompt_limits())?;
        Ok(PromptProjection {
            bytes,
            checkpoint_hash,
            entry_count,
        })
    }

    fn verify_source(&self, source_text: &str) -> Result<()> {
        if ContentHash::of_bytes(source_text.as_bytes()) != self.source_hash {
            return Err(Error::invalid("retained document source text mismatch"));
        }
        Ok(())
    }

    fn verify_identifiers(&self, source_text: &str, values: &[IdentifierEvidence]) -> Result<()> {
        for value in values {
            validate_token(&value.scheme, "identifier scheme")?;
            validate_token(&value.value, "identifier value")?;
            let selected = value.evidence.span.select(source_text)?;
            if ContentHash::of_bytes(selected.as_bytes()) != value.evidence.selected_hash {
                return Err(Error::invalid("identifier evidence source mismatch"));
            }
        }
        Ok(())
    }

    fn append_observations(
        &mut self,
        handle: &DocumentEntityHandle,
        name: &str,
        mentions: Vec<GroundedMention>,
        identifiers: Vec<IdentifierEvidence>,
        binding: Option<(String, String)>,
    ) -> Result<()> {
        let add = mentions.len() + identifiers.len() + 1 + usize::from(binding.is_some());
        self.reserve(add)?;
        let alias_evidence = mentions[0].clone();
        let entity = self.entities.get_mut(handle).expect("issued handle");
        entity.mentions.extend(mentions);
        entity.aliases.push(AliasEvidence {
            alias: name.to_owned(),
            evidence: alias_evidence,
        });
        entity.identifiers.extend(identifiers);
        if let Some((request_seed, local_id)) = binding {
            let key = (request_seed.clone(), local_id.clone());
            if let Some(other) = self.bindings.get(&key) {
                if other != handle {
                    return Err(conflict("local reference binding collision"));
                }
            }
            entity.bindings.push(LocalBinding {
                request_seed,
                local_id,
            });
            self.bindings.insert(key, handle.clone());
        }
        Ok(())
    }

    fn reserve(&mut self, add: usize) -> Result<()> {
        let next = self.components.checked_add(add).ok_or_else(Error::limit)?;
        if next > MAX_COMPONENTS {
            return Err(Error::limit());
        }
        self.components = next;
        Ok(())
    }

    fn restore_entity(&mut self, entity: DocumentEntity) -> Result<()> {
        if entity.key_seed.source_id != self.source_id
            || entity.key_seed.text_version != self.text_version
        {
            return Err(Error::invalid("entity seed source mismatch"));
        }
        let expected_hash = hash_seed(&entity.key_seed);
        if expected_hash != entity.key_hash || entity_iri(&expected_hash)? != entity.iri {
            return Err(Error::invalid("document entity key seed corruption"));
        }
        if issued_handle(&self.source_hash, &expected_hash) != entity.handle {
            return Err(Error::invalid("document entity handle corruption"));
        }
        if let Some((seed, _)) = self.keys.get(&expected_hash) {
            if seed != &entity.key_seed {
                return Err(conflict("document entity cryptographic key collision"));
            }
            return Err(conflict("duplicate document entity key"));
        }
        for binding in &entity.bindings {
            let key = (binding.request_seed.clone(), binding.local_id.clone());
            if self.bindings.insert(key, entity.handle.clone()).is_some() {
                return Err(conflict("duplicate local reference binding"));
            }
        }
        let add = 1
            + entity.mentions.len()
            + entity.aliases.len()
            + entity.identifiers.len()
            + entity.bindings.len();
        self.reserve(add)?;
        self.keys.insert(
            expected_hash,
            (entity.key_seed.clone(), entity.handle.clone()),
        );
        if self
            .entities
            .insert(entity.handle.clone(), entity)
            .is_some()
        {
            return Err(conflict("duplicate document entity handle"));
        }
        Ok(())
    }

    fn checkpoint_value(&self) -> V {
        V::object([
            ("version".to_owned(), V::string(DOCUMENT_ENTITY_ALGORITHM)),
            ("source_id".to_owned(), V::string(self.source_id.as_str())),
            (
                "text_version".to_owned(),
                V::string(self.text_version.as_str()),
            ),
            (
                "source_hash".to_owned(),
                V::string(self.source_hash.as_str()),
            ),
            (
                "entities".to_owned(),
                V::Array(self.entities.values().map(entity_value).collect()),
            ),
            (
                "identity_reviews".to_owned(),
                V::Array(self.identity_reviews.iter().map(review_value).collect()),
            ),
        ])
        .expect("static checkpoint keys")
    }
}

fn exact_occurrences(text: &str, name: &str, spans: &[Utf8Span]) -> Result<Vec<(usize, usize)>> {
    let mut found = BTreeSet::new();
    for span in spans {
        let selected = span.select(text)?;
        for (offset, _) in selected.match_indices(name) {
            found.insert((span.start() + offset, span.start() + offset + name.len()));
        }
    }
    Ok(found.into_iter().collect())
}

fn identifiers_compatible(left: &[IdentifierEvidence], right: &[IdentifierEvidence]) -> bool {
    !left.iter().any(|a| {
        right
            .iter()
            .any(|b| a.scheme == b.scheme && a.value != b.value)
    })
}

fn contextual_discriminator(request_seed: &str, local_id: &str) -> String {
    // Preserve the v2 seed convention used by the original host minter. The
    // surrounding seed tuple remains length-framed, so this separator cannot
    // create an ambiguous canonical tuple.
    format!("{request_seed}\0{local_id}")
}

fn seed_bytes(seed: &EntityKeySeed) -> Vec<u8> {
    frame(&[
        DOCUMENT_ENTITY_ALGORITHM,
        seed.source_id.as_str(),
        seed.text_version.as_str(),
        seed.anchor_kind.as_str(),
        &seed.start.to_string(),
        &seed.end.to_string(),
        &seed.discriminator,
    ])
    .into_bytes()
}

fn frame(values: &[&str]) -> String {
    let mut framed = String::new();
    for value in values {
        framed.push_str(&value.len().to_string());
        framed.push(':');
        framed.push_str(value);
    }
    framed
}

fn hash_seed(seed: &EntityKeySeed) -> ContentHash {
    ContentHash::of_bytes(&seed_bytes(seed))
}

fn entity_iri(hash: &ContentHash) -> Result<EntityId> {
    EntityId::new(format!(
        "urn:ctxql:entity:document:v2:{}",
        &hash.as_str()[7..]
    ))
}

fn issued_handle(source_hash: &ContentHash, key_hash: &ContentHash) -> DocumentEntityHandle {
    let digest = ContentHash::of_bytes(
        frame(&[
            "ctxql-document-entity-handle/v1",
            source_hash.as_str(),
            key_hash.as_str(),
        ])
        .as_bytes(),
    );
    DocumentEntityHandle(format!("deh_v1_{}", &digest.as_str()[7..]))
}

fn validate_token(value: &str, what: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::invalid(format!("invalid {what}")));
    }
    Ok(())
}

fn conflict(message: &str) -> Error {
    Error::new(ErrorKind::Conflict, message)
}

fn prompt_limits() -> Limits {
    Limits::new(MAX_PROMPT_BYTES, 16, 4096, 100_000, MAX_PROMPT_BYTES)
        .expect("static prompt limits")
}

fn projection_value(hash: &ContentHash, entries: Vec<V>) -> V {
    object([
        ("version", V::string("ctxql-document-entity-prompt/v1")),
        ("checkpoint_hash", V::string(hash.as_str())),
        ("entries", V::Array(entries)),
    ])
}

fn object<const N: usize>(entries: [(&str, V); N]) -> V {
    V::object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value)),
    )
    .expect("static object keys")
}

fn span_value(value: &GroundedMention) -> V {
    object([
        ("start", V::integer(value.span.start() as u64)),
        ("end", V::integer(value.span.end() as u64)),
        ("selected_hash", V::string(value.selected_hash.as_str())),
    ])
}

fn seed_value(value: &EntityKeySeed) -> V {
    object([
        ("source_id", V::string(value.source_id.as_str())),
        ("text_version", V::string(value.text_version.as_str())),
        ("anchor_kind", V::string(value.anchor_kind.as_str())),
        ("start", V::integer(value.start as u64)),
        ("end", V::integer(value.end as u64)),
        ("discriminator", V::string(value.discriminator.clone())),
    ])
}

fn entity_value(value: &DocumentEntity) -> V {
    object([
        ("handle", V::string(value.handle.as_str())),
        ("iri", V::string(value.iri.as_str())),
        ("key_hash", V::string(value.key_hash.as_str())),
        ("key_seed", seed_value(&value.key_seed)),
        (
            "mentions",
            V::Array(value.mentions.iter().map(span_value).collect()),
        ),
        (
            "aliases",
            V::Array(
                value
                    .aliases
                    .iter()
                    .map(|alias| {
                        object([
                            ("alias", V::string(alias.alias.clone())),
                            ("evidence", span_value(&alias.evidence)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "identifiers",
            V::Array(
                value
                    .identifiers
                    .iter()
                    .map(|id| {
                        object([
                            ("scheme", V::string(id.scheme.clone())),
                            ("value", V::string(id.value.clone())),
                            ("evidence", span_value(&id.evidence)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "bindings",
            V::Array(
                value
                    .bindings
                    .iter()
                    .map(|binding| {
                        object([
                            ("request_seed", V::string(binding.request_seed.clone())),
                            ("local_id", V::string(binding.local_id.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn review_value(value: &IdentityLinkReview) -> V {
    object([
        ("left", V::string(value.left.as_str())),
        ("right", V::string(value.right.as_str())),
        (
            "evidence",
            V::Array(value.evidence.iter().map(span_value).collect()),
        ),
        ("reason", V::string(value.reason.clone())),
    ])
}

fn parse_span(value: &V, source_text: &str) -> Result<GroundedMention> {
    value.closed(&["start", "end", "selected_hash"], &[])?;
    let start = usize::try_from(value.field("start")?.u64()?).map_err(|_| Error::limit())?;
    let end = usize::try_from(value.field("end")?.u64()?).map_err(|_| Error::limit())?;
    let result = GroundedMention::from_source(source_text, Utf8Span::new(start, end)?)?;
    if result.selected_hash != ContentHash::parse(value.field("selected_hash")?.as_str()?)? {
        return Err(Error::invalid("grounded evidence hash corruption"));
    }
    Ok(result)
}

fn parse_seed(value: &V) -> Result<EntityKeySeed> {
    value.closed(
        &[
            "source_id",
            "text_version",
            "anchor_kind",
            "start",
            "end",
            "discriminator",
        ],
        &[],
    )?;
    Ok(EntityKeySeed {
        source_id: SourceId::new(value.field("source_id")?.as_str()?)?,
        text_version: ContentHash::parse(value.field("text_version")?.as_str()?)?,
        anchor_kind: AnchorKind::parse(value.field("anchor_kind")?.as_str()?)?,
        start: usize::try_from(value.field("start")?.u64()?).map_err(|_| Error::limit())?,
        end: usize::try_from(value.field("end")?.u64()?).map_err(|_| Error::limit())?,
        discriminator: value.field("discriminator")?.as_str()?.to_owned(),
    })
}

fn parse_handle(value: &V) -> Result<DocumentEntityHandle> {
    let value = value.as_str()?;
    if value.len() != 71
        || !value.starts_with("deh_v1_")
        || !value[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::invalid("invalid document entity handle"));
    }
    Ok(DocumentEntityHandle(value.to_owned()))
}

fn parse_entity(value: &V, source_text: &str) -> Result<DocumentEntity> {
    value.closed(
        &[
            "handle",
            "iri",
            "key_hash",
            "key_seed",
            "mentions",
            "aliases",
            "identifiers",
            "bindings",
        ],
        &[],
    )?;
    let mentions = value
        .field("mentions")?
        .as_array()?
        .iter()
        .map(|v| parse_span(v, source_text))
        .collect::<Result<Vec<_>>>()?;
    let aliases = value
        .field("aliases")?
        .as_array()?
        .iter()
        .map(|v| {
            v.closed(&["alias", "evidence"], &[])?;
            Ok(AliasEvidence {
                alias: v.field("alias")?.as_str()?.to_owned(),
                evidence: parse_span(v.field("evidence")?, source_text)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let identifiers = value
        .field("identifiers")?
        .as_array()?
        .iter()
        .map(|v| {
            v.closed(&["scheme", "value", "evidence"], &[])?;
            Ok(IdentifierEvidence {
                scheme: v.field("scheme")?.as_str()?.to_owned(),
                value: v.field("value")?.as_str()?.to_owned(),
                evidence: parse_span(v.field("evidence")?, source_text)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let bindings = value
        .field("bindings")?
        .as_array()?
        .iter()
        .map(|v| {
            v.closed(&["request_seed", "local_id"], &[])?;
            Ok(LocalBinding {
                request_seed: v.field("request_seed")?.as_str()?.to_owned(),
                local_id: v.field("local_id")?.as_str()?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DocumentEntity {
        handle: parse_handle(value.field("handle")?)?,
        iri: EntityId::new(value.field("iri")?.as_str()?)?,
        key_hash: ContentHash::parse(value.field("key_hash")?.as_str()?)?,
        key_seed: parse_seed(value.field("key_seed")?)?,
        mentions,
        aliases,
        identifiers,
        bindings,
    })
}

fn parse_review(value: &V, source_text: &str) -> Result<IdentityLinkReview> {
    value.closed(&["left", "right", "evidence", "reason"], &[])?;
    Ok(IdentityLinkReview {
        left: parse_handle(value.field("left")?)?,
        right: parse_handle(value.field("right")?)?,
        evidence: value
            .field("evidence")?
            .as_array()?
            .iter()
            .map(|v| parse_span(v, source_text))
            .collect::<Result<Vec<_>>>()?,
        reason: value.field("reason")?.as_str()?.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> DocumentEntityTable {
        DocumentEntityTable::new(
            SourceId::new("document-1").unwrap(),
            ContentHash::of_bytes(b"version-1"),
            text,
        )
    }

    #[test]
    fn canonical_identity_is_deterministic_and_same_anchor_reuses() {
        let text = "Acme lends.";
        let span = Utf8Span::new(0, 4).unwrap();
        let mut a = table(text);
        let first = a
            .resolve_or_mint(text, "req", "e1", "Acme", &[span], &[])
            .unwrap();
        let second = a
            .resolve_or_mint(text, "req", "e2", "Acme", &[span], &[])
            .unwrap();
        assert_eq!(first, second);
        let mut b = table(text);
        let other = b
            .resolve_or_mint(text, "other", "different", "Acme", &[span], &[])
            .unwrap();
        assert_eq!(
            a.resolve_reference(&first).unwrap().iri,
            b.resolve_reference(&other).unwrap().iri
        );
    }

    #[test]
    fn overlapping_evidence_does_not_merge_distinct_physical_mentions() {
        let text = "Acme shares business with Acme";
        let mut table = table(text);
        let left = table
            .resolve_or_mint(
                text,
                "request:1",
                "left",
                "Acme",
                &[Utf8Span::new(0, 20).unwrap()],
                &[],
            )
            .unwrap();
        let right = table
            .resolve_or_mint(
                text,
                "request:2",
                "right",
                "Acme",
                &[Utf8Span::new(12, text.len()).unwrap()],
                &[],
            )
            .unwrap();
        assert_ne!(left, right);
        let repeated = table
            .resolve_or_mint(
                text,
                "request:3",
                "left-again",
                "Acme",
                &[Utf8Span::new(0, 4).unwrap()],
                &[],
            )
            .unwrap();
        assert_eq!(left, repeated);
    }

    #[test]
    fn same_spelling_distinct_spans_and_overlapping_aliases() {
        let text = "Bank Alpha and Bank Alpha";
        let mut table = table(text);
        let left = table
            .resolve_or_mint(
                text,
                "r",
                "left",
                "Bank Alpha",
                &[Utf8Span::new(0, 10).unwrap()],
                &[],
            )
            .unwrap();
        let right = table
            .resolve_or_mint(
                text,
                "r",
                "right",
                "Bank Alpha",
                &[Utf8Span::new(15, 25).unwrap()],
                &[],
            )
            .unwrap();
        assert_ne!(left, right);
        let overlap = table
            .resolve_or_mint(
                text,
                "r2",
                "alias",
                "Bank Alpha",
                &[Utf8Span::new(0, 14).unwrap()],
                &[],
            )
            .unwrap();
        assert_eq!(left, overlap);
    }

    #[test]
    fn contextual_label_uses_request_and_local_discriminator() {
        let text = "the party receiving funds";
        let span = Utf8Span::new(0, text.len()).unwrap();
        let mut table = table(text);
        let a = table
            .resolve_or_mint(text, "request", "borrower-a", "Borrower", &[span], &[])
            .unwrap();
        let b = table
            .resolve_or_mint(text, "request", "borrower-b", "Borrower", &[span], &[])
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(
            table.resolve_reference(&a).unwrap().key_seed.anchor_kind,
            AnchorKind::ContextualAnchor
        );
    }

    #[test]
    fn contradictory_identifiers_never_merge_and_late_link_is_review_only() {
        let text = "Acme / Acme ID-A ID-B same party";
        let first_id =
            IdentifierEvidence::from_source(text, "lei", "ID-A", Utf8Span::new(12, 16).unwrap())
                .unwrap();
        let second_id =
            IdentifierEvidence::from_source(text, "lei", "ID-B", Utf8Span::new(17, 21).unwrap())
                .unwrap();
        let mut table = table(text);
        let a = table
            .resolve_or_mint(
                text,
                "r1",
                "a",
                "Acme",
                &[Utf8Span::new(0, 4).unwrap()],
                &[first_id],
            )
            .unwrap();
        let b = table
            .resolve_or_mint(
                text,
                "r2",
                "b",
                "Acme",
                &[Utf8Span::new(7, 11).unwrap()],
                &[second_id],
            )
            .unwrap();
        assert_ne!(a, b);
        let before = (
            table.resolve_reference(&a).unwrap().iri.clone(),
            table.resolve_reference(&b).unwrap().iri.clone(),
        );
        table
            .propose_identity_link(
                text,
                &a,
                &b,
                &[Utf8Span::new(22, 32).unwrap()],
                "two issued keys may identify one party",
            )
            .unwrap();
        assert_eq!(before.0, table.resolve_reference(&a).unwrap().iri);
        assert_eq!(before.1, table.resolve_reference(&b).unwrap().iri);
        assert_eq!(table.identity_reviews().len(), 1);
    }

    #[test]
    fn checkpoint_roundtrip_projection_and_corruption() {
        let text = "Acme lends to Beta";
        let mut table = table(text);
        let a = table
            .resolve_or_mint(text, "r", "a", "Acme", &[Utf8Span::new(0, 4).unwrap()], &[])
            .unwrap();
        table
            .bind_alias(text, &a, "Acme", Utf8Span::new(0, 4).unwrap())
            .unwrap();
        let bytes = table.checkpoint_bytes().unwrap();
        let restored = DocumentEntityTable::from_checkpoint(&bytes, text).unwrap();
        assert_eq!(bytes, restored.checkpoint_bytes().unwrap());
        assert_eq!(
            table.checkpoint_hash().unwrap(),
            restored.checkpoint_hash().unwrap()
        );
        let projection = restored.prompt_projection().unwrap();
        assert!(projection.entry_count <= MAX_PROMPT_ENTRIES);
        assert!(projection.bytes.len() <= MAX_PROMPT_BYTES);
        assert!(DocumentEntityTable::from_checkpoint(&bytes, "changed").is_err());
        let mut corrupt = bytes;
        let marker = b"\"key_hash\":\"sha256:";
        let position = corrupt
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len();
        corrupt[position] = if corrupt[position] == b'a' {
            b'b'
        } else {
            b'a'
        };
        assert!(DocumentEntityTable::from_checkpoint(&corrupt, text).is_err());
    }
}
