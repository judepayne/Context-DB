//! Lossless conversion from the closed Pi grammar into backend-neutral advisory values.

use crate::parser::{ClaimObject, ClaimPair, Coordinate, ParsedOutput};
use cdb_acquisition::candidates::{
    AdvisoryBundle, AdvisoryClaim, CandidateLimits, CandidateObject, ClaimMetadata,
    EntityCandidate, LocalId, TypedLiteral,
};
use cdb_acquisition::coordinates::{LineCoordinate, LineId, LineSelection};
use cdb_core::id::{ContentHash, Iri};
use cdb_core::{Error, Result};
use std::collections::BTreeMap;

pub fn into_advisory(
    output: ParsedOutput,
    limits: &CandidateLimits,
) -> Result<Vec<AdvisoryBundle>> {
    let ParsedOutput::Claims(pairs) = output else {
        return Ok(Vec::new());
    };
    let mut grouped = BTreeMap::<String, Vec<ClaimPair>>::new();
    for pair in pairs {
        grouped
            .entry(pair.claim.bundle_id.clone())
            .or_default()
            .push(pair);
    }
    grouped
        .into_iter()
        .map(|(bundle, pairs)| convert_bundle(bundle, pairs, limits))
        .collect()
}

fn convert_bundle(
    bundle: String,
    pairs: Vec<ClaimPair>,
    limits: &CandidateLimits,
) -> Result<AdvisoryBundle> {
    let local_bundle_id = LocalId::new(bundle, limits.max_local_id_bytes)?;
    let mut entities = BTreeMap::<LocalId, EntityCandidate>::new();
    let mut claims = Vec::with_capacity(pairs.len());
    let mut metadata = Vec::with_capacity(pairs.len());
    for pair in pairs {
        if pair.claim.valid_time_end.is_some() {
            return Err(Error::invalid(
                "interval endpoints require a temporal qualifier claim",
            ));
        }
        let subject = convert_entity(&pair.claim.subject, limits)?;
        insert_entity(&mut entities, subject.clone())?;
        let object = match &pair.claim.object {
            ClaimObject::Entity(entity) => {
                let entity = convert_entity(entity, limits)?;
                let id = entity.local_id().clone();
                insert_entity(&mut entities, entity)?;
                CandidateObject::Entity(id)
            }
            ClaimObject::Literal(literal) => CandidateObject::Literal(TypedLiteral::new(
                &literal.lexical,
                Iri::new(&literal.datatype_iri)?,
                literal.language.clone(),
                limits,
            )?),
        };
        let local_claim_id = LocalId::new(&pair.claim.claim_id, limits.max_local_id_bytes)?;
        claims.push(AdvisoryClaim {
            local_claim_id: local_claim_id.clone(),
            subject: subject.local_id().clone(),
            predicate: Iri::new(&pair.claim.predicate_iri)?,
            object,
            relation_type: Iri::new(&pair.claim.relation_type_iri)?,
            claim_type: Iri::new(&pair.claim.claim_type_iri)?,
            endpoint_type_claims: pair
                .claim
                .endpoint_type_claim_ids
                .iter()
                .map(|id| LocalId::new(id, limits.max_local_id_bytes))
                .collect::<Result<_>>()?,
            confidence: pair.claim.confidence,
            valid_time: pair.claim.valid_time_start,
        });
        metadata.push(ClaimMetadata {
            local_claim_id,
            locator: Iri::new(&pair.metadata.locator)?,
            text_version: ContentHash::parse(&pair.metadata.text_version)?,
            coordinates: pair
                .metadata
                .coordinates
                .iter()
                .map(convert_coordinate)
                .collect::<Result<_>>()?,
            temporal_qualifier_claim: pair
                .metadata
                .temporal_qualifier_claim_id
                .as_deref()
                .map(|id| LocalId::new(id, limits.max_local_id_bytes))
                .transpose()?,
        });
    }
    let bundle = AdvisoryBundle {
        local_bundle_id,
        entities: entities.into_values().collect(),
        claims,
        metadata,
    };
    bundle.validate_shape(limits)?;
    Ok(bundle)
}

fn convert_entity(
    value: &crate::parser::EntityRef,
    limits: &CandidateLimits,
) -> Result<EntityCandidate> {
    EntityCandidate::new(
        LocalId::new(&value.entity_id, limits.max_local_id_bytes)?,
        &value.spelling,
        Iri::new(&value.type_iri)?,
        limits,
    )
}

fn insert_entity(
    entities: &mut BTreeMap<LocalId, EntityCandidate>,
    entity: EntityCandidate,
) -> Result<()> {
    if let Some(previous) = entities.insert(entity.local_id().clone(), entity.clone()) {
        if previous != entity {
            return Err(Error::invalid("conflicting local entity definition"));
        }
    }
    Ok(())
}

fn convert_coordinate(value: &Coordinate) -> Result<LineCoordinate> {
    let selection = match (value.start, value.end, value.whole_line) {
        (Some(start), Some(end), None) => LineSelection::Range { start, end },
        (None, None, Some(true)) => LineSelection::WholeLine,
        _ => return Err(Error::invalid("provider coordinate shape")),
    };
    Ok(LineCoordinate {
        line_id: LineId::from_host(&value.line_id)?,
        selection,
    })
}
