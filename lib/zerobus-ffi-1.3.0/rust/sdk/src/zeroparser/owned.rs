//! Owned, self-referential wrapper around `ParsedMessage`.
//!
//! `ParsedMessage<'a>` borrows from two backing storages: the encoded protobuf
//! bytes and the descriptor cache owned by a `MessageRegistry`. Carrying it
//! across an API boundary that needs to outlive both borrows requires a
//! self-referential container. `OwnedParsedMessage` is that container, built
//! on top of the `self_cell` crate which provides a safe abstraction for
//! self-referential structs without any hand-rolled `unsafe`.

use std::sync::Arc;

use self_cell::self_cell;

use super::errors::ParseError;
use super::parser::ParsedMessage;
use super::registry::MessageRegistry;

/// Owns the encoded bytes and the registry referenced by a `ParsedMessage`.
///
/// The fields are kept `Vec<u8>` and `Arc<MessageRegistry>` so their backing
/// addresses are stable across moves of the enclosing struct.
struct Owner {
    bytes: Vec<u8>,
    registry: Arc<MessageRegistry>,
}

self_cell!(
    struct OwnedParsedMessageInner {
        owner: Owner,

        #[covariant]
        dependent: ParsedMessage,
    }
);

/// Self-referential wrapper that owns the encoded bytes and registry, plus a
/// `ParsedMessage` view into them. Built on `self_cell` for safety.
pub struct OwnedParsedMessage {
    inner: OwnedParsedMessageInner,
}

impl OwnedParsedMessage {
    /// Parses `bytes` using `registry` and stores both alongside the parsed
    /// view in a single self-referential value.
    ///
    /// On parse failure, returns the original `bytes` alongside the error so
    /// callers on the ingestion hot path can fall back to a different parser
    /// without re-cloning the encoded record.
    pub fn parse(
        bytes: Vec<u8>,
        registry: Arc<MessageRegistry>,
    ) -> Result<Self, (ParseError, Vec<u8>)> {
        let owner = Owner { bytes, registry };
        match OwnedParsedMessageInner::try_new_or_recover(owner, |owner| {
            ParsedMessage::parse(&owner.bytes, &owner.registry)
        }) {
            Ok(inner) => Ok(Self { inner }),
            Err((owner, err)) => Err((err, owner.bytes)),
        }
    }

    /// Returns a reference to the parsed message, bound to the lifetime of `self`.
    #[inline]
    pub fn parsed(&self) -> &ParsedMessage<'_> {
        self.inner.borrow_dependent()
    }

    /// Returns the encoded bytes that were parsed.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.inner.borrow_owner().bytes
    }

    /// Consumes `self` and returns the original encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner.into_owner().bytes
    }
}

impl std::fmt::Debug for OwnedParsedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedParsedMessage")
            .field("bytes_len", &self.bytes().len())
            .field("parsed", self.parsed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use prost_types::DescriptorProto;

    use super::*;

    fn make_registry() -> Arc<MessageRegistry> {
        let descriptor = DescriptorProto {
            name: Some("Empty".to_string()),
            ..Default::default()
        };
        Arc::new(MessageRegistry::from_descriptor(&descriptor))
    }

    #[test]
    fn parse_and_access_round_trip() {
        let registry = make_registry();
        let bytes = vec![];
        let owned = OwnedParsedMessage::parse(bytes.clone(), Arc::clone(&registry)).unwrap();
        assert_eq!(owned.bytes(), bytes.as_slice());
        let _ = owned.parsed();
    }

    #[test]
    fn into_bytes_returns_original() {
        let registry = make_registry();
        let bytes = vec![];
        let owned = OwnedParsedMessage::parse(bytes.clone(), registry).unwrap();
        assert_eq!(owned.into_bytes(), bytes);
    }

    // Field 1 (tag 0x08), varint value 42 (0x2A). Empty descriptor ignores
    // unknown fields per protobuf spec, so this parses successfully while
    // exercising a non-trivial payload.
    const NON_TRIVIAL_BYTES: &[u8] = &[0x08, 0x2A];

    #[test]
    fn bytes_returns_parsed_payload() {
        let registry = make_registry();
        let owned = OwnedParsedMessage::parse(NON_TRIVIAL_BYTES.to_vec(), registry).unwrap();
        assert_eq!(owned.bytes(), NON_TRIVIAL_BYTES);
    }

    #[test]
    fn into_bytes_round_trip_non_empty() {
        let registry = make_registry();
        let owned = OwnedParsedMessage::parse(NON_TRIVIAL_BYTES.to_vec(), registry).unwrap();
        assert_eq!(owned.into_bytes(), NON_TRIVIAL_BYTES);
    }

    #[test]
    fn parse_error_recovers_bytes() {
        let registry = make_registry();
        // Tag byte (1 << 3) | 6 = 0x0E declares wire type 6, which is invalid
        // and triggers ParseError::InvalidWireType regardless of descriptor.
        let invalid = vec![0x0Eu8];
        let (err, recovered) = OwnedParsedMessage::parse(invalid.clone(), registry).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidWireType(6)),
            "unexpected error: {err:?}"
        );
        assert_eq!(recovered, invalid);
    }
}
