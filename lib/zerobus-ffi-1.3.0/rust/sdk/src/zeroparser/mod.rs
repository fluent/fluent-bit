//! Zero-copy, single-pass protobuf parser driven by a [`prost_types::DescriptorProto`].
//!
//! Parses nested messages in one O(N) traversal; all string and byte values
//! borrow from the input buffer. Designed for ingestion paths where the schema
//! is only known at runtime but per-record allocations need to stay flat.
//!
//! ```no_run
//! use prost_types::DescriptorProto;
//! use databricks_zerobus_ingest_sdk::zeroparser::{
//!     parser::ParsedMessage, types::FieldValueRef, MessageRegistry, ParseResult,
//! };
//!
//! # fn run(descriptor: DescriptorProto, bytes: &[u8]) -> ParseResult<()> {
//! let registry = MessageRegistry::from_descriptor(&descriptor);
//! let parsed = ParsedMessage::parse(bytes, &registry)?;
//! if let Some(FieldValueRef::String(s)) = parsed.get_scalar(1) {
//!     println!("field 1 = {s}");
//! }
//! # Ok(()) }
//! ```

mod errors;
mod owned;
pub mod parser;
mod registry;
mod sparse_field_map;
pub mod types;
pub mod wire;

pub use errors::{ParseError, ParseResult};
pub use owned::OwnedParsedMessage;
pub use registry::MessageRegistry;
