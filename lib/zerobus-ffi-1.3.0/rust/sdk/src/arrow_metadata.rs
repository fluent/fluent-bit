//! Metadata types for Arrow Flight offset tracking and acknowledgements.
//!
//! Arrow Flight uses the `app_metadata` field in `FlightData` and `PutResult`
//! messages to carry application-specific metadata. We use this for offset
//! tracking (similar to the existing gRPC/HTTP APIs).

use serde::{Deserialize, Serialize};

use crate::errors::ZerobusError;
use crate::offset_generator::OffsetId;
use crate::ZerobusResult;

/// Sentinel offset value indicating stream setup is complete but no batches have been acked yet.
/// The server sends this as the first `PutResult` after successful setup.
pub const STREAM_READY_OFFSET: OffsetId = -1;

/// Metadata sent with each FlightData batch from the client.
///
/// This is serialized to JSON and sent in `FlightData.app_metadata`.
/// The offset_id tracks the position in the stream for acknowledgements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightBatchMetadata {
    /// Client-provided offset ID for this batch.
    /// Must be strictly sequential starting from 0 (0, 1, 2, ...).
    pub offset_id: OffsetId,
}

impl FlightBatchMetadata {
    /// Create new batch metadata with the given offset ID.
    pub fn new(offset_id: OffsetId) -> Self {
        Self { offset_id }
    }

    /// Serialize to JSON bytes for FlightData.app_metadata.
    #[allow(clippy::result_large_err)]
    pub fn to_bytes(&self) -> ZerobusResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            ZerobusError::InvalidArgument(format!("Failed to serialize FlightBatchMetadata: {}", e))
        })
    }

    /// Deserialize from FlightData.app_metadata bytes.
    #[cfg(test)]
    #[allow(clippy::result_large_err)]
    pub fn from_bytes(bytes: &[u8]) -> ZerobusResult<Self> {
        if bytes.is_empty() {
            return Err(ZerobusError::InvalidArgument(
                "Empty app_metadata in FlightData - client must provide offset_id".to_string(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|e| {
            ZerobusError::InvalidArgument(format!("Failed to parse FlightBatchMetadata: {}", e))
        })
    }
}

/// Acknowledgement metadata sent back to the client.
///
/// This is serialized to JSON and sent in `PutResult.app_metadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightAckMetadata {
    /// Offset ID up to which records are durably stored.
    /// All records with offset_id <= this value are guaranteed durable.
    ///
    /// Special value [`STREAM_READY_OFFSET`] indicates a "ready" signal: stream setup succeeded
    /// (schema validation, table access) but no batches acked yet.
    /// The SDK waits for this signal during stream creation.
    pub ack_up_to_offset: OffsetId,
    /// Cumulative count of records durably stored up to this acknowledgment.
    pub ack_up_to_records: u64,
    /// Optional close stream signal with grace period duration in milliseconds.
    ///
    /// When present, the server is signaling that it will close the stream after
    /// this duration. The client should enter a "paused" state: stop sending new
    /// batches but continue processing acknowledgments for in-flight batches.
    /// After the grace period (or when all in-flight batches are acked), the client
    /// triggers stream recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub close_stream_duration_ms: Option<u64>,
}

impl FlightAckMetadata {
    /// Create new acknowledgement metadata.
    #[allow(dead_code)]
    pub fn new(ack_up_to_offset: OffsetId, ack_up_to_records: u64) -> Self {
        Self {
            ack_up_to_offset,
            ack_up_to_records,
            close_stream_duration_ms: None,
        }
    }

    /// Create a "stream ready" signal indicating successful stream setup.
    /// Uses [`STREAM_READY_OFFSET`] as the offset value.
    #[allow(dead_code)]
    pub fn stream_ready() -> Self {
        Self {
            ack_up_to_offset: STREAM_READY_OFFSET,
            ack_up_to_records: 0,
            close_stream_duration_ms: None,
        }
    }

    /// Returns true if this message contains a close stream signal.
    pub fn is_close_signal(&self) -> bool {
        self.close_stream_duration_ms.is_some()
    }

    /// Returns true if this is a stream ready signal (setup complete, no batches acked).
    pub fn is_stream_ready(&self) -> bool {
        self.ack_up_to_offset == STREAM_READY_OFFSET
    }

    /// Deserialize from PutResult.app_metadata bytes.
    #[allow(clippy::result_large_err)]
    pub fn from_bytes(bytes: &[u8]) -> ZerobusResult<Self> {
        if bytes.is_empty() {
            return Err(ZerobusError::InvalidArgument(
                "Empty app_metadata in PutResult - server should provide ack offset".to_string(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|e| {
            ZerobusError::InvalidArgument(format!("Failed to parse FlightAckMetadata: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flight_batch_metadata_roundtrip() {
        let metadata = FlightBatchMetadata::new(42);
        let bytes = metadata.to_bytes().unwrap();
        let parsed = FlightBatchMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.offset_id, 42);
    }

    #[test]
    fn test_flight_batch_metadata_parse() {
        let json = r#"{"offset_id": 42}"#;
        let parsed = FlightBatchMetadata::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(parsed.offset_id, 42);
    }

    #[test]
    fn test_flight_batch_metadata_empty_error() {
        let result = FlightBatchMetadata::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_flight_ack_metadata_parse_with_records() {
        let json = r#"{"ack_up_to_offset": 99, "ack_up_to_records": 5000}"#;
        let parsed = FlightAckMetadata::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(parsed.ack_up_to_offset, 99);
        assert_eq!(parsed.ack_up_to_records, 5000);
        assert!(parsed.close_stream_duration_ms.is_none());
        assert!(!parsed.is_close_signal());
    }

    #[test]
    fn test_flight_ack_metadata_with_close_signal() {
        let json = r#"{"ack_up_to_offset": 5, "ack_up_to_records": 100, "close_stream_duration_ms": 2000}"#;
        let parsed = FlightAckMetadata::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(parsed.ack_up_to_offset, 5);
        assert_eq!(parsed.ack_up_to_records, 100);
        assert_eq!(parsed.close_stream_duration_ms, Some(2000));
        assert!(parsed.is_close_signal());
    }

    #[test]
    fn test_flight_ack_metadata_close_signal_only() {
        let json =
            r#"{"ack_up_to_offset": -1, "ack_up_to_records": 0, "close_stream_duration_ms": 5000}"#;
        let parsed = FlightAckMetadata::from_bytes(json.as_bytes()).unwrap();
        assert!(parsed.is_close_signal());
        assert!(parsed.is_stream_ready());
        assert_eq!(parsed.close_stream_duration_ms, Some(5000));
    }

    #[test]
    fn test_flight_ack_metadata_empty_error() {
        let result = FlightAckMetadata::from_bytes(&[]);
        assert!(result.is_err());
    }
}
