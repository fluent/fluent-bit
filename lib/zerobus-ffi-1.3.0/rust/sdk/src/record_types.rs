//! Record types and wrappers for the Zerobus SDK.
//!
//! This module contains all the types related to encoding records for ingestion:
//! - [`EncodedRecord`] - The core enum for encoded records (JSON or Proto)
//! - [`EncodedBatch`] - A batch of encoded records
//! - Wrapper types for ergonomic record creation:
//!   - [`ProtoBytes`] - For pre-serialized protobuf bytes (you handle serialization)
//!   - [`JsonString`] - For pre-serialized JSON strings (you handle serialization)
//!   - [`ProtoMessage`] - For protobuf messages (SDK handles serialization automatically)
//!   - [`JsonValue`] - For JSON-serializable objects (SDK handles serialization automatically)

use prost::Message;
use smallvec::{smallvec, SmallVec};

use crate::databricks::zerobus::{
    ephemeral_stream_request::Payload as RequestPayload,
    ingest_record_batch_request::Batch as IngestRequestBatch,
    ingest_record_request::Record as IngestRequestRecord, IngestRecordBatchRequest,
    IngestRecordRequest, JsonRecordBatch, ProtoEncodedRecordBatch, RecordType,
};
use crate::OffsetId;

/// A type alias for a protobuf-encoded record.
pub type ProtoEncodedRecord = Vec<u8>;

/// A type alias for a JSON-encoded record.
pub type JsonEncodedRecord = String;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncodedRecord {
    Json(JsonEncodedRecord),
    Proto(ProtoEncodedRecord),
}

impl From<ProtoEncodedRecord> for EncodedRecord {
    fn from(v: ProtoEncodedRecord) -> Self {
        EncodedRecord::Proto(v)
    }
}

impl From<JsonEncodedRecord> for EncodedRecord {
    fn from(s: JsonEncodedRecord) -> Self {
        EncodedRecord::Json(s)
    }
}

/// Wrapper for pre-serialized protobuf bytes.
///
/// Use this when you've already serialized the protobuf data yourself.
/// This is optional - you can also pass `Vec<u8>` directly.
///
/// # Examples
///
/// ```no_run
/// # use databricks_zerobus_ingest_sdk::{ZerobusStream, ProtoBytes};
/// # async fn example(stream: &ZerobusStream) -> Result<(), Box<dyn std::error::Error>> {
/// let proto_bytes = vec![1, 2, 3, 4];
/// let offset = stream.ingest_record_offset(ProtoBytes(proto_bytes)).await?;
/// stream.wait_for_offset(offset).await?;
/// # Ok(())
/// # }
/// ```
pub struct ProtoBytes(pub Vec<u8>);

impl From<ProtoBytes> for EncodedRecord {
    fn from(bytes: ProtoBytes) -> Self {
        EncodedRecord::Proto(bytes.0)
    }
}

/// Wrapper for pre-serialized JSON strings.
///
/// Use this when you've already serialized the JSON data yourself.
/// This is optional - you can also pass `String` directly.
///
/// # Examples
///
/// ```no_run
/// # use databricks_zerobus_ingest_sdk::{ZerobusStream, JsonString};
/// # async fn example(stream: &ZerobusStream) -> Result<(), Box<dyn std::error::Error>> {
/// let json_str = r#"{"name":"test","value":42}"#.to_string();
/// let offset = stream.ingest_record_offset(JsonString(json_str)).await?;
/// stream.wait_for_offset(offset).await?;
/// # Ok(())
/// # }
/// ```
pub struct JsonString(pub String);

impl From<JsonString> for EncodedRecord {
    fn from(s: JsonString) -> Self {
        EncodedRecord::Json(s.0)
    }
}

/// Wrapper for protobuf messages with automatic serialization.
///
/// Use this when you want the SDK to handle serialization for you.
/// Pass any protobuf message that implements `prost::Message` and it will be
/// automatically serialized to bytes.
///
/// # Examples
///
/// ```no_run
/// # use databricks_zerobus_ingest_sdk::{ZerobusStream, ProtoMessage};
/// # async fn example(stream: &ZerobusStream, my_proto_msg: impl prost::Message) -> Result<(), Box<dyn std::error::Error>> {
/// // Ingest a protobuf message - it will be automatically serialized
/// let offset = stream.ingest_record_offset(ProtoMessage(my_proto_msg)).await?;
/// stream.wait_for_offset(offset).await?;
/// # Ok(())
/// # }
/// ```
pub struct ProtoMessage<T: Message>(pub T);

impl<T: Message> From<ProtoMessage<T>> for EncodedRecord {
    fn from(msg: ProtoMessage<T>) -> Self {
        EncodedRecord::Proto(msg.0.encode_to_vec())
    }
}

/// Wrapper for JSON-serializable objects with automatic serialization.
///
/// Use this when you want the SDK to handle serialization for you.
/// Pass any Rust struct that implements `serde::Serialize` and it will be
/// automatically serialized to a JSON string.
///
/// # Examples
///
/// ```no_run
/// # use databricks_zerobus_ingest_sdk::{ZerobusStream, JsonValue};
/// # use serde::Serialize;
/// # async fn example(stream: &ZerobusStream) -> Result<(), Box<dyn std::error::Error>> {
/// #[derive(Serialize)]
/// struct MyData {
///     name: String,
///     value: i32,
/// }
///
/// let my_data = MyData { name: "test".into(), value: 42 };
/// // Ingest a JSON object - it will be automatically serialized
/// let offset = stream.ingest_record_offset(JsonValue(my_data)).await?;
/// stream.wait_for_offset(offset).await?;
/// # Ok(())
/// # }
/// ```
pub struct JsonValue<T: serde::Serialize>(pub T);

impl<T: serde::Serialize> From<JsonValue<T>> for EncodedRecord {
    fn from(obj: JsonValue<T>) -> Self {
        let json_string = serde_json::to_string(&obj.0).expect(
            "Failed to serialize to JSON - ensure your type implements serde::Serialize correctly",
        );
        EncodedRecord::Json(json_string)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncodedBatch {
    Proto(SmallVec<[ProtoEncodedRecord; 1]>),
    Json(SmallVec<[JsonEncodedRecord; 1]>),
}

impl EncodedBatch {
    /// Try to convert a single record into an encoded batch of the provided type.
    /// If the record type does not match the provided type, None is returned.
    pub(crate) fn try_from_record<T: Into<EncodedRecord>>(
        value: T,
        record_type: RecordType,
    ) -> Option<Self> {
        match (value.into(), record_type) {
            (EncodedRecord::Json(s), RecordType::Json) => Some(EncodedBatch::Json(smallvec![s])),
            (EncodedRecord::Proto(v), RecordType::Proto) => Some(EncodedBatch::Proto(smallvec![v])),
            _ => None,
        }
    }

    /// Try to convert records into an encoded batch of the provided type.
    /// If the record type does not match the records' type, None is returned.
    /// The returned batch will be empty if no records are provided.
    pub(crate) fn try_from_batch<B, R>(batch: B, record_type: RecordType) -> Option<Self>
    where
        B: IntoIterator<Item = R>,
        R: Into<EncodedRecord>,
    {
        let mut batch_iter = batch.into_iter();
        let (lower, upper) = batch_iter.size_hint();
        let size_hint = upper.unwrap_or(lower);

        match record_type {
            RecordType::Json => batch_iter
                .try_fold(
                    SmallVec::with_capacity(size_hint),
                    |mut vec, record| match record.into() {
                        EncodedRecord::Json(value) => {
                            vec.push(value);
                            Some(vec)
                        }
                        _ => None,
                    },
                )
                .map(EncodedBatch::Json),
            RecordType::Proto => batch_iter
                .try_fold(
                    SmallVec::with_capacity(size_hint),
                    |mut vec, record| match record.into() {
                        EncodedRecord::Proto(value) => {
                            vec.push(value);
                            Some(vec)
                        }
                        _ => None,
                    },
                )
                .map(EncodedBatch::Proto),
            _ => None,
        }
    }

    pub(crate) fn into_request_payload(self, offset_id: OffsetId) -> RequestPayload {
        match self {
            EncodedBatch::Proto(records) if records.len() == 1 => {
                RequestPayload::IngestRecord(IngestRecordRequest {
                    record: Some(IngestRequestRecord::ProtoEncodedRecord(
                        records.into_iter().next().unwrap(),
                    )),
                    offset_id: Some(offset_id),
                })
            }
            EncodedBatch::Proto(records) => {
                RequestPayload::IngestRecordBatch(IngestRecordBatchRequest {
                    batch: Some(IngestRequestBatch::ProtoEncodedBatch(
                        ProtoEncodedRecordBatch {
                            records: records.into_vec(),
                        },
                    )),
                    offset_id: Some(offset_id),
                })
            }
            EncodedBatch::Json(records) if records.len() == 1 => {
                RequestPayload::IngestRecord(IngestRecordRequest {
                    record: Some(IngestRequestRecord::JsonRecord(
                        records.into_iter().next().unwrap(),
                    )),
                    offset_id: Some(offset_id),
                })
            }
            EncodedBatch::Json(records) => {
                RequestPayload::IngestRecordBatch(IngestRecordBatchRequest {
                    batch: Some(IngestRequestBatch::JsonBatch(JsonRecordBatch {
                        records: records.into_vec(),
                    })),
                    offset_id: Some(offset_id),
                })
            }
        }
    }

    /// Returns the number of records in this batch.
    pub fn get_record_count(&self) -> usize {
        match self {
            EncodedBatch::Proto(records) => records.len(),
            EncodedBatch::Json(records) => records.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.get_record_count() == 0
    }
}

impl IntoIterator for EncodedBatch {
    type Item = EncodedRecord;
    type IntoIter = EncodedBatchIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            EncodedBatch::Proto(records) => EncodedBatchIter::Proto(records.into_iter()),
            EncodedBatch::Json(records) => EncodedBatchIter::Json(records.into_iter()),
        }
    }
}

pub enum EncodedBatchIter {
    Proto(smallvec::IntoIter<[ProtoEncodedRecord; 1]>),
    Json(smallvec::IntoIter<[JsonEncodedRecord; 1]>),
}

impl Iterator for EncodedBatchIter {
    type Item = EncodedRecord;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EncodedBatchIter::Proto(iter) => iter.next().map(EncodedRecord::Proto),
            EncodedBatchIter::Json(iter) => iter.next().map(EncodedRecord::Json),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            EncodedBatchIter::Proto(iter) => iter.size_hint(),
            EncodedBatchIter::Json(iter) => iter.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as ProstMessage;
    use serde::Serialize;
    use smallvec::smallvec;

    #[derive(Clone, PartialEq, ProstMessage)]
    struct TestMessage {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(int32, tag = "2")]
        value: i32,
    }

    #[derive(Serialize, PartialEq, Debug)]
    struct TestData {
        name: String,
        value: i32,
    }

    mod encoded_record_conversions {
        use super::*;

        #[test]
        fn test_vec_u8_to_encoded_record() {
            let bytes = vec![1, 2, 3, 4, 5];
            let record: EncodedRecord = bytes.clone().into();

            match record {
                EncodedRecord::Proto(data) => assert_eq!(data, bytes),
                _ => panic!("Expected Proto variant"),
            }
        }

        #[test]
        fn test_proto_bytes_to_encoded_record() {
            let bytes = vec![1, 2, 3, 4, 5];
            let proto_bytes = ProtoBytes(bytes.clone());
            let record: EncodedRecord = proto_bytes.into();

            match record {
                EncodedRecord::Proto(data) => assert_eq!(data, bytes),
                _ => panic!("Expected Proto variant"),
            }
        }

        #[test]
        fn test_proto_message_to_encoded_record() {
            let message = TestMessage {
                name: "test".to_string(),
                value: 42,
            };
            let expected_bytes = message.encode_to_vec();

            let proto_message = ProtoMessage(message.clone());
            let record: EncodedRecord = proto_message.into();

            match record {
                EncodedRecord::Proto(data) => {
                    assert_eq!(data, expected_bytes);
                    let decoded = TestMessage::decode(&data[..]).unwrap();
                    assert_eq!(decoded, message);
                }
                _ => panic!("Expected Proto variant"),
            }
        }

        #[test]
        fn test_string_to_encoded_record() {
            let json_str = r#"{"name":"test","value":42}"#.to_string();
            let record: EncodedRecord = json_str.clone().into();

            match record {
                EncodedRecord::Json(data) => assert_eq!(data, json_str),
                _ => panic!("Expected Json variant"),
            }
        }

        #[test]
        fn test_json_string_to_encoded_record() {
            let json_str = r#"{"name":"test","value":42}"#.to_string();
            let json_string = JsonString(json_str.clone());
            let record: EncodedRecord = json_string.into();

            match record {
                EncodedRecord::Json(data) => assert_eq!(data, json_str),
                _ => panic!("Expected Json variant"),
            }
        }

        #[test]
        fn test_json_value_to_encoded_record() {
            let test_data = TestData {
                name: "test".to_string(),
                value: 42,
            };

            let json_value = JsonValue(test_data);
            let record: EncodedRecord = json_value.into();

            match record {
                EncodedRecord::Json(data) => {
                    let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
                    assert_eq!(parsed["name"], "test");
                    assert_eq!(parsed["value"], 42);
                }
                _ => panic!("Expected Json variant"),
            }
        }

        #[test]
        fn test_wrapper_types_are_zero_cost() {
            use std::mem::size_of;

            assert_eq!(size_of::<ProtoBytes>(), size_of::<Vec<u8>>());
            assert_eq!(size_of::<JsonString>(), size_of::<String>());
        }
    }

    mod encoded_batch_try_from {
        use super::*;

        #[test]
        fn test_try_from_record_json_with_json_type() {
            let json_str = r#"{"id": 1}"#.to_string();
            let batch = EncodedBatch::try_from_record(json_str.clone(), RecordType::Json);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            assert_eq!(batch.get_record_count(), 1);
            match batch {
                EncodedBatch::Json(records) => assert_eq!(records[0], json_str),
                _ => panic!("Expected Json batch"),
            }
        }

        #[test]
        fn test_try_from_record_proto_with_proto_type() {
            let bytes = vec![1, 2, 3];
            let batch = EncodedBatch::try_from_record(bytes.clone(), RecordType::Proto);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            assert_eq!(batch.get_record_count(), 1);
            match batch {
                EncodedBatch::Proto(records) => assert_eq!(records[0], bytes),
                _ => panic!("Expected Proto batch"),
            }
        }

        #[test]
        fn test_try_from_record_json_with_proto_type_fails() {
            let json_str = r#"{"id": 1}"#.to_string();
            let batch = EncodedBatch::try_from_record(json_str, RecordType::Proto);

            assert!(batch.is_none());
        }

        #[test]
        fn test_try_from_record_proto_with_json_type_fails() {
            let bytes = vec![1, 2, 3];
            let batch = EncodedBatch::try_from_record(bytes, RecordType::Json);

            assert!(batch.is_none());
        }

        #[test]
        fn test_try_from_record_with_json_string_wrapper() {
            let json_str = JsonString(r#"{"id": 1}"#.to_string());
            let batch = EncodedBatch::try_from_record(json_str, RecordType::Json);

            assert!(batch.is_some());
            assert_eq!(batch.unwrap().get_record_count(), 1);
        }

        #[test]
        fn test_try_from_record_with_proto_bytes_wrapper() {
            let proto_bytes = ProtoBytes(vec![1, 2, 3]);
            let batch = EncodedBatch::try_from_record(proto_bytes, RecordType::Proto);

            assert!(batch.is_some());
            assert_eq!(batch.unwrap().get_record_count(), 1);
        }

        #[test]
        fn test_try_from_record_with_json_value_wrapper() {
            let test_data = TestData {
                name: "test".to_string(),
                value: 42,
            };
            let batch = EncodedBatch::try_from_record(JsonValue(test_data), RecordType::Json);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            match batch {
                EncodedBatch::Json(records) => {
                    let parsed: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
                    assert_eq!(parsed["name"], "test");
                }
                _ => panic!("Expected Json batch"),
            }
        }

        #[test]
        fn test_try_from_record_with_proto_message_wrapper() {
            let message = TestMessage {
                name: "test".to_string(),
                value: 42,
            };
            let batch =
                EncodedBatch::try_from_record(ProtoMessage(message.clone()), RecordType::Proto);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            match batch {
                EncodedBatch::Proto(records) => {
                    let decoded = TestMessage::decode(&records[0][..]).unwrap();
                    assert_eq!(decoded, message);
                }
                _ => panic!("Expected Proto batch"),
            }
        }

        #[test]
        fn test_try_from_batch_json_records() {
            let records = vec![
                r#"{"id": 1}"#.to_string(),
                r#"{"id": 2}"#.to_string(),
                r#"{"id": 3}"#.to_string(),
            ];
            let batch = EncodedBatch::try_from_batch(records.clone(), RecordType::Json);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            assert_eq!(batch.get_record_count(), 3);
            match batch {
                EncodedBatch::Json(batch_records) => {
                    assert_eq!(batch_records.as_slice(), records.as_slice());
                }
                _ => panic!("Expected Json batch"),
            }
        }

        #[test]
        fn test_try_from_batch_proto_records() {
            let records = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
            let batch = EncodedBatch::try_from_batch(records.clone(), RecordType::Proto);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            assert_eq!(batch.get_record_count(), 3);
            match batch {
                EncodedBatch::Proto(batch_records) => {
                    assert_eq!(batch_records.as_slice(), records.as_slice());
                }
                _ => panic!("Expected Proto batch"),
            }
        }

        #[test]
        fn test_try_from_batch_empty() {
            let records: Vec<String> = vec![];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Json);

            assert!(batch.is_some());
            let batch = batch.unwrap();
            assert!(batch.is_empty());
        }

        #[test]
        fn test_try_from_batch_json_with_proto_type_fails() {
            let records = vec![r#"{"id": 1}"#.to_string(), r#"{"id": 2}"#.to_string()];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Proto);

            assert!(batch.is_none());
        }

        #[test]
        fn test_try_from_batch_proto_with_json_type_fails() {
            let records = vec![vec![1, 2], vec![3, 4]];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Json);

            assert!(batch.is_none());
        }

        #[test]
        fn test_try_from_batch_with_json_string_wrappers() {
            let records = vec![
                JsonString(r#"{"id": 1}"#.to_string()),
                JsonString(r#"{"id": 2}"#.to_string()),
            ];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Json);

            assert!(batch.is_some());
            assert_eq!(batch.unwrap().get_record_count(), 2);
        }

        #[test]
        fn test_try_from_batch_with_proto_bytes_wrappers() {
            let records = vec![ProtoBytes(vec![1, 2]), ProtoBytes(vec![3, 4])];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Proto);

            assert!(batch.is_some());
            assert_eq!(batch.unwrap().get_record_count(), 2);
        }

        #[test]
        fn test_try_from_batch_with_json_value_wrappers() {
            let records = vec![
                JsonValue(TestData {
                    name: "a".to_string(),
                    value: 1,
                }),
                JsonValue(TestData {
                    name: "b".to_string(),
                    value: 2,
                }),
            ];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Json);

            assert!(batch.is_some());
            assert_eq!(batch.unwrap().get_record_count(), 2);
        }

        #[test]
        fn test_try_from_batch_with_proto_message_wrappers() {
            let records = vec![
                ProtoMessage(TestMessage {
                    name: "a".to_string(),
                    value: 1,
                }),
                ProtoMessage(TestMessage {
                    name: "b".to_string(),
                    value: 2,
                }),
            ];
            let batch = EncodedBatch::try_from_batch(records, RecordType::Proto);

            assert!(batch.is_some());
            assert_eq!(batch.unwrap().get_record_count(), 2);
        }
    }

    mod encoded_batch_methods {
        use super::*;

        #[test]
        fn test_get_record_count() {
            let proto_batch = EncodedBatch::Proto(smallvec![vec![1], vec![2], vec![3]]);
            assert_eq!(proto_batch.get_record_count(), 3);

            let json_batch = EncodedBatch::Json(smallvec!["a".to_string(), "b".to_string()]);
            assert_eq!(json_batch.get_record_count(), 2);

            let empty_batch = EncodedBatch::Proto(smallvec![]);
            assert_eq!(empty_batch.get_record_count(), 0);
        }

        #[test]
        fn test_is_empty() {
            let non_empty = EncodedBatch::Proto(smallvec![vec![1]]);
            assert!(!non_empty.is_empty());

            let empty = EncodedBatch::Json(smallvec![]);
            assert!(empty.is_empty());
        }

        #[test]
        fn test_into_request_payload_single_proto_record() {
            let record = vec![1, 2, 3];
            let batch = EncodedBatch::Proto(smallvec![record.clone()]);
            let payload = batch.into_request_payload(42);

            match payload {
                RequestPayload::IngestRecord(req) => {
                    assert_eq!(req.offset_id, Some(42));
                    match req.record {
                        Some(IngestRequestRecord::ProtoEncodedRecord(data)) => {
                            assert_eq!(data, record);
                        }
                        _ => panic!("Expected ProtoEncodedRecord"),
                    }
                }
                _ => panic!("Expected IngestRecord payload"),
            }
        }

        #[test]
        fn test_into_request_payload_single_json_record() {
            let record = r#"{"id": 1}"#.to_string();
            let batch = EncodedBatch::Json(smallvec![record.clone()]);
            let payload = batch.into_request_payload(123);

            match payload {
                RequestPayload::IngestRecord(req) => {
                    assert_eq!(req.offset_id, Some(123));
                    match req.record {
                        Some(IngestRequestRecord::JsonRecord(data)) => {
                            assert_eq!(data, record);
                        }
                        _ => panic!("Expected JsonRecord"),
                    }
                }
                _ => panic!("Expected IngestRecord payload"),
            }
        }

        #[test]
        fn test_into_request_payload_batch_proto() {
            let records = vec![vec![1, 2, 3], vec![4, 5, 6]];
            let batch = EncodedBatch::Proto(SmallVec::from_vec(records.clone()));
            let payload = batch.into_request_payload(99);

            match payload {
                RequestPayload::IngestRecordBatch(req) => {
                    assert_eq!(req.offset_id, Some(99));
                    match req.batch {
                        Some(IngestRequestBatch::ProtoEncodedBatch(proto_batch)) => {
                            assert_eq!(proto_batch.records, records);
                        }
                        _ => panic!("Expected ProtoEncodedBatch"),
                    }
                }
                _ => panic!("Expected IngestRecordBatch payload"),
            }
        }

        #[test]
        fn test_into_request_payload_batch_json() {
            let records = vec![r#"{"id": 1}"#.to_string(), r#"{"id": 2}"#.to_string()];
            let batch = EncodedBatch::Json(SmallVec::from_vec(records.clone()));
            let payload = batch.into_request_payload(77);

            match payload {
                RequestPayload::IngestRecordBatch(req) => {
                    assert_eq!(req.offset_id, Some(77));
                    match req.batch {
                        Some(IngestRequestBatch::JsonBatch(json_batch)) => {
                            assert_eq!(json_batch.records, records);
                        }
                        _ => panic!("Expected JsonBatch"),
                    }
                }
                _ => panic!("Expected IngestRecordBatch payload"),
            }
        }
    }

    mod encoded_batch_iter {
        use super::*;

        #[test]
        fn test_iter_proto_batch() {
            let records = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
            let batch = EncodedBatch::Proto(SmallVec::from_vec(records.clone()));

            let collected: Vec<EncodedRecord> = batch.into_iter().collect();
            assert_eq!(collected.len(), 3);

            for (i, record) in collected.iter().enumerate() {
                match record {
                    EncodedRecord::Proto(data) => assert_eq!(data, &records[i]),
                    _ => panic!("Expected Proto variant"),
                }
            }
        }

        #[test]
        fn test_iter_json_batch() {
            let records = vec!["a".to_string(), "b".to_string(), "c".to_string()];
            let batch = EncodedBatch::Json(SmallVec::from_vec(records.clone()));

            let collected: Vec<EncodedRecord> = batch.into_iter().collect();
            assert_eq!(collected.len(), 3);

            for (i, record) in collected.iter().enumerate() {
                match record {
                    EncodedRecord::Json(data) => assert_eq!(data, &records[i]),
                    _ => panic!("Expected Json variant"),
                }
            }
        }

        #[test]
        fn test_iter_empty_batch() {
            let batch = EncodedBatch::Proto(smallvec![]);
            let collected: Vec<EncodedRecord> = batch.into_iter().collect();
            assert!(collected.is_empty());
        }

        #[test]
        fn test_iter_size_hint() {
            let batch = EncodedBatch::Proto(smallvec![vec![1], vec![2], vec![3]]);
            let iter = batch.into_iter();
            assert_eq!(iter.size_hint(), (3, Some(3)));
        }

        #[test]
        fn test_iter_size_hint_decreases() {
            let batch = EncodedBatch::Json(smallvec!["a".to_string(), "b".to_string()]);
            let mut iter = batch.into_iter();

            assert_eq!(iter.size_hint(), (2, Some(2)));
            iter.next();
            assert_eq!(iter.size_hint(), (1, Some(1)));
            iter.next();
            assert_eq!(iter.size_hint(), (0, Some(0)));
        }
    }

    mod batch_conversions {
        use super::*;

        #[test]
        fn test_batch_with_proto_messages() {
            let msg1 = TestMessage {
                name: "msg1".to_string(),
                value: 1,
            };
            let msg2 = TestMessage {
                name: "msg2".to_string(),
                value: 2,
            };

            let batch: Vec<ProtoMessage<TestMessage>> =
                vec![ProtoMessage(msg1.clone()), ProtoMessage(msg2.clone())];

            let records: Vec<EncodedRecord> = batch.into_iter().map(|m| m.into()).collect();

            assert_eq!(records.len(), 2);
            for (i, record) in records.iter().enumerate() {
                match record {
                    EncodedRecord::Proto(_) => {}
                    _ => panic!("Expected Proto variant at index {}", i),
                }
            }
        }

        #[test]
        fn test_batch_with_json_values() {
            let data1 = TestData {
                name: "data1".to_string(),
                value: 1,
            };
            let data2 = TestData {
                name: "data2".to_string(),
                value: 2,
            };

            let batch: Vec<JsonValue<TestData>> = vec![JsonValue(data1), JsonValue(data2)];

            let records: Vec<EncodedRecord> = batch.into_iter().map(|m| m.into()).collect();

            assert_eq!(records.len(), 2);
            for (i, record) in records.iter().enumerate() {
                match record {
                    EncodedRecord::Json(data) => {
                        let parsed: serde_json::Value = serde_json::from_str(data).unwrap();
                        assert!(parsed["name"].as_str().unwrap().starts_with("data"));
                    }
                    _ => panic!("Expected Json variant at index {}", i),
                }
            }
        }

        #[test]
        fn test_batch_with_proto_bytes() {
            let bytes1 = vec![1, 2, 3];
            let bytes2 = vec![4, 5, 6];

            let batch = vec![ProtoBytes(bytes1.clone()), ProtoBytes(bytes2.clone())];
            let records: Vec<EncodedRecord> = batch.into_iter().map(|b| b.into()).collect();

            assert_eq!(records.len(), 2);
            match &records[0] {
                EncodedRecord::Proto(data) => assert_eq!(data, &bytes1),
                _ => panic!("Expected Proto variant"),
            }
            match &records[1] {
                EncodedRecord::Proto(data) => assert_eq!(data, &bytes2),
                _ => panic!("Expected Proto variant"),
            }
        }

        #[test]
        fn test_batch_with_json_strings() {
            let json1 = r#"{"id":1}"#.to_string();
            let json2 = r#"{"id":2}"#.to_string();

            let batch = vec![JsonString(json1.clone()), JsonString(json2.clone())];
            let records: Vec<EncodedRecord> = batch.into_iter().map(|s| s.into()).collect();

            assert_eq!(records.len(), 2);
            match &records[0] {
                EncodedRecord::Json(data) => assert_eq!(data, &json1),
                _ => panic!("Expected Json variant"),
            }
            match &records[1] {
                EncodedRecord::Json(data) => assert_eq!(data, &json2),
                _ => panic!("Expected Json variant"),
            }
        }

        #[test]
        fn test_batch_backward_compat_vec_u8() {
            let bytes1 = vec![1, 2, 3];
            let bytes2 = vec![4, 5, 6];

            let batch: Vec<Vec<u8>> = vec![bytes1.clone(), bytes2.clone()];
            let records: Vec<EncodedRecord> = batch.into_iter().map(|b| b.into()).collect();

            assert_eq!(records.len(), 2);
            match &records[0] {
                EncodedRecord::Proto(data) => assert_eq!(data, &bytes1),
                _ => panic!("Expected Proto variant"),
            }
            match &records[1] {
                EncodedRecord::Proto(data) => assert_eq!(data, &bytes2),
                _ => panic!("Expected Proto variant"),
            }
        }

        #[test]
        fn test_batch_backward_compat_string() {
            let json1 = r#"{"id":1}"#.to_string();
            let json2 = r#"{"id":2}"#.to_string();

            let batch: Vec<String> = vec![json1.clone(), json2.clone()];
            let records: Vec<EncodedRecord> = batch.into_iter().map(|s| s.into()).collect();

            assert_eq!(records.len(), 2);
            match &records[0] {
                EncodedRecord::Json(data) => assert_eq!(data, &json1),
                _ => panic!("Expected Json variant"),
            }
            match &records[1] {
                EncodedRecord::Json(data) => assert_eq!(data, &json2),
                _ => panic!("Expected Json variant"),
            }
        }
    }
}
