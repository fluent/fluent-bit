mod common;

// Proto2 and proto3 have usually the same field ordinals, so we can use the same constants.
use all_types_fields::{proto2 as all_types_ordinals, proto3 as all_types_ordinals_proto3};
use common::{
    all_types_fields, complex_nested_fields, create_registry_for_version,
    deeply_nested_message_fields, encode_message_for_version, field_num, nested_message_fields,
    supported_types_fields, ProtoVersion,
};
use databricks_zerobus_ingest_sdk::zeroparser::parser::ParsedMessage;
use databricks_zerobus_ingest_sdk::zeroparser::types::{FieldValueRef, MapKeyRef};
use databricks_zerobus_ingest_sdk::zeroparser::{MessageRegistry, ParseError};
use prost_types::field_descriptor_proto::Type;
use prost_types::{DescriptorProto, FieldDescriptorProto};
use rstest::rstest;

#[allow(clippy::enum_variant_names)]
mod proto2 {
    include!(concat!(env!("OUT_DIR"), "/zeroparser.e2e.proto2.rs"));
}

// proto3 mirror types parse identically on the wire, so the parameterized
// tests construct proto2 values and feed them through both registries —
// nothing constructs the proto3 structs directly.
#[allow(dead_code, clippy::enum_variant_names)]
mod proto3 {
    include!(concat!(env!("OUT_DIR"), "/zeroparser.e2e.proto3.rs"));
}

// ============================================================================
// POSITIVE TESTS FOR BOTH PROTO2 AND PROTO3
// ============================================================================

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_all_scalar_types(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_int32: Some(-42),
        f_int64: Some(-9223372036854775807),
        f_uint32: Some(4294967295),
        f_uint64: Some(18446744073709551615),
        f_sint32: Some(-2147483648),
        f_sint64: Some(-9223372036854775808),
        f_fixed32: Some(123456),
        f_fixed64: Some(123456789012345),
        f_sfixed32: Some(-123456),
        f_sfixed64: Some(-123456789012345),
        f_float: Some(3.25),
        f_double: Some(2.125),
        f_bool: Some(true),
        f_string: Some("test_string".to_string()),
        f_bytes: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        f_enum: Some(proto2::Status::Approved.into()),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT32),
        Some(&FieldValueRef::Int32(-42))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT64),
        Some(&FieldValueRef::Int64(-9223372036854775807))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_UINT32),
        Some(&FieldValueRef::UInt32(4294967295))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_UINT64),
        Some(&FieldValueRef::UInt64(18446744073709551615))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SINT32),
        Some(&FieldValueRef::Int32(-2147483648))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SINT64),
        Some(&FieldValueRef::Int64(-9223372036854775808))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_FIXED32),
        Some(&FieldValueRef::UInt32(123456))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_FIXED64),
        Some(&FieldValueRef::UInt64(123456789012345))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SFIXED32),
        Some(&FieldValueRef::Int32(-123456))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SFIXED64),
        Some(&FieldValueRef::Int64(-123456789012345))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_FLOAT),
        Some(&FieldValueRef::Float(3.25))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_DOUBLE),
        Some(&FieldValueRef::Double(2.125))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_BOOL),
        Some(&FieldValueRef::Bool(true))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_STRING),
        Some(&FieldValueRef::String("test_string"))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_BYTES),
        Some(&FieldValueRef::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF]))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_ENUM),
        Some(&FieldValueRef::Int32(2))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_empty_message(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage::default();
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
    assert!(!parsed.has_field(2));
    assert!(!parsed.has_field(14));
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_nested_messages(#[case] version: ProtoVersion) {
    // Test with populated nested messages
    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_nested: Some(proto2::all_types_message::NestedMessage {
                    nested_id: Some(123),
                    nested_name: Some("nested".to_string()),
                }),
                f_deeply_nested: Some(proto2::all_types_message::DeeplyNestedMessage {
                    deep_id: Some(456),
                    nested: Some(proto2::all_types_message::NestedMessage {
                        nested_id: Some(789),
                        nested_name: Some("deep_nested".to_string()),
                    }),
                }),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_nested: Some(proto3::all_types_message::NestedMessage {
                    nested_id: 123,
                    nested_name: "nested".to_string(),
                }),
                f_deeply_nested: Some(proto3::all_types_message::DeeplyNestedMessage {
                    deep_id: 456,
                    nested: Some(proto3::all_types_message::NestedMessage {
                        nested_id: 789,
                        nested_name: "deep_nested".to_string(),
                    }),
                }),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    let nested_field_num = field_num(version, "f_nested");
    let deeply_nested_field_num = field_num(version, "f_deeply_nested");

    let nested = parsed
        .get_message(nested_field_num)
        .expect("f_nested should be present");
    assert_eq!(
        nested.get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(123))
    );
    assert_eq!(
        nested.get_scalar(nested_message_fields::NESTED_NAME),
        Some(&FieldValueRef::String("nested"))
    );

    let deeply_nested = parsed
        .get_message(deeply_nested_field_num)
        .expect("f_deeply_nested should be present");
    assert_eq!(
        deeply_nested.get_scalar(deeply_nested_message_fields::DEEP_ID),
        Some(&FieldValueRef::Int32(456))
    );

    let inner_nested = deeply_nested
        .get_message(deeply_nested_message_fields::NESTED)
        .expect("nested should be present");
    assert_eq!(
        inner_nested.get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(789))
    );
    assert_eq!(
        inner_nested.get_scalar(nested_message_fields::NESTED_NAME),
        Some(&FieldValueRef::String("deep_nested"))
    );

    // Test with empty nested message
    let (buf_empty, registry_empty) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_nested: Some(proto2::all_types_message::NestedMessage {
                    nested_id: None,
                    nested_name: None,
                }),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_nested: Some(proto3::all_types_message::NestedMessage {
                    nested_id: 0,
                    nested_name: "".to_string(),
                }),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed_empty = ParsedMessage::parse(&buf_empty, &registry_empty).unwrap();
    let nested_empty = parsed_empty
        .get_message(nested_field_num)
        .expect("f_nested should be present");
    assert!(!nested_empty.has_field(1), "nested_id should be absent");
    assert!(!nested_empty.has_field(2), "nested_name should be absent");
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_repeated_fields(#[case] version: ProtoVersion) {
    // Test with populated repeated fields
    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_repeated_int32: vec![1, 2, 3, -1, 0],
                f_repeated_string: vec!["a".to_string(), "b".to_string(), "".to_string()],
                f_repeated_packed: vec![10, 20, 30],
                f_repeated_unpacked: vec![100, 200, 300],
                f_repeated_message: vec![
                    proto2::all_types_message::NestedMessage {
                        nested_id: Some(1),
                        nested_name: Some("first".to_string()),
                    },
                    proto2::all_types_message::NestedMessage {
                        nested_id: Some(2),
                        nested_name: Some("second".to_string()),
                    },
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_repeated_int32: vec![1, 2, 3, -1, 0],
                f_repeated_string: vec!["a".to_string(), "b".to_string(), "".to_string()],
                f_repeated_message: vec![
                    proto3::all_types_message::NestedMessage {
                        nested_id: 1,
                        nested_name: "first".to_string(),
                    },
                    proto3::all_types_message::NestedMessage {
                        nested_id: 2,
                        nested_name: "second".to_string(),
                    },
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    let repeated_int32_field = field_num(version, "f_repeated_int32");
    let repeated_string_field = field_num(version, "f_repeated_string");
    let repeated_message_field = field_num(version, "f_repeated_message");

    let repeated_int32 = parsed.get_repeated_scalars(repeated_int32_field);
    assert_eq!(repeated_int32.len(), 5);
    assert_eq!(repeated_int32[0], FieldValueRef::Int32(1));
    assert_eq!(repeated_int32[1], FieldValueRef::Int32(2));
    assert_eq!(repeated_int32[2], FieldValueRef::Int32(3));
    assert_eq!(repeated_int32[3], FieldValueRef::Int32(-1));
    assert_eq!(repeated_int32[4], FieldValueRef::Int32(0));

    let repeated_string = parsed.get_repeated_scalars(repeated_string_field);
    assert_eq!(repeated_string.len(), 3);
    assert_eq!(repeated_string[0], FieldValueRef::String("a"));
    assert_eq!(repeated_string[1], FieldValueRef::String("b"));
    assert_eq!(repeated_string[2], FieldValueRef::String(""));

    if version == ProtoVersion::Proto2 {
        let repeated_packed = parsed.get_repeated_scalars(field_num(version, "f_repeated_packed"));
        assert_eq!(repeated_packed.len(), 3);
        assert_eq!(repeated_packed[0], FieldValueRef::Int32(10));
        assert_eq!(repeated_packed[1], FieldValueRef::Int32(20));
        assert_eq!(repeated_packed[2], FieldValueRef::Int32(30));

        let repeated_unpacked =
            parsed.get_repeated_scalars(field_num(version, "f_repeated_unpacked"));
        assert_eq!(repeated_unpacked.len(), 3);
        assert_eq!(repeated_unpacked[0], FieldValueRef::Int32(100));
        assert_eq!(repeated_unpacked[1], FieldValueRef::Int32(200));
        assert_eq!(repeated_unpacked[2], FieldValueRef::Int32(300));
    }

    let repeated_messages = parsed.get_repeated_messages(repeated_message_field);
    assert_eq!(repeated_messages.len(), 2);
    assert_eq!(
        repeated_messages[0].get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(1))
    );
    assert_eq!(
        repeated_messages[0].get_scalar(nested_message_fields::NESTED_NAME),
        Some(&FieldValueRef::String("first"))
    );
    assert_eq!(
        repeated_messages[1].get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(2))
    );
    assert_eq!(
        repeated_messages[1].get_scalar(nested_message_fields::NESTED_NAME),
        Some(&FieldValueRef::String("second"))
    );

    // Test with empty repeated fields
    let msg_empty = proto2::AllTypesMessage::default();
    let (buf_empty, registry_empty) =
        encode_message_for_version(version, &msg_empty, "AllTypesMessage");
    let parsed_empty = ParsedMessage::parse(&buf_empty, &registry_empty).unwrap();

    assert_eq!(
        parsed_empty
            .get_repeated_scalars(repeated_int32_field)
            .len(),
        0
    );
    assert_eq!(
        parsed_empty
            .get_repeated_scalars(repeated_string_field)
            .len(),
        0
    );
    assert_eq!(
        parsed_empty
            .get_repeated_messages(repeated_message_field)
            .len(),
        0
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_map_fields(#[case] version: ProtoVersion) {
    use databricks_zerobus_ingest_sdk::zeroparser::types::ParsedMapValue;

    // Test with populated map fields
    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_map_int_string: [(1, "one".to_string()), (2, "two".to_string())]
                    .into_iter()
                    .collect(),
                f_map_string_string: [
                    ("key1".to_string(), "value1".to_string()),
                    ("key2".to_string(), "value2".to_string()),
                ]
                .into_iter()
                .collect(),
                f_map_string_message: [(
                    "msg_key".to_string(),
                    proto2::all_types_message::NestedMessage {
                        nested_id: Some(999),
                        nested_name: Some("map_nested".to_string()),
                    },
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_map_int_string: [(1, "one".to_string()), (2, "two".to_string())]
                    .into_iter()
                    .collect(),
                f_map_string_string: [
                    ("key1".to_string(), "value1".to_string()),
                    ("key2".to_string(), "value2".to_string()),
                ]
                .into_iter()
                .collect(),
                f_map_string_message: [(
                    "msg_key".to_string(),
                    proto3::all_types_message::NestedMessage {
                        nested_id: 999,
                        nested_name: "map_nested".to_string(),
                    },
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    let map_int_string_field = field_num(version, "f_map_int_string");
    let map_string_string_field = field_num(version, "f_map_string_string");
    let map_string_message_field = field_num(version, "f_map_string_message");

    // Verify map content
    assert_eq!(parsed.get_map_entries_count(map_int_string_field), 2);
    let mut found_one = false;
    let mut found_two = false;
    for (key, value) in parsed.get_map_entries(map_int_string_field) {
        match (*key, value) {
            (MapKeyRef::Int32(1), ParsedMapValue::Scalar(FieldValueRef::String("one"))) => {
                found_one = true
            }
            (MapKeyRef::Int32(2), ParsedMapValue::Scalar(FieldValueRef::String("two"))) => {
                found_two = true
            }
            _ => {}
        }
    }
    assert!(found_one, "Map should contain key=1, value='one'");
    assert!(found_two, "Map should contain key=2, value='two'");

    assert_eq!(parsed.get_map_entries_count(map_string_string_field), 2);
    let mut found_key1 = false;
    let mut found_key2 = false;
    for (key, value) in parsed.get_map_entries(map_string_string_field) {
        match (*key, value) {
            (
                MapKeyRef::String("key1"),
                ParsedMapValue::Scalar(FieldValueRef::String("value1")),
            ) => found_key1 = true,
            (
                MapKeyRef::String("key2"),
                ParsedMapValue::Scalar(FieldValueRef::String("value2")),
            ) => found_key2 = true,
            _ => {}
        }
    }
    assert!(found_key1, "Map should contain key='key1', value='value1'");
    assert!(found_key2, "Map should contain key='key2', value='value2'");

    assert_eq!(parsed.get_map_entries_count(map_string_message_field), 1);
    let map_string_message: Vec<_> = parsed.get_map_entries(map_string_message_field).collect();
    let (key, value) = &map_string_message[0];
    assert_eq!(**key, MapKeyRef::String("msg_key"));
    let nested_msg = match value {
        ParsedMapValue::Message(msg) => msg,
        _ => panic!("Expected message value"),
    };
    assert_eq!(
        nested_msg.get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(999))
    );
    assert_eq!(
        nested_msg.get_scalar(nested_message_fields::NESTED_NAME),
        Some(&FieldValueRef::String("map_nested"))
    );

    // Test with empty map fields
    let msg_empty = proto2::AllTypesMessage::default();
    let (buf_empty, registry_empty) =
        encode_message_for_version(version, &msg_empty, "AllTypesMessage");
    let parsed_empty = ParsedMessage::parse(&buf_empty, &registry_empty).unwrap();

    assert_eq!(parsed_empty.get_map_entries_count(map_int_string_field), 0);
    assert_eq!(
        parsed_empty.get_map_entries_count(map_string_string_field),
        0
    );
    assert_eq!(
        parsed_empty.get_map_entries_count(map_string_message_field),
        0
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_large_field_numbers(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_large_field_150: Some(150),
        f_large_field_200: Some("field_200".to_string()),
        f_large_field_300: Some(300000),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert!(
        parsed.has_field(all_types_ordinals::F_LARGE_FIELD_150),
        "f_large_field_150 should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_LARGE_FIELD_150),
        Some(&FieldValueRef::Int32(150))
    );

    assert!(
        parsed.has_field(all_types_ordinals::F_LARGE_FIELD_200),
        "f_large_field_200 should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_LARGE_FIELD_200),
        Some(&FieldValueRef::String("field_200"))
    );

    assert!(
        parsed.has_field(all_types_ordinals::F_LARGE_FIELD_300),
        "f_large_field_300 should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_LARGE_FIELD_300),
        Some(&FieldValueRef::Int64(300000))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_string_and_binary_data(#[case] version: ProtoVersion) {
    // Test UTF-8 strings
    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_string: Some("Hello 世界 🌍 émojis".to_string()),
                f_bytes: Some(vec![0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56]),
                f_repeated_string: vec![
                    "ASCII".to_string(),
                    "日本語".to_string(),
                    "🚀🌟".to_string(),
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_string: "Hello 世界 🌍 émojis".to_string(),
                f_bytes: vec![0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56],
                f_repeated_string: vec![
                    "ASCII".to_string(),
                    "日本語".to_string(),
                    "🚀🌟".to_string(),
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    // Verify UTF-8 string
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_STRING),
        Some(&FieldValueRef::String("Hello 世界 🌍 émojis"))
    );

    // Verify binary data
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_BYTES),
        Some(&FieldValueRef::Bytes(&[
            0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56
        ]))
    );

    // Verify repeated strings with international characters
    let repeated_string_field = field_num(version, "f_repeated_string");

    let repeated_string = parsed.get_repeated_scalars(repeated_string_field);
    assert_eq!(repeated_string[0], FieldValueRef::String("ASCII"));
    assert_eq!(repeated_string[1], FieldValueRef::String("日本語"));
    assert_eq!(repeated_string[2], FieldValueRef::String("🚀🌟"));
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_unknown_fields(#[case] version: ProtoVersion) {
    let file_desc_set = common::load_descriptor_set(version);
    let mut buf = Vec::new();
    let msg_v2 = proto2::SupportedTypesV2 {
        approved: Some(true),
        day_num: Some(10),
        cost: Some(5000),
        description: Some("test".to_string()),
        discount: Some(0.15),
        cost_with_discount: Some(4250.0),
        photo: Some(vec![0xAA, 0xBB]),
        tags: vec!["tag1".to_string(), "tag2".to_string()],
        metadata: [(1, "meta1".to_string())].into_iter().collect(),
    };
    prost::Message::encode(&msg_v2, &mut buf).unwrap();

    let descriptor_v1 = common::get_message_descriptor(&file_desc_set, "SupportedTypesV1");
    let registry = MessageRegistry::from_descriptor(&descriptor_v1);
    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(supported_types_fields::APPROVED),
        Some(&FieldValueRef::Bool(true))
    );
    assert_eq!(
        parsed.get_scalar(supported_types_fields::DAY_NUM),
        Some(&FieldValueRef::Int32(10))
    );
    assert_eq!(
        parsed.get_scalar(supported_types_fields::COST),
        Some(&FieldValueRef::Int64(5000))
    );
    assert_eq!(
        parsed.get_scalar(supported_types_fields::DESCRIPTION),
        Some(&FieldValueRef::String("test"))
    );

    assert!(
        !parsed.has_field(supported_types_fields::DISCOUNT),
        "discount should be unknown"
    );
    assert!(
        !parsed.has_field(supported_types_fields::COST_WITH_DISCOUNT),
        "cost_with_discount should be unknown"
    );
    assert!(
        !parsed.has_field(supported_types_fields::PHOTO),
        "photo should be unknown"
    );
    assert_eq!(
        parsed
            .get_repeated_scalars(supported_types_fields::TAGS)
            .len(),
        0,
        "tags should be unknown"
    );
    assert_eq!(
        parsed.get_map_entries_count(supported_types_fields::METADATA),
        0,
        "metadata should be unknown"
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_max_min_edge_values(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_int32: Some(i32::MAX),
        f_int64: Some(i64::MIN),
        f_uint32: Some(u32::MAX),
        f_uint64: Some(u64::MAX),
        f_sint32: Some(i32::MIN),
        f_sint64: Some(i64::MAX),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT32),
        Some(&FieldValueRef::Int32(i32::MAX))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT64),
        Some(&FieldValueRef::Int64(i64::MIN))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_UINT32),
        Some(&FieldValueRef::UInt32(u32::MAX))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_UINT64),
        Some(&FieldValueRef::UInt64(u64::MAX))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SINT32),
        Some(&FieldValueRef::Int32(i32::MIN))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SINT64),
        Some(&FieldValueRef::Int64(i64::MAX))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_negative_numbers(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_int32: Some(-12345),
        f_int64: Some(-9876543210),
        f_sint32: Some(-2147483648),
        f_sint64: Some(-9223372036854775808),
        f_sfixed32: Some(-99999),
        f_sfixed64: Some(-9999999999),
        f_float: Some(-3.25),
        f_double: Some(-2.125),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT32),
        Some(&FieldValueRef::Int32(-12345))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT64),
        Some(&FieldValueRef::Int64(-9876543210))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SINT32),
        Some(&FieldValueRef::Int32(-2147483648))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SINT64),
        Some(&FieldValueRef::Int64(-9223372036854775808))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SFIXED32),
        Some(&FieldValueRef::Int32(-99999))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_SFIXED64),
        Some(&FieldValueRef::Int64(-9999999999))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_FLOAT),
        Some(&FieldValueRef::Float(-3.25))
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_DOUBLE),
        Some(&FieldValueRef::Double(-2.125))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_all_enum_values(#[case] version: ProtoVersion) {
    match version {
        ProtoVersion::Proto2 => {
            for (enum_val, expected) in [
                (proto2::Status::Unknown, 0),
                (proto2::Status::Pending, 1),
                (proto2::Status::Approved, 2),
                (proto2::Status::Rejected, 3),
            ] {
                let msg = proto2::AllTypesMessage {
                    f_enum: Some(enum_val.into()),
                    f_required: 0,
                    ..Default::default()
                };

                let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");
                let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
                assert_eq!(
                    parsed.get_scalar(all_types_ordinals::F_ENUM),
                    Some(&FieldValueRef::Int32(expected)),
                    "Enum value {:?} should be {}",
                    enum_val,
                    expected
                );
            }
        }
        ProtoVersion::Proto3 => {
            for (enum_val, expected) in [
                (proto3::Status::Unknown, 0),
                (proto3::Status::Pending, 1),
                (proto3::Status::Approved, 2),
                (proto3::Status::Rejected, 3),
            ] {
                let msg = proto3::AllTypesMessage {
                    f_enum: enum_val.into(),
                    ..Default::default()
                };

                let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");
                let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

                if expected == 0 {
                    assert!(
                        !parsed.has_field(all_types_ordinals::F_ENUM),
                        "Enum default value (0) should not be present"
                    );
                } else {
                    assert_eq!(
                        parsed.get_scalar(all_types_ordinals::F_ENUM),
                        Some(&FieldValueRef::Int32(expected)),
                        "Enum value {:?} should be {}",
                        enum_val,
                        expected
                    );
                }
            }
        }
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_float_special_values(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_float: Some(f32::NAN),
        f_double: Some(f64::INFINITY),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    if let Some(FieldValueRef::Float(float_val)) = parsed.get_scalar(all_types_ordinals::F_FLOAT) {
        assert!(float_val.is_nan(), "f_float should be NaN");
    } else {
        panic!("f_float should be present as Float");
    }

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_DOUBLE),
        Some(&FieldValueRef::Double(f64::INFINITY)),
        "f_double should be +Infinity"
    );

    let msg2 = proto2::AllTypesMessage {
        f_float: Some(f32::NEG_INFINITY),
        f_double: Some(f64::NEG_INFINITY),
        ..Default::default()
    };
    let (buf2, registry2) = encode_message_for_version(version, &msg2, "AllTypesMessage");

    let parsed2 = ParsedMessage::parse(&buf2, &registry2).unwrap();

    assert_eq!(
        parsed2.get_scalar(all_types_ordinals::F_FLOAT),
        Some(&FieldValueRef::Float(f32::NEG_INFINITY)),
        "f_float should be -Infinity"
    );
    assert_eq!(
        parsed2.get_scalar(all_types_ordinals::F_DOUBLE),
        Some(&FieldValueRef::Double(f64::NEG_INFINITY)),
        "f_double should be -Infinity"
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_oneof_fields(#[case] version: ProtoVersion) {
    let oneof_int_field = field_num(version, "f_oneof_int");
    let oneof_string_field = field_num(version, "f_oneof_string");
    let oneof_message_field = field_num(version, "f_oneof_message");

    let (buf_int, registry_int) = match version {
        ProtoVersion::Proto2 => {
            let msg_int = proto2::AllTypesMessage {
                f_required: 1,
                f_oneof: Some(proto2::all_types_message::FOneof::OneofInt(42)),
                ..Default::default()
            };
            encode_message_for_version(version, &msg_int, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg_int = proto3::AllTypesMessage {
                f_oneof: Some(proto3::all_types_message::FOneof::OneofInt(42)),
                ..Default::default()
            };
            encode_message_for_version(version, &msg_int, "AllTypesMessage")
        }
    };

    let parsed_int = ParsedMessage::parse(&buf_int, &registry_int).unwrap();

    assert!(
        parsed_int.has_field(oneof_int_field),
        "oneof_int should be present"
    );
    assert_eq!(
        parsed_int.get_scalar(oneof_int_field),
        Some(&FieldValueRef::Int32(42))
    );
    assert!(
        !parsed_int.has_field(oneof_string_field),
        "oneof_string should be absent"
    );
    assert!(
        parsed_int.get_message(oneof_message_field).is_none(),
        "oneof_message should be absent"
    );

    let (buf_string, registry_string) = match version {
        ProtoVersion::Proto2 => {
            let msg_string = proto2::AllTypesMessage {
                f_required: 1,
                f_oneof: Some(proto2::all_types_message::FOneof::OneofString(
                    "oneof_test".to_string(),
                )),
                ..Default::default()
            };
            encode_message_for_version(version, &msg_string, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg_string = proto3::AllTypesMessage {
                f_oneof: Some(proto3::all_types_message::FOneof::OneofString(
                    "oneof_test".to_string(),
                )),
                ..Default::default()
            };
            encode_message_for_version(version, &msg_string, "AllTypesMessage")
        }
    };

    let parsed_string = ParsedMessage::parse(&buf_string, &registry_string).unwrap();

    assert!(
        !parsed_string.has_field(oneof_int_field),
        "oneof_int should be absent"
    );
    assert!(
        parsed_string.has_field(oneof_string_field),
        "oneof_string should be present"
    );
    assert_eq!(
        parsed_string.get_scalar(oneof_string_field),
        Some(&FieldValueRef::String("oneof_test"))
    );
    assert!(
        parsed_string.get_message(oneof_message_field).is_none(),
        "oneof_message should be absent"
    );

    let (buf_message, registry_message) = match version {
        ProtoVersion::Proto2 => {
            let msg_message = proto2::AllTypesMessage {
                f_required: 1,
                f_oneof: Some(proto2::all_types_message::FOneof::OneofMessage(
                    proto2::all_types_message::NestedMessage {
                        nested_id: Some(123),
                        nested_name: Some("oneof_nested".to_string()),
                    },
                )),
                ..Default::default()
            };
            encode_message_for_version(version, &msg_message, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg_message = proto3::AllTypesMessage {
                f_oneof: Some(proto3::all_types_message::FOneof::OneofMessage(
                    proto3::all_types_message::NestedMessage {
                        nested_id: 123,
                        nested_name: "oneof_nested".to_string(),
                    },
                )),
                ..Default::default()
            };
            encode_message_for_version(version, &msg_message, "AllTypesMessage")
        }
    };

    let parsed_message = ParsedMessage::parse(&buf_message, &registry_message).unwrap();

    assert!(
        !parsed_message.has_field(oneof_int_field),
        "oneof_int should be absent"
    );
    assert!(
        !parsed_message.has_field(oneof_string_field),
        "oneof_string should be absent"
    );
    let nested = parsed_message
        .get_message(oneof_message_field)
        .expect("oneof_message should be present");
    assert_eq!(
        nested.get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(123))
    );
    assert_eq!(
        nested.get_scalar(nested_message_fields::NESTED_NAME),
        Some(&FieldValueRef::String("oneof_nested"))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_oneof_last_writer_wins_on_wire(#[case] version: ProtoVersion) {
    use prost::Message;

    // Prost always emits a single oneof variant per message, so to simulate a
    // non-canonical producer that wrote multiple variants of the same oneof we
    // encode separate single-variant messages and concatenate their wire bytes.
    // Per the protobuf spec the parser must treat this as last-writer-wins and
    // clear the earlier variants from storage.
    let msg_int = proto2::AllTypesMessage {
        f_required: 1,
        f_oneof: Some(proto2::all_types_message::FOneof::OneofInt(42)),
        ..Default::default()
    };
    let msg_string = proto2::AllTypesMessage {
        f_required: 1,
        f_oneof: Some(proto2::all_types_message::FOneof::OneofString(
            "winner".to_string(),
        )),
        ..Default::default()
    };
    let msg_message = proto2::AllTypesMessage {
        f_required: 1,
        f_oneof: Some(proto2::all_types_message::FOneof::OneofMessage(
            proto2::all_types_message::NestedMessage {
                nested_id: Some(123),
                nested_name: Some("nested".to_string()),
            },
        )),
        ..Default::default()
    };

    let mut buf_int = Vec::new();
    msg_int.encode(&mut buf_int).unwrap();
    let mut buf_string = Vec::new();
    msg_string.encode(&mut buf_string).unwrap();
    let mut buf_message = Vec::new();
    msg_message.encode(&mut buf_message).unwrap();

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let oneof_int_field = field_num(version, "f_oneof_int");
    let oneof_string_field = field_num(version, "f_oneof_string");
    let oneof_message_field = field_num(version, "f_oneof_message");

    // Case 1: scalar → scalar. Later scalar wins; earlier scalar is cleared.
    let mut wire = buf_int.clone();
    wire.extend_from_slice(&buf_string);
    let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
    assert!(
        !parsed.has_field(oneof_int_field),
        "oneof_int should be cleared by later oneof_string"
    );
    assert_eq!(
        parsed.get_scalar(oneof_string_field),
        Some(&FieldValueRef::String("winner"))
    );
    assert!(parsed.get_message(oneof_message_field).is_none());

    // Case 2: scalar → message. Message wins; scalar is cleared.
    let mut wire = buf_string.clone();
    wire.extend_from_slice(&buf_message);
    let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
    assert!(
        !parsed.has_field(oneof_string_field),
        "oneof_string should be cleared by later oneof_message"
    );
    assert!(!parsed.has_field(oneof_int_field));
    let nested = parsed
        .get_message(oneof_message_field)
        .expect("oneof_message should be present");
    assert_eq!(
        nested.get_scalar(nested_message_fields::NESTED_ID),
        Some(&FieldValueRef::Int32(123))
    );

    // Case 3: message → scalar. Scalar wins; message is cleared.
    let mut wire = buf_message.clone();
    wire.extend_from_slice(&buf_int);
    let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
    assert!(
        parsed.get_message(oneof_message_field).is_none(),
        "oneof_message should be cleared by later oneof_int"
    );
    assert!(!parsed.has_field(oneof_string_field));
    assert_eq!(
        parsed.get_scalar(oneof_int_field),
        Some(&FieldValueRef::Int32(42))
    );
}

#[rstest]
#[case(ProtoVersion::Proto3)]
fn test_proto3_optional_coexists_with_oneof(#[case] version: ProtoVersion) {
    use prost::Message;

    // Proto3's `optional` keyword compiles each field to a single-member
    // synthetic oneof. The parser excludes those synthetic oneofs from
    // last-writer-wins enforcement, so real oneof activity must never clear
    // a proto3 `optional` field and vice versa. This test guards that boundary
    // by concatenating two messages that each touch both worlds.
    let msg_a = proto3::AllTypesMessage {
        f_optional_int32: Some(1),
        f_optional_string: Some("keep".to_string()),
        f_oneof: Some(proto3::all_types_message::FOneof::OneofString(
            "first".to_string(),
        )),
        ..Default::default()
    };
    let msg_b = proto3::AllTypesMessage {
        f_optional_int32: Some(2),
        f_oneof: Some(proto3::all_types_message::FOneof::OneofInt(99)),
        ..Default::default()
    };

    let mut wire = Vec::new();
    msg_a.encode(&mut wire).unwrap();
    let mut buf_b = Vec::new();
    msg_b.encode(&mut buf_b).unwrap();
    wire.extend_from_slice(&buf_b);

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let parsed = ParsedMessage::parse(&wire, &registry).unwrap();

    // f_optional_int32 appears in both halves; normal last-wins applies.
    assert_eq!(
        parsed.get_scalar(all_types_ordinals_proto3::F_OPTIONAL_INT32),
        Some(&FieldValueRef::Int32(2))
    );
    // f_optional_string appears only in msg_a. Nothing in msg_b should clear
    // it — in particular the real oneof write in msg_b must not touch it.
    assert_eq!(
        parsed.get_scalar(all_types_ordinals_proto3::F_OPTIONAL_STRING),
        Some(&FieldValueRef::String("keep"))
    );
    // The real oneof follows last-writer-wins: oneof_int replaces oneof_string.
    assert_eq!(
        parsed.get_scalar(field_num(version, "f_oneof_int")),
        Some(&FieldValueRef::Int32(99))
    );
    assert!(
        !parsed.has_field(field_num(version, "f_oneof_string")),
        "oneof_string should be cleared by later oneof_int"
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_repeated_enum(#[case] version: ProtoVersion) {
    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_repeated_enum: vec![
                    proto2::Status::Unknown.into(),
                    proto2::Status::Pending.into(),
                    proto2::Status::Approved.into(),
                    proto2::Status::Rejected.into(),
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_repeated_enum: vec![
                    proto3::Status::Unknown.into(),
                    proto3::Status::Pending.into(),
                    proto3::Status::Approved.into(),
                    proto3::Status::Rejected.into(),
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    let repeated_enum_field = field_num(version, "f_repeated_enum");

    let repeated_enum = parsed.get_repeated_scalars(repeated_enum_field);
    assert_eq!(repeated_enum.len(), 4);
    assert_eq!(repeated_enum[0], FieldValueRef::Int32(0));
    assert_eq!(repeated_enum[1], FieldValueRef::Int32(1));
    assert_eq!(repeated_enum[2], FieldValueRef::Int32(2));
    assert_eq!(repeated_enum[3], FieldValueRef::Int32(3));
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_last_value_wins_for_singular_field(#[case] version: ProtoVersion) {
    use prost::Message;

    let msg1 = proto2::AllTypesMessage {
        f_int32: Some(100),
        f_string: Some("first".to_string()),
        ..Default::default()
    };

    let msg2 = proto2::AllTypesMessage {
        f_int32: Some(200),
        f_string: Some("second".to_string()),
        ..Default::default()
    };

    let mut buf1 = Vec::new();
    msg1.encode(&mut buf1).unwrap();

    let mut buf2 = Vec::new();
    msg2.encode(&mut buf2).unwrap();

    let mut combined = buf1.clone();
    combined.extend_from_slice(&buf2);

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let parsed = ParsedMessage::parse(&combined, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT32),
        Some(&FieldValueRef::Int32(200)),
        "f_int32 should be 200 (last value)"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_STRING),
        Some(&FieldValueRef::String("second")),
        "f_string should be 'second' (last value)"
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_complex_nested_all_field_types(#[case] version: ProtoVersion) {
    let msg = proto2::ComplexNested {
        id: Some(100),
        name: Some("complex".to_string()),
        inner: Some(proto2::complex_nested::InnerData {
            value: Some(999),
            data: Some(vec![0x01, 0x02, 0x03]),
            numbers: vec![10, 20, 30],
        }),
        int_list: vec![1, 2, 3, 4, 5],
        string_list: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        bool_list: vec![true, false, true],
        inner_list: vec![
            proto2::complex_nested::InnerData {
                value: Some(111),
                data: Some(vec![0xAA]),
                numbers: vec![1],
            },
            proto2::complex_nested::InnerData {
                value: Some(222),
                data: Some(vec![0xBB]),
                numbers: vec![2, 3],
            },
        ],
        string_to_int: [("key1".to_string(), 10), ("key2".to_string(), 20)]
            .into_iter()
            .collect(),
        int_to_string: [(1, "one".to_string()), (2, "two".to_string())]
            .into_iter()
            .collect(),
        string_to_message: [(
            "inner".to_string(),
            proto2::complex_nested::InnerData {
                value: Some(333),
                data: Some(vec![0xCC]),
                numbers: vec![100],
            },
        )]
        .into_iter()
        .collect(),
        data_with_maps: Some(proto2::complex_nested::DataWithMaps {
            label: Some("label1".to_string()),
            properties: [("prop1".to_string(), "val1".to_string())]
                .into_iter()
                .collect(),
            indices: vec![5, 10, 15],
        }),
        items: vec![
            proto2::complex_nested::ComplexItem {
                item_id: Some(1),
                tags: vec!["tag1".to_string(), "tag2".to_string()],
                attributes: [("attr1".to_string(), 100)].into_iter().collect(),
            },
            proto2::complex_nested::ComplexItem {
                item_id: Some(2),
                tags: vec!["tag3".to_string()],
                attributes: [("attr2".to_string(), 200)].into_iter().collect(),
            },
        ],
        // Build a tree structure:
        //        root(10)
        //       /         \
        //    left(5)    right(15)
        //     /    \
        //  ll(3)  lr(7)
        tree: Some(proto2::complex_nested::TreeNode {
            value: Some(10),
            label: Some("root".to_string()),
            children: vec![],
            left: Some(Box::new(proto2::complex_nested::TreeNode {
                value: Some(5),
                label: Some("left".to_string()),
                children: vec![
                    proto2::complex_nested::TreeNode {
                        value: Some(3),
                        label: Some("left-left".to_string()),
                        children: vec![],
                        left: None,
                        right: None,
                    },
                    proto2::complex_nested::TreeNode {
                        value: Some(7),
                        label: Some("left-right".to_string()),
                        children: vec![],
                        left: None,
                        right: None,
                    },
                ],
                left: None,
                right: None,
            })),
            right: Some(Box::new(proto2::complex_nested::TreeNode {
                value: Some(15),
                label: Some("right".to_string()),
                children: vec![],
                left: None,
                right: None,
            })),
        }),
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "ComplexNested");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(complex_nested_fields::ID),
        Some(&FieldValueRef::Int32(100))
    );
    assert_eq!(
        parsed.get_scalar(complex_nested_fields::NAME),
        Some(&FieldValueRef::String("complex"))
    );

    let inner = parsed
        .get_message(complex_nested_fields::INNER)
        .expect("inner should be present");
    assert_eq!(
        inner.get_scalar(complex_nested_fields::inner_data::VALUE),
        Some(&FieldValueRef::Int64(999))
    );
    assert_eq!(
        inner.get_scalar(complex_nested_fields::inner_data::DATA),
        Some(&FieldValueRef::Bytes(&[0x01, 0x02, 0x03]))
    );
    let inner_numbers = inner.get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS);
    assert_eq!(inner_numbers.len(), 3);
    assert_eq!(inner_numbers[0], FieldValueRef::Int32(10));

    let int_list = parsed.get_repeated_scalars(complex_nested_fields::INT_LIST);
    assert_eq!(int_list.len(), 5);
    assert_eq!(int_list[0], FieldValueRef::Int32(1));
    assert_eq!(int_list[4], FieldValueRef::Int32(5));

    let string_list = parsed.get_repeated_scalars(complex_nested_fields::STRING_LIST);
    assert_eq!(string_list.len(), 3);
    assert_eq!(string_list[0], FieldValueRef::String("a"));

    let bool_list = parsed.get_repeated_scalars(complex_nested_fields::BOOL_LIST);
    assert_eq!(bool_list.len(), 3);
    assert_eq!(bool_list[0], FieldValueRef::Bool(true));
    assert_eq!(bool_list[1], FieldValueRef::Bool(false));

    let inner_list = parsed.get_repeated_messages(complex_nested_fields::INNER_LIST);
    assert_eq!(inner_list.len(), 2);
    assert_eq!(
        inner_list[0].get_scalar(complex_nested_fields::inner_data::VALUE),
        Some(&FieldValueRef::Int64(111))
    );
    assert_eq!(
        inner_list[1].get_scalar(complex_nested_fields::inner_data::VALUE),
        Some(&FieldValueRef::Int64(222))
    );

    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::STRING_TO_INT),
        2
    );

    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::INT_TO_STRING),
        2
    );

    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::STRING_TO_MESSAGE),
        1
    );

    let data_with_maps = parsed
        .get_message(complex_nested_fields::DATA_WITH_MAPS)
        .expect("data_with_maps should be present");
    assert_eq!(
        data_with_maps.get_scalar(complex_nested_fields::data_with_maps::LABEL),
        Some(&FieldValueRef::String("label1"))
    );
    assert_eq!(
        data_with_maps.get_map_entries_count(complex_nested_fields::data_with_maps::PROPERTIES),
        1
    );
    assert_eq!(
        data_with_maps
            .get_repeated_scalars(complex_nested_fields::data_with_maps::INDICES)
            .len(),
        3
    );

    let items = parsed.get_repeated_messages(complex_nested_fields::ITEMS);
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0].get_scalar(complex_nested_fields::complex_item::ITEM_ID),
        Some(&FieldValueRef::Int32(1))
    );
    assert_eq!(
        items[0]
            .get_repeated_scalars(complex_nested_fields::complex_item::TAGS)
            .len(),
        2
    );
    assert_eq!(
        items[0].get_map_entries_count(complex_nested_fields::complex_item::ATTRIBUTES),
        1
    );

    // Verify tree structure
    let tree_root = parsed
        .get_message(complex_nested_fields::TREE)
        .expect("tree should be present");
    assert_eq!(
        tree_root.get_scalar(complex_nested_fields::tree_node::VALUE),
        Some(&FieldValueRef::Int32(10))
    );
    assert_eq!(
        tree_root.get_scalar(complex_nested_fields::tree_node::LABEL),
        Some(&FieldValueRef::String("root"))
    );

    let tree_left = tree_root
        .get_message(complex_nested_fields::tree_node::LEFT)
        .expect("left subtree should be present");
    assert_eq!(
        tree_left.get_scalar(complex_nested_fields::tree_node::VALUE),
        Some(&FieldValueRef::Int32(5))
    );
    let left_children = tree_left.get_repeated_messages(complex_nested_fields::tree_node::CHILDREN);
    assert_eq!(left_children.len(), 2);
    assert_eq!(
        left_children[0].get_scalar(complex_nested_fields::tree_node::VALUE),
        Some(&FieldValueRef::Int32(3))
    );
    assert_eq!(
        left_children[1].get_scalar(complex_nested_fields::tree_node::VALUE),
        Some(&FieldValueRef::Int32(7))
    );

    let tree_right = tree_root
        .get_message(complex_nested_fields::tree_node::RIGHT)
        .expect("right subtree should be present");
    assert_eq!(
        tree_right.get_scalar(complex_nested_fields::tree_node::VALUE),
        Some(&FieldValueRef::Int32(15))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_all_types_message_with_null_values(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        // Test null for various scalar types
        f_int32: None,
        f_int64: None,
        f_uint32: None,
        f_uint64: None,
        f_sint32: None,
        f_sint64: None,
        f_fixed32: None,
        f_fixed64: None,
        f_sfixed32: None,
        f_sfixed64: None,
        f_float: None,
        f_double: None,
        f_bool: None,
        f_string: None,
        f_bytes: None,
        f_enum: None,
        // Required field must have a value in proto2
        f_required: 1,
        // Test null for fields with defaults
        f_default_int: None,
        f_default_string: None,
        f_default_bool: None,
        // Test null nested message
        f_nested: None,
        // Test null deeply nested message
        f_deeply_nested: None,
        // Test empty repeated fields
        f_repeated_int32: vec![],
        f_repeated_string: vec![],
        f_repeated_packed: vec![],
        f_repeated_unpacked: vec![],
        f_repeated_message: vec![],
        // Test empty maps
        f_map_int_string: Default::default(),
        f_map_string_string: Default::default(),
        f_map_string_message: Default::default(),
        // Test oneof with no value set
        f_oneof: None,
        // Repeated enum
        f_repeated_enum: vec![],
        // Large field numbers
        f_large_field_150: None,
        f_large_field_200: None,
        f_large_field_300: None,
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    // All optional scalar fields should be absent
    assert!(
        !parsed.has_field(all_types_ordinals::F_INT32),
        "f_int32 should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_INT64),
        "f_int64 should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_FLOAT),
        "f_float should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_DOUBLE),
        "f_double should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_BOOL),
        "f_bool should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_STRING),
        "f_string should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_BYTES),
        "f_bytes should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_ENUM),
        "f_enum should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_DEFAULT_INT),
        "f_default_int should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_DEFAULT_STRING),
        "f_default_string should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_DEFAULT_BOOL),
        "f_default_bool should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_NESTED),
        "f_nested should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_DEEPLY_NESTED),
        "f_deeply_nested should be absent"
    );
    // Required field should be present
    assert!(
        parsed.has_field(all_types_ordinals::F_REQUIRED),
        "f_required should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_REQUIRED),
        Some(&FieldValueRef::Int32(1))
    );
    // Empty repeated fields
    assert_eq!(
        parsed
            .get_repeated_scalars(all_types_ordinals::F_REPEATED_INT32)
            .len(),
        0
    );
    assert_eq!(
        parsed
            .get_repeated_scalars(all_types_ordinals::F_REPEATED_STRING)
            .len(),
        0
    );
    assert_eq!(
        parsed
            .get_repeated_scalars(all_types_ordinals::F_REPEATED_PACKED)
            .len(),
        0
    );
    assert_eq!(
        parsed
            .get_repeated_scalars(all_types_ordinals::F_REPEATED_UNPACKED)
            .len(),
        0
    );
    assert_eq!(
        parsed
            .get_repeated_messages(all_types_ordinals::F_REPEATED_MESSAGE)
            .len(),
        0
    );
    // Empty maps
    assert_eq!(
        parsed.get_map_entries_count(all_types_ordinals::F_MAP_INT_STRING),
        0
    );
    assert_eq!(
        parsed.get_map_entries_count(all_types_ordinals::F_MAP_STRING_STRING),
        0
    );
    assert_eq!(
        parsed.get_map_entries_count(all_types_ordinals::F_MAP_STRING_MESSAGE),
        0
    );
    // Oneof should have no value set
    assert!(
        !parsed.has_field(all_types_ordinals::F_ONEOF_INT),
        "oneof_int should not be set"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_ONEOF_STRING),
        "oneof_string should not be set"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_ONEOF_MESSAGE),
        "oneof_message should not be set"
    );
    // Empty repeated enum
    assert_eq!(
        parsed
            .get_repeated_scalars(all_types_ordinals::F_REPEATED_ENUM)
            .len(),
        0
    );
    // Large field numbers should be absent
    assert!(
        !parsed.has_field(all_types_ordinals::F_LARGE_FIELD_150),
        "f_large_field_150 should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_LARGE_FIELD_200),
        "f_large_field_200 should be absent"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_LARGE_FIELD_300),
        "f_large_field_300 should be absent"
    );

    // Required field should be present in proto2
    if version == ProtoVersion::Proto2 {
        assert!(
            parsed.has_field(all_types_ordinals::F_REQUIRED),
            "f_required should be present"
        );
        assert_eq!(
            parsed.get_scalar(all_types_ordinals::F_REQUIRED),
            Some(&FieldValueRef::Int32(1))
        );
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_complex_nested_with_null_values(#[case] version: ProtoVersion) {
    let msg = proto2::ComplexNested {
        // Test null at top level
        id: None,
        name: Some("partial".to_string()),
        // Test nested message with null fields
        inner: Some(proto2::complex_nested::InnerData {
            value: None,
            data: None,
            numbers: vec![],
        }),
        // Empty repeated scalars
        int_list: vec![],
        string_list: vec![],
        bool_list: vec![],
        // Repeated messages with mixed null values
        inner_list: vec![
            proto2::complex_nested::InnerData {
                value: Some(111),
                data: None,
                numbers: vec![],
            },
            proto2::complex_nested::InnerData {
                value: None,
                data: Some(vec![0xBB]),
                numbers: vec![],
            },
            proto2::complex_nested::InnerData {
                value: None,
                data: None,
                numbers: vec![1, 2, 3],
            },
        ],
        // Empty maps
        string_to_int: Default::default(),
        int_to_string: Default::default(),
        string_to_message: Default::default(),
        // Null nested message with maps
        data_with_maps: None,
        // Empty repeated complex items
        items: vec![],
        // Test tree with partial values
        tree: Some(proto2::complex_nested::TreeNode {
            value: Some(42),
            label: None,
            children: vec![],
            left: None,
            right: Some(Box::new(proto2::complex_nested::TreeNode {
                value: None,
                label: Some("right-only".to_string()),
                children: vec![],
                left: None,
                right: None,
            })),
        }),
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "ComplexNested");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    match version {
        ProtoVersion::Proto2 => {
            // Top level null field
            assert!(
                !parsed.has_field(complex_nested_fields::ID),
                "id should be absent"
            );
            assert_eq!(
                parsed.get_scalar(complex_nested_fields::NAME),
                Some(&FieldValueRef::String("partial"))
            );

            // Nested message with null fields
            let inner = parsed
                .get_message(complex_nested_fields::INNER)
                .expect("inner should be present");
            assert!(
                !inner.has_field(complex_nested_fields::inner_data::VALUE),
                "inner.value should be absent"
            );
            assert!(
                !inner.has_field(complex_nested_fields::inner_data::DATA),
                "inner.data should be absent"
            );
            assert_eq!(
                inner
                    .get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS)
                    .len(),
                0
            );
        }
        ProtoVersion::Proto3 => {
            // Proto3 doesn't encode zero values
            assert!(
                !parsed.has_field(complex_nested_fields::ID),
                "id (zero) should not be encoded"
            );
            assert_eq!(
                parsed.get_scalar(complex_nested_fields::NAME),
                Some(&FieldValueRef::String("partial"))
            );

            // Nested message with zero/empty values
            let inner = parsed
                .get_message(complex_nested_fields::INNER)
                .expect("inner should be present");
            assert!(
                !inner.has_field(complex_nested_fields::inner_data::VALUE),
                "inner.value (zero) should not be encoded"
            );
            assert!(
                !inner.has_field(complex_nested_fields::inner_data::DATA),
                "inner.data (empty) should not be encoded"
            );
            assert_eq!(
                inner
                    .get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS)
                    .len(),
                0
            );
        }
    }

    // Empty repeated fields
    assert_eq!(
        parsed
            .get_repeated_scalars(complex_nested_fields::INT_LIST)
            .len(),
        0
    );
    assert_eq!(
        parsed
            .get_repeated_scalars(complex_nested_fields::STRING_LIST)
            .len(),
        0
    );
    assert_eq!(
        parsed
            .get_repeated_scalars(complex_nested_fields::BOOL_LIST)
            .len(),
        0
    );

    // Repeated messages with partial null values
    let inner_list = parsed.get_repeated_messages(complex_nested_fields::INNER_LIST);
    assert_eq!(inner_list.len(), 3);

    // First item: has value, no data, no numbers
    assert_eq!(
        inner_list[0].get_scalar(complex_nested_fields::inner_data::VALUE),
        Some(&FieldValueRef::Int64(111))
    );
    assert!(!inner_list[0].has_field(complex_nested_fields::inner_data::DATA));
    assert_eq!(
        inner_list[0]
            .get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS)
            .len(),
        0
    );

    // Second item: no value, has data, no numbers
    match version {
        ProtoVersion::Proto2 => {
            assert!(!inner_list[1].has_field(complex_nested_fields::inner_data::VALUE))
        }
        ProtoVersion::Proto3 => {
            assert!(!inner_list[1].has_field(complex_nested_fields::inner_data::VALUE))
        }
    }
    assert_eq!(
        inner_list[1].get_scalar(complex_nested_fields::inner_data::DATA),
        Some(&FieldValueRef::Bytes(&[0xBB]))
    );
    assert_eq!(
        inner_list[1]
            .get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS)
            .len(),
        0
    );

    // Third item: no value, no data, has numbers
    match version {
        ProtoVersion::Proto2 => {
            assert!(!inner_list[2].has_field(complex_nested_fields::inner_data::VALUE))
        }
        ProtoVersion::Proto3 => {
            assert!(!inner_list[2].has_field(complex_nested_fields::inner_data::VALUE))
        }
    }
    assert!(!inner_list[2].has_field(complex_nested_fields::inner_data::DATA));
    assert_eq!(
        inner_list[2]
            .get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS)
            .len(),
        3
    );

    // Empty maps
    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::STRING_TO_INT),
        0
    );
    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::INT_TO_STRING),
        0
    );
    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::STRING_TO_MESSAGE),
        0
    );

    // Null nested message
    assert!(
        !parsed.has_field(complex_nested_fields::DATA_WITH_MAPS),
        "data_with_maps should be absent"
    );

    // Empty repeated complex items
    assert_eq!(
        parsed
            .get_repeated_messages(complex_nested_fields::ITEMS)
            .len(),
        0
    );

    // Test tree with partial values
    let tree_root = parsed
        .get_message(complex_nested_fields::TREE)
        .expect("tree should be present");

    assert_eq!(
        tree_root.get_scalar(complex_nested_fields::tree_node::VALUE),
        Some(&FieldValueRef::Int32(42))
    );

    match version {
        ProtoVersion::Proto2 => {
            assert!(
                !tree_root.has_field(complex_nested_fields::tree_node::LABEL),
                "label should be absent in proto2"
            );
        }
        ProtoVersion::Proto3 => {
            assert!(
                !tree_root.has_field(complex_nested_fields::tree_node::LABEL),
                "label should be absent in proto3"
            );
        }
    }

    assert!(
        tree_root
            .get_message(complex_nested_fields::tree_node::LEFT)
            .is_none(),
        "left should be absent"
    );

    let tree_right = tree_root
        .get_message(complex_nested_fields::tree_node::RIGHT)
        .expect("right should be present");

    match version {
        ProtoVersion::Proto2 => {
            assert!(
                !tree_right.has_field(complex_nested_fields::tree_node::VALUE),
                "right.value should be absent in proto2"
            );
        }
        ProtoVersion::Proto3 => {
            assert!(
                !tree_right.has_field(complex_nested_fields::tree_node::VALUE),
                "right.value should be absent in proto3"
            );
        }
    }

    assert_eq!(
        tree_right.get_scalar(complex_nested_fields::tree_node::LABEL),
        Some(&FieldValueRef::String("right-only"))
    );

    assert_eq!(
        tree_right
            .get_repeated_messages(complex_nested_fields::tree_node::CHILDREN)
            .len(),
        0
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_map_duplicate_keys_last_value_wins(#[case] version: ProtoVersion) {
    use databricks_zerobus_ingest_sdk::zeroparser::types::ParsedMapValue;
    use prost::Message;

    let mut buf1 = Vec::new();
    let mut buf2 = Vec::new();

    match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_map_int_string: [(1, "first".to_string()), (2, "second".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            msg.encode(&mut buf1).unwrap();

            let msg2 = proto2::AllTypesMessage {
                f_map_int_string: [(1, "overridden".to_string()), (3, "third".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            msg2.encode(&mut buf2).unwrap();
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_map_int_string: [(1, "first".to_string()), (2, "second".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            msg.encode(&mut buf1).unwrap();

            let msg2 = proto3::AllTypesMessage {
                f_map_int_string: [(1, "overridden".to_string()), (3, "third".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            };
            msg2.encode(&mut buf2).unwrap();
        }
    }

    let mut combined = buf1.clone();
    combined.extend_from_slice(&buf2);

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let parsed = ParsedMessage::parse(&combined, &registry).unwrap();

    let map_int_string_field = field_num(version, "f_map_int_string");

    assert_eq!(
        parsed.get_map_entries_count(map_int_string_field),
        3,
        "Should have 3 unique keys"
    );

    let mut found_overridden = false;
    let mut found_second = false;
    let mut found_third = false;

    for (key, value) in parsed.get_map_entries(map_int_string_field) {
        match (*key, value) {
            (MapKeyRef::Int32(1), ParsedMapValue::Scalar(FieldValueRef::String("overridden"))) => {
                found_overridden = true
            }
            (MapKeyRef::Int32(2), ParsedMapValue::Scalar(FieldValueRef::String("second"))) => {
                found_second = true
            }
            (MapKeyRef::Int32(3), ParsedMapValue::Scalar(FieldValueRef::String("third"))) => {
                found_third = true
            }
            _ => {}
        }
    }

    assert!(
        found_overridden,
        "Key 1 should have 'overridden' (last value wins)"
    );
    assert!(found_second, "Key 2 should have 'second'");
    assert!(found_third, "Key 3 should have 'third'");
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_map_with_complex_nested_values(#[case] version: ProtoVersion) {
    use databricks_zerobus_ingest_sdk::zeroparser::types::ParsedMapValue;

    let msg = proto2::ComplexNested {
        id: Some(1),
        name: Some("test".to_string()),
        string_to_message: [(
            "nested_map".to_string(),
            proto2::complex_nested::InnerData {
                value: Some(42),
                data: Some(vec![0xAB, 0xCD]),
                numbers: vec![1, 2, 3],
            },
        )]
        .into_iter()
        .collect(),
        data_with_maps: Some(proto2::complex_nested::DataWithMaps {
            label: Some("outer".to_string()),
            properties: [
                ("key1".to_string(), "value1".to_string()),
                ("key2".to_string(), "value2".to_string()),
            ]
            .into_iter()
            .collect(),
            indices: vec![10, 20, 30],
        }),
        ..Default::default()
    };

    let (buf, registry) = encode_message_for_version(version, &msg, "ComplexNested");
    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_map_entries_count(complex_nested_fields::STRING_TO_MESSAGE),
        1
    );

    let string_to_message: Vec<_> = parsed
        .get_map_entries(complex_nested_fields::STRING_TO_MESSAGE)
        .collect();
    let (key, value) = &string_to_message[0];
    assert_eq!(**key, MapKeyRef::String("nested_map"));

    let nested_msg = match value {
        ParsedMapValue::Message(msg) => msg,
        _ => panic!("Expected message value"),
    };

    assert_eq!(
        nested_msg.get_scalar(complex_nested_fields::inner_data::VALUE),
        Some(&FieldValueRef::Int64(42))
    );
    assert_eq!(
        nested_msg.get_scalar(complex_nested_fields::inner_data::DATA),
        Some(&FieldValueRef::Bytes(&[0xAB, 0xCD]))
    );

    let numbers = nested_msg.get_repeated_scalars(complex_nested_fields::inner_data::NUMBERS);
    assert_eq!(numbers.len(), 3);
    assert_eq!(numbers[0], FieldValueRef::Int32(1));

    let data_with_maps = parsed
        .get_message(complex_nested_fields::DATA_WITH_MAPS)
        .expect("data_with_maps should be present");

    assert_eq!(
        data_with_maps.get_map_entries_count(complex_nested_fields::data_with_maps::PROPERTIES),
        2
    );

    let indices =
        data_with_maps.get_repeated_scalars(complex_nested_fields::data_with_maps::INDICES);
    assert_eq!(indices.len(), 3);
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_interleaved_repeated_fields(#[case] version: ProtoVersion) {
    use prost::Message;

    let msg1 = proto2::AllTypesMessage {
        f_repeated_int32: vec![1, 2, 3],
        f_repeated_string: vec!["first".to_string()],
        ..Default::default()
    };

    let mut buf1 = Vec::new();
    msg1.encode(&mut buf1).unwrap();

    let msg2 = proto2::AllTypesMessage {
        f_repeated_int32: vec![4, 5],
        f_repeated_string: vec!["second".to_string(), "third".to_string()],
        ..Default::default()
    };

    let mut buf2 = Vec::new();
    msg2.encode(&mut buf2).unwrap();

    let mut combined = buf1.clone();
    combined.extend_from_slice(&buf2);

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let parsed = ParsedMessage::parse(&combined, &registry).unwrap();

    let repeated_int32_field = field_num(version, "f_repeated_int32");
    let repeated_string_field = field_num(version, "f_repeated_string");

    let repeated_int32 = parsed.get_repeated_scalars(repeated_int32_field);
    assert_eq!(
        repeated_int32.len(),
        5,
        "Should accumulate all repeated int32 values"
    );
    assert_eq!(repeated_int32[0], FieldValueRef::Int32(1));
    assert_eq!(repeated_int32[1], FieldValueRef::Int32(2));
    assert_eq!(repeated_int32[2], FieldValueRef::Int32(3));
    assert_eq!(repeated_int32[3], FieldValueRef::Int32(4));
    assert_eq!(repeated_int32[4], FieldValueRef::Int32(5));

    let repeated_string = parsed.get_repeated_scalars(repeated_string_field);
    assert_eq!(
        repeated_string.len(),
        3,
        "Should accumulate all repeated string values"
    );
    assert_eq!(repeated_string[0], FieldValueRef::String("first"));
    assert_eq!(repeated_string[1], FieldValueRef::String("second"));
    assert_eq!(repeated_string[2], FieldValueRef::String("third"));
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_mixed_packed_unpacked_encoding(#[case] version: ProtoVersion) {
    use prost::encoding::{encode_key, encode_varint, WireType};

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let repeated_int32_field = field_num(version, "f_repeated_int32");

    let mut buf = Vec::new();

    encode_key(repeated_int32_field as u32, WireType::Varint, &mut buf);
    encode_varint(100, &mut buf);

    encode_key(
        repeated_int32_field as u32,
        WireType::LengthDelimited,
        &mut buf,
    );
    let mut packed_data = Vec::new();
    encode_varint(200, &mut packed_data);
    encode_varint(300, &mut packed_data);
    encode_varint(packed_data.len() as u64, &mut buf);
    buf.extend_from_slice(&packed_data);

    encode_key(repeated_int32_field as u32, WireType::Varint, &mut buf);
    encode_varint(400, &mut buf);

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
    let repeated = parsed.get_repeated_scalars(repeated_int32_field);

    assert_eq!(
        repeated.len(),
        4,
        "Should handle mixed packed and unpacked encoding"
    );
    assert_eq!(repeated[0], FieldValueRef::Int32(100));
    assert_eq!(repeated[1], FieldValueRef::Int32(200));
    assert_eq!(repeated[2], FieldValueRef::Int32(300));
    assert_eq!(repeated[3], FieldValueRef::Int32(400));
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_length_delimited_field_with_zero_length(#[case] version: ProtoVersion) {
    use prost::Message;

    let mut buf = Vec::new();
    let registry = create_registry_for_version(version, "AllTypesMessage");

    match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_string: Some("".to_string()),
                f_bytes: Some(vec![]),
                f_nested: Some(proto2::all_types_message::NestedMessage {
                    nested_id: None,
                    nested_name: None,
                }),
                ..Default::default()
            };
            msg.encode(&mut buf).unwrap();
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_string: "".to_string(),
                f_bytes: vec![],
                f_nested: Some(proto3::all_types_message::NestedMessage {
                    nested_id: 0,
                    nested_name: "".to_string(),
                }),
                ..Default::default()
            };
            msg.encode(&mut buf).unwrap();
        }
    }

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    match version {
        ProtoVersion::Proto2 => {
            assert!(
                parsed.has_field(all_types_ordinals::F_STRING),
                "Empty string should be present in proto2"
            );
            assert_eq!(
                parsed.get_scalar(all_types_ordinals::F_STRING),
                Some(&FieldValueRef::String(""))
            );

            assert!(
                parsed.has_field(all_types_ordinals::F_BYTES),
                "Empty bytes should be present in proto2"
            );
            assert_eq!(
                parsed.get_scalar(all_types_ordinals::F_BYTES),
                Some(&FieldValueRef::Bytes(&[]))
            );

            let nested = parsed
                .get_message(all_types_ordinals::F_NESTED)
                .expect("Empty nested message should be present in proto2");
            assert!(
                !nested.has_field(1),
                "Empty nested message should have no fields"
            );
            assert!(
                !nested.has_field(2),
                "Empty nested message should have no fields"
            );
        }
        ProtoVersion::Proto3 => {
            assert!(
                !parsed.has_field(all_types_ordinals::F_STRING),
                "Empty string should not be present in proto3"
            );
            assert!(
                !parsed.has_field(all_types_ordinals::F_BYTES),
                "Empty bytes should not be present in proto3"
            );

            let nested = parsed.get_message(all_types_ordinals::F_NESTED);
            if let Some(nested_msg) = nested {
                assert!(
                    !nested_msg.has_field(1),
                    "Empty nested message should have no fields"
                );
                assert!(
                    !nested_msg.has_field(2),
                    "Empty nested message should have no fields"
                );
            }
        }
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_varint_extremes(#[case] version: ProtoVersion) {
    use prost::encoding::{encode_key, encode_varint, WireType};

    let registry = create_registry_for_version(version, "AllTypesMessage");

    // Test unsigned extremes (u64)
    let f_uint64_field = all_types_ordinals::F_UINT64 as u32;
    for value in [u64::MAX, u64::MAX - 1] {
        let mut buf = Vec::new();
        encode_key(f_uint64_field, WireType::Varint, &mut buf);
        encode_varint(value, &mut buf);

        let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
        assert_eq!(
            parsed.get_scalar(all_types_ordinals::F_UINT64),
            Some(&FieldValueRef::UInt64(value))
        );
    }

    // Test signed extremes (i64)
    let f_int64_field = all_types_ordinals::F_INT64 as u32;
    for value in [i64::MAX, i64::MIN] {
        let mut buf = Vec::new();
        encode_key(f_int64_field, WireType::Varint, &mut buf);
        encode_varint(value as u64, &mut buf);

        let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
        assert_eq!(
            parsed.get_scalar(all_types_ordinals::F_INT64),
            Some(&FieldValueRef::Int64(value))
        );
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_float_double_special_edge_values(#[case] version: ProtoVersion) {
    // Test f64 extremes
    for value in [f64::MIN, f64::MAX, f64::MIN_POSITIVE] {
        let msg = proto2::AllTypesMessage {
            f_double: Some(value),
            ..Default::default()
        };
        let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

        let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
        assert_eq!(
            parsed.get_scalar(all_types_ordinals::F_DOUBLE),
            Some(&FieldValueRef::Double(value))
        );
    }

    // Test f32 extremes
    for value in [f32::MIN, f32::MAX, f32::MIN_POSITIVE] {
        let msg = proto2::AllTypesMessage {
            f_float: Some(value),
            ..Default::default()
        };
        let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

        let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
        assert_eq!(
            parsed.get_scalar(all_types_ordinals::F_FLOAT),
            Some(&FieldValueRef::Float(value))
        );
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_large_field_numbers_with_max_values(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_large_field_150: Some(i32::MAX),
        f_large_field_200: Some("x".repeat(10000)),
        f_large_field_300: Some(i64::MAX),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_LARGE_FIELD_150),
        Some(&FieldValueRef::Int32(i32::MAX))
    );

    if let Some(FieldValueRef::String(s)) = parsed.get_scalar(all_types_ordinals::F_LARGE_FIELD_200)
    {
        assert_eq!(s.len(), 10000);
    } else {
        panic!("Expected large string");
    }

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_LARGE_FIELD_300),
        Some(&FieldValueRef::Int64(i64::MAX))
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_bytes_various_patterns(#[case] version: ProtoVersion) {
    let test_patterns = vec![
        (0..=255).collect::<Vec<u8>>(), // All possible byte values
        vec![0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xAB, 0x00, 0xCD, 0x00], // Null bytes pattern
        vec![0xFF; 1000],               // All 0xFF
        vec![0x00; 1000],               // All 0x00
        vec![0xAA; 1000],               // Alternating bits
        vec![0x55; 1000],               // Alternating bits (inverse)
        (0..255).cycle().take(1000).collect::<Vec<u8>>(), // Sequential pattern
    ];

    for pattern in test_patterns {
        let (buf, registry) = match version {
            ProtoVersion::Proto2 => {
                let msg = proto2::AllTypesMessage {
                    f_required: 1,
                    f_bytes: Some(pattern.clone()),
                    ..Default::default()
                };
                encode_message_for_version(version, &msg, "AllTypesMessage")
            }
            ProtoVersion::Proto3 => {
                let msg = proto3::AllTypesMessage {
                    f_bytes: pattern.clone(),
                    ..Default::default()
                };
                encode_message_for_version(version, &msg, "AllTypesMessage")
            }
        };

        let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
        assert_eq!(
            parsed.get_scalar(all_types_ordinals::F_BYTES),
            Some(&FieldValueRef::Bytes(pattern.as_slice()))
        );
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_large_bytes_field(#[case] version: ProtoVersion) {
    // Create a 10MB byte array
    let large_bytes: Vec<u8> = (0..10_000_000).map(|i| (i % 256) as u8).collect();

    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_bytes: Some(large_bytes.clone()),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_bytes: large_bytes.clone(),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    if let Some(FieldValueRef::Bytes(bytes)) = parsed.get_scalar(all_types_ordinals::F_BYTES) {
        assert_eq!(bytes.len(), 10_000_000);
        assert_eq!(*bytes, large_bytes.as_slice());
    } else {
        panic!("Expected large bytes to be present");
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_string_various_special_characters(#[case] version: ProtoVersion) {
    let test_strings = [
        "Hello\tWorld\nNew\rLine\x00Null\x1FUnit", // Control characters + null bytes
        "Before\x00Middle\x00\x00After",           // Multiple null bytes
        "🚀🌟💻🎉",                                // Emojis
        "مرحبا بالعالم",                           // Arabic (RTL)
        "שלום עולם",                               // Hebrew (RTL)
        "こんにちは世界",                          // Japanese
        "안녕하세요 세상",                         // Korean
        "Ζεῖα καὶ ἄνθρωποι",                       // Ancient Greek
        "e̷̢̡̛̛̛͔͖̞̟̯͈̳̭̤̭͎͈̣̭̠͉̦̹̬͓̺̩͈͓̪̪̻͕̤̞̓͋̀͛̽̌̾̔͆̓̈́̄͊͐̐̓́͂̄̽̀̓͆͛͗͂̃̚̚͘͘͜͠͠͝",                                       // Combining characters
        "𝕳𝖊𝖑𝖑𝖔 𝖂𝖔𝖗𝖑𝖉",                             // Mathematical bold fraktur
        "👨‍👩‍👧‍👦",                                      // Family emoji (multiple code points)
        "🏳️‍🌈",                                      // Rainbow flag (multiple code points)
    ];

    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_string: Some(test_strings[0].to_string()),
                f_repeated_string: test_strings.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_string: test_strings[0].to_string(),
                f_repeated_string: test_strings.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_STRING),
        Some(&FieldValueRef::String(test_strings[0]))
    );

    let repeated_string_field = field_num(version, "f_repeated_string");
    let repeated = parsed.get_repeated_scalars(repeated_string_field);
    assert_eq!(repeated.len(), test_strings.len());

    for (i, expected) in test_strings.iter().enumerate() {
        assert_eq!(repeated[i], FieldValueRef::String(expected));
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_very_long_string(#[case] version: ProtoVersion) {
    // Create a 1MB string
    let long_string = "a".repeat(1_000_000);

    let (buf, registry) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::AllTypesMessage {
                f_required: 1,
                f_string: Some(long_string.clone()),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::AllTypesMessage {
                f_string: long_string.clone(),
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "AllTypesMessage")
        }
    };

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    if let Some(FieldValueRef::String(s)) = parsed.get_scalar(all_types_ordinals::F_STRING) {
        assert_eq!(s.len(), 1_000_000);
        assert_eq!(s, &long_string);
    } else {
        panic!("Expected long string to be present");
    }
}

// ============================================================================
// NEGATIVE TESTS FOR BOTH PROTO2 AND PROTO3
// ============================================================================

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_empty_buffer(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    let empty_buf: &[u8] = &[];
    let parsed = ParsedMessage::parse(empty_buf, &registry).unwrap();
    assert!(!parsed.has_field(1), "Empty message should have no fields");
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_truncated_varint(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_int32 is at field number 29, wire type 0 (Varint)
    // Tag = (29 << 3) | 0 = 232 = 0xE8
    let malformed = vec![0xE8, 0x01, 0xFF];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::TruncatedVarint)),
        "Expected TruncatedVarint error, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_varint_too_long(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_int32 is at field number 29, wire type 0 (Varint)
    // Tag = (29 << 3) | 0 = 232 = 0xE8
    let mut malformed = vec![0xE8, 0x01];
    malformed.extend(std::iter::repeat_n(0xFF, 10));
    malformed.push(0xFF);

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::VarintTooLong)),
        "Expected VarintTooLong error, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_invalid_wire_type(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    let malformed = vec![0x0E, 0x00];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::InvalidWireType(6))),
        "Expected InvalidWireType(6) error, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_truncated_fields(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");

    let test_cases = vec![
        (
            vec![0x62, 0x64, b'h', b'e', b'l', b'l', b'o'], // Truncated length-delimited (string)
            "truncated length-delimited field",
        ),
        (
            vec![0xFD, 0x01, 0x01, 0x02], // Truncated fixed32 (needs 4 bytes)
            "truncated fixed32 field",
        ),
        (
            vec![0x29, 0x01, 0x02, 0x03], // Truncated fixed64 (needs 8 bytes)
            "truncated fixed64 field",
        ),
    ];

    for (malformed, description) in test_cases {
        let result = ParsedMessage::parse(&malformed, &registry);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort { .. })),
            "Expected BufferTooShort error for {}, got {:?}",
            description,
            result
        );
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_invalid_utf8_string(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_string is now at field number 12, wire type 2 (length-delimited)
    // Tag = (12 << 3) | 2 = 98 = 0x62
    let malformed = vec![0x62, 0x04, 0xFF, 0xFE, 0xFD, 0xFC];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::InvalidUtf8 { .. })),
        "Expected InvalidUtf8 error, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_unsupported_group_wire_type(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    let malformed = vec![0x0B];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::UnsupportedGroupWireType)),
        "Expected UnsupportedGroupWireType error, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_truncated_nested_message(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_nested is at field number 4, wire type 2 (Length-delimited)
    // Tag = (4 << 3) | 2 = 34 = 0x22
    let mut malformed = vec![0x22];
    malformed.push(0x32);
    malformed.extend_from_slice(&[0x08, 0x01, 0x12]);

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::BufferTooShort { .. })),
        "Expected BufferTooShort error for truncated nested message, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_partial_field_tag(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    let malformed = vec![0x80];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::TruncatedVarint)),
        "Expected TruncatedVarint error for partial field tag, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_wire_type_mismatch(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_string (field 12) expects Length-delimited (wire type 2)
    // Send it as Varint (wire type 0): tag = (12 << 3) | 0 = 96 = 0x60
    let mismatched = vec![0x60, 0x42];

    let result = ParsedMessage::parse(&mismatched, &registry);
    assert!(
        matches!(result, Err(ParseError::TypeMismatch { .. })),
        "Expected TypeMismatch error for wire type mismatch, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_overflow_length(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_string is now at field number 12, wire type 2 (length-delimited)
    // Tag = (12 << 3) | 2 = 98 = 0x62
    let malformed = vec![
        0x62, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, b'h', b'e', b'l', b'l',
        b'o',
    ];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::BufferTooShort { .. })),
        "Expected BufferTooShort error for overflow length, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_invalid_field_numbers(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");

    let test_cases = vec![
        (vec![0x00, 0x42], "field number 0"),
        (
            vec![0x80, 0x80, 0x80, 0x80, 0x10, 0x42],
            "field number > max",
        ),
    ];

    for (malformed, description) in test_cases {
        let result = ParsedMessage::parse(&malformed, &registry);
        assert!(
            matches!(result, Err(ParseError::InvalidFieldNumber { .. })),
            "Expected InvalidFieldNumber error for {}, got {:?}",
            description,
            result
        );
    }
}

#[test]
fn test_unknown_type_name() {
    let field = FieldDescriptorProto {
        name: Some("missing_nested".to_string()),
        number: Some(1),
        label: Some(prost_types::field_descriptor_proto::Label::Optional as i32),
        r#type: Some(Type::Message as i32),
        type_name: Some(".NonExistentMessage".to_string()),
        ..Default::default()
    };

    let descriptor = DescriptorProto {
        name: Some("TestMessage".to_string()),
        field: vec![field],
        ..Default::default()
    };

    let registry = MessageRegistry::from_descriptor(&descriptor);

    let malformed = vec![0x0A, 0x02, 0x08, 0x2A];

    let result = ParsedMessage::parse(&malformed, &registry);
    assert!(
        matches!(result, Err(ParseError::UnknownTypeName { .. })),
        "Expected UnknownTypeName error, got {:?}",
        result
    );
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_invalid_utf8_various_errors(#[case] version: ProtoVersion) {
    let registry = create_registry_for_version(version, "AllTypesMessage");
    // Field f_string is at field number 12, wire type 2 (length-delimited)
    // Tag = (12 << 3) | 2 = 98 = 0x62

    // Test various invalid UTF-8 byte sequences
    let test_cases = vec![
        (vec![0x62, 0x02, 0xC0, 0x81], "overlong encoding"),
        (vec![0x62, 0x02, 0xC2, 0x00], "invalid continuation byte"),
        (vec![0x62, 0x02, 0xE0, 0xA0], "truncated multibyte sequence"),
        (
            vec![0x62, 0x03, 0xED, 0xA0, 0x80],
            "UTF-16 surrogate halves",
        ),
        (
            vec![0x62, 0x03, 0x80, 0x80, 0x80],
            "continuation without start byte",
        ),
        (
            vec![0x62, 0x04, 0xF5, 0x80, 0x80, 0x80],
            "invalid 4-byte sequence (out of range)",
        ),
    ];

    for (malformed, description) in test_cases {
        let result = ParsedMessage::parse(&malformed, &registry);
        assert!(
            matches!(result, Err(ParseError::InvalidUtf8 { .. })),
            "Expected InvalidUtf8 error for {}, got {:?}",
            description,
            result
        );
    }
}

#[rstest]
#[case(ProtoVersion::Proto2)]
#[case(ProtoVersion::Proto3)]
fn test_google_protobuf_types_not_in_registry(#[case] version: ProtoVersion) {
    use prost_types::{Duration, Timestamp};

    let registry = create_registry_for_version(version, "GoogleProtobufTypesMessage");

    // Test google.protobuf types (Timestamp/Duration)
    let (buf_timestamp, _) = match version {
        ProtoVersion::Proto2 => {
            let msg = proto2::GoogleProtobufTypesMessage {
                timestamp: Some(Timestamp {
                    seconds: 1234567890,
                    nanos: 123456789,
                }),
                duration: Some(Duration {
                    seconds: 3600,
                    nanos: 500000000,
                }),
                timestamps: vec![
                    Timestamp {
                        seconds: 1000000000,
                        nanos: 0,
                    },
                    Timestamp {
                        seconds: 2000000000,
                        nanos: 999999999,
                    },
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "GoogleProtobufTypesMessage")
        }
        ProtoVersion::Proto3 => {
            let msg = proto3::GoogleProtobufTypesMessage {
                timestamp: Some(Timestamp {
                    seconds: 1234567890,
                    nanos: 123456789,
                }),
                duration: Some(Duration {
                    seconds: 3600,
                    nanos: 500000000,
                }),
                timestamps: vec![
                    Timestamp {
                        seconds: 1000000000,
                        nanos: 0,
                    },
                    Timestamp {
                        seconds: 2000000000,
                        nanos: 999999999,
                    },
                ],
                ..Default::default()
            };
            encode_message_for_version(version, &msg, "GoogleProtobufTypesMessage")
        }
    };

    let result = ParsedMessage::parse(&buf_timestamp, &registry);
    assert!(
        matches!(result, Err(ParseError::UnknownTypeName { .. })),
        "Expected UnknownTypeName error for google.protobuf.Timestamp, got {:?}",
        result
    );

    // Test wrapper types (manually encoded)
    let mut buf_wrappers = Vec::new();

    // StringValue (field 3) - message with field 1 = string
    let mut string_value_buf = Vec::new();
    prost::encoding::string::encode(1, &"wrapped_string".to_string(), &mut string_value_buf);
    prost::encoding::message::encode(3, &string_value_buf, &mut buf_wrappers);

    // Int32Value (field 4) - message with field 1 = int32
    let mut int32_value_buf = Vec::new();
    prost::encoding::int32::encode(1, &-42, &mut int32_value_buf);
    prost::encoding::message::encode(4, &int32_value_buf, &mut buf_wrappers);

    let result = ParsedMessage::parse(&buf_wrappers, &registry);
    assert!(
        matches!(result, Err(ParseError::UnknownTypeName { .. })),
        "Expected UnknownTypeName error for google.protobuf wrapper types, got {:?}",
        result
    );
}

// ============================================================================
// PROTO2-ONLY TESTS
// ============================================================================

#[rstest]
#[case(ProtoVersion::Proto2)]
fn test_proto2_required_and_default_values(#[case] version: ProtoVersion) {
    // Test required fields and absent default fields
    let msg_unset = proto2::AllTypesMessage {
        f_required: 42,
        ..Default::default()
    };
    let (buf_unset, registry_unset) =
        encode_message_for_version(version, &msg_unset, "AllTypesMessage");
    let parsed_unset = ParsedMessage::parse(&buf_unset, &registry_unset).unwrap();

    assert!(
        parsed_unset.has_field(all_types_ordinals::F_REQUIRED),
        "f_required should be present"
    );
    assert_eq!(
        parsed_unset.get_scalar(all_types_ordinals::F_REQUIRED),
        Some(&FieldValueRef::Int32(42))
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals::F_INT32),
        "f_int32 should be absent"
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals::F_STRING),
        "f_string should be absent"
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals::F_DEFAULT_INT),
        "f_default_int should be absent when not set"
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals::F_DEFAULT_STRING),
        "f_default_string should be absent when not set"
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals::F_DEFAULT_BOOL),
        "f_default_bool should be absent when not set"
    );

    // Test default values when explicitly set
    let msg_set = proto2::AllTypesMessage {
        f_required: 1,
        f_default_int: Some(42),
        f_default_string: Some("default_value".to_string()),
        f_default_bool: Some(true),
        ..Default::default()
    };
    let (buf_set, registry_set) = encode_message_for_version(version, &msg_set, "AllTypesMessage");
    let parsed_set = ParsedMessage::parse(&buf_set, &registry_set).unwrap();

    assert!(
        parsed_set.has_field(all_types_ordinals::F_DEFAULT_INT),
        "f_default_int should be present when explicitly set"
    );
    assert_eq!(
        parsed_set.get_scalar(all_types_ordinals::F_DEFAULT_INT),
        Some(&FieldValueRef::Int32(42))
    );
    assert!(
        parsed_set.has_field(all_types_ordinals::F_DEFAULT_STRING),
        "f_default_string should be present when explicitly set"
    );
    assert_eq!(
        parsed_set.get_scalar(all_types_ordinals::F_DEFAULT_STRING),
        Some(&FieldValueRef::String("default_value"))
    );
    assert!(
        parsed_set.has_field(all_types_ordinals::F_DEFAULT_BOOL),
        "f_default_bool should be present when explicitly set"
    );
    assert_eq!(
        parsed_set.get_scalar(all_types_ordinals::F_DEFAULT_BOOL),
        Some(&FieldValueRef::Bool(true))
    );

    // Test custom non-default values
    let msg_custom = proto2::AllTypesMessage {
        f_required: 1,
        f_default_int: Some(100),
        f_default_string: Some("custom".to_string()),
        f_default_bool: Some(false),
        ..Default::default()
    };
    let (buf_custom, registry_custom) =
        encode_message_for_version(version, &msg_custom, "AllTypesMessage");
    let parsed_custom = ParsedMessage::parse(&buf_custom, &registry_custom).unwrap();

    assert_eq!(
        parsed_custom.get_scalar(all_types_ordinals::F_DEFAULT_INT),
        Some(&FieldValueRef::Int32(100))
    );
    assert_eq!(
        parsed_custom.get_scalar(all_types_ordinals::F_DEFAULT_STRING),
        Some(&FieldValueRef::String("custom"))
    );
    assert_eq!(
        parsed_custom.get_scalar(all_types_ordinals::F_DEFAULT_BOOL),
        Some(&FieldValueRef::Bool(false))
    );
}

// Proto2-specific test: zero values are encoded
#[rstest]
#[case(ProtoVersion::Proto2)]
fn test_zero_values_proto2(#[case] version: ProtoVersion) {
    let msg = proto2::AllTypesMessage {
        f_int32: Some(0),
        f_int64: Some(0),
        f_uint32: Some(0),
        f_uint64: Some(0),
        f_float: Some(0.0),
        f_double: Some(0.0),
        f_bool: Some(false),
        f_string: Some("".to_string()),
        f_bytes: Some(vec![]),
        f_enum: Some(proto2::Status::Unknown.into()),
        f_required: 0,
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert!(
        parsed.has_field(all_types_ordinals::F_INT32),
        "f_int32 should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT32),
        Some(&FieldValueRef::Int32(0))
    );
    assert!(
        parsed.has_field(all_types_ordinals::F_INT64),
        "f_int64 should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_INT64),
        Some(&FieldValueRef::Int64(0))
    );
    assert!(
        parsed.has_field(all_types_ordinals::F_BOOL),
        "f_bool should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_BOOL),
        Some(&FieldValueRef::Bool(false))
    );
    assert!(
        parsed.has_field(all_types_ordinals::F_STRING),
        "f_string should be present"
    );
    assert_eq!(
        parsed.get_scalar(all_types_ordinals::F_STRING),
        Some(&FieldValueRef::String(""))
    );
}

// ============================================================================
// PROTO3-ONLY TESTS
// ============================================================================

#[rstest]
#[case(ProtoVersion::Proto3)]
fn test_explicit_optional_fields(#[case] version: ProtoVersion) {
    // Test with zero values set
    let msg_set = proto3::AllTypesMessage {
        f_optional_int32: Some(0),
        f_optional_string: Some("".to_string()),
        f_optional_bool: Some(false),
        ..Default::default()
    };
    let (buf_set, registry_set) = encode_message_for_version(version, &msg_set, "AllTypesMessage");
    let parsed_set = ParsedMessage::parse(&buf_set, &registry_set).unwrap();

    // Explicit optional fields should be present even with zero values
    assert!(
        parsed_set.has_field(all_types_ordinals_proto3::F_OPTIONAL_INT32),
        "f_optional_int32 should be present when set to 0"
    );
    assert_eq!(
        parsed_set.get_scalar(all_types_ordinals_proto3::F_OPTIONAL_INT32),
        Some(&FieldValueRef::Int32(0))
    );
    assert!(
        parsed_set.has_field(all_types_ordinals_proto3::F_OPTIONAL_STRING),
        "f_optional_string should be present when set to empty"
    );
    assert_eq!(
        parsed_set.get_scalar(all_types_ordinals_proto3::F_OPTIONAL_STRING),
        Some(&FieldValueRef::String(""))
    );
    assert!(
        parsed_set.has_field(all_types_ordinals_proto3::F_OPTIONAL_BOOL),
        "f_optional_bool should be present when set to false"
    );
    assert_eq!(
        parsed_set.get_scalar(all_types_ordinals_proto3::F_OPTIONAL_BOOL),
        Some(&FieldValueRef::Bool(false))
    );

    // Test with fields unset
    let msg_unset = proto3::AllTypesMessage {
        f_optional_int32: None,
        f_optional_string: None,
        f_optional_bool: None,
        ..Default::default()
    };
    let (buf_unset, registry_unset) =
        encode_message_for_version(version, &msg_unset, "AllTypesMessage");
    let parsed_unset = ParsedMessage::parse(&buf_unset, &registry_unset).unwrap();

    // Unset optional fields should be absent
    assert!(
        !parsed_unset.has_field(all_types_ordinals_proto3::F_OPTIONAL_INT32),
        "f_optional_int32 should be absent when unset"
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals_proto3::F_OPTIONAL_STRING),
        "f_optional_string should be absent when unset"
    );
    assert!(
        !parsed_unset.has_field(all_types_ordinals_proto3::F_OPTIONAL_BOOL),
        "f_optional_bool should be absent when unset"
    );
}

// In proto3, zero values are not encoded
#[rstest]
#[case(ProtoVersion::Proto3)]
fn test_zero_values_proto3(#[case] version: ProtoVersion) {
    let msg = proto3::AllTypesMessage {
        f_int32: 0,
        f_int64: 0,
        f_uint32: 0,
        f_uint64: 0,
        f_float: 0.0,
        f_double: 0.0,
        f_bool: false,
        f_string: "".to_string(),
        f_bytes: vec![],
        f_enum: proto3::Status::Unknown.into(),
        ..Default::default()
    };
    let (buf, registry) = encode_message_for_version(version, &msg, "AllTypesMessage");

    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();

    assert!(
        !parsed.has_field(all_types_ordinals::F_INT32),
        "f_int32 zero value should not be present"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_INT64),
        "f_int64 zero value should not be present"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_BOOL),
        "f_bool false should not be present"
    );
    assert!(
        !parsed.has_field(all_types_ordinals::F_STRING),
        "f_string empty should not be present"
    );
}

#[rstest]
#[case(ProtoVersion::Proto3)]
fn test_proto3_packed_vs_unpacked_encoding(#[case] version: ProtoVersion) {
    use prost::encoding::{encode_key, encode_varint, WireType};

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let repeated_int32_field = field_num(version, "f_repeated_int32");

    let mut buf_packed = Vec::new();
    encode_key(
        repeated_int32_field as u32,
        WireType::LengthDelimited,
        &mut buf_packed,
    );
    let values = vec![10, 20, 30];
    let mut packed_data = Vec::new();
    for val in &values {
        encode_varint(*val as u64, &mut packed_data);
    }
    encode_varint(packed_data.len() as u64, &mut buf_packed);
    buf_packed.extend_from_slice(&packed_data);

    let parsed_packed = ParsedMessage::parse(&buf_packed, &registry).unwrap();
    let repeated_packed = parsed_packed.get_repeated_scalars(repeated_int32_field);
    assert_eq!(repeated_packed.len(), 3);
    assert_eq!(repeated_packed[0], FieldValueRef::Int32(10));
    assert_eq!(repeated_packed[1], FieldValueRef::Int32(20));
    assert_eq!(repeated_packed[2], FieldValueRef::Int32(30));

    let mut buf_unpacked = Vec::new();
    for val in &values {
        encode_key(
            repeated_int32_field as u32,
            WireType::Varint,
            &mut buf_unpacked,
        );
        encode_varint(*val as u64, &mut buf_unpacked);
    }

    let parsed_unpacked = ParsedMessage::parse(&buf_unpacked, &registry).unwrap();
    let repeated_unpacked = parsed_unpacked.get_repeated_scalars(repeated_int32_field);
    assert_eq!(repeated_unpacked.len(), 3);
    assert_eq!(repeated_unpacked[0], FieldValueRef::Int32(10));
    assert_eq!(repeated_unpacked[1], FieldValueRef::Int32(20));
    assert_eq!(repeated_unpacked[2], FieldValueRef::Int32(30));
}

#[rstest]
#[case(ProtoVersion::Proto2)]
fn test_proto2_packed_unpacked_cross_acceptance(#[case] version: ProtoVersion) {
    // Spec: a repeated primitive field declared with `[packed = true]` must
    // still accept unpacked wire bytes, and vice versa. proto2's
    // `f_repeated_packed` is declared `[packed = true]`, `f_repeated_unpacked`
    // is declared `[packed = false]`. Both must round-trip under either wire
    // encoding.
    use prost::encoding::{encode_key, encode_varint, WireType};

    let registry = create_registry_for_version(version, "AllTypesMessage");
    let packed_field = field_num(version, "f_repeated_packed");
    let unpacked_field = field_num(version, "f_repeated_unpacked");
    let values = [10i32, 20, 30];
    let expected = [
        FieldValueRef::Int32(10),
        FieldValueRef::Int32(20),
        FieldValueRef::Int32(30),
    ];

    // (A) `[packed = true]` field encoded with UNPACKED wire bytes.
    let mut buf = Vec::new();
    for v in &values {
        encode_key(packed_field as u32, WireType::Varint, &mut buf);
        encode_varint(*v as u64, &mut buf);
    }
    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
    assert_eq!(
        parsed.get_repeated_scalars(packed_field),
        &expected,
        "field declared `packed = true` must accept unpacked wire encoding"
    );

    // (B) `[packed = false]` field encoded with PACKED wire bytes.
    let mut buf = Vec::new();
    encode_key(unpacked_field as u32, WireType::LengthDelimited, &mut buf);
    let mut payload = Vec::new();
    for v in &values {
        encode_varint(*v as u64, &mut payload);
    }
    encode_varint(payload.len() as u64, &mut buf);
    buf.extend_from_slice(&payload);
    let parsed = ParsedMessage::parse(&buf, &registry).unwrap();
    assert_eq!(
        parsed.get_repeated_scalars(unpacked_field),
        &expected,
        "field declared `packed = false` must accept packed wire encoding"
    );
}
