//! Single-pass recursive protobuf parsing.

use std::collections::HashMap;

use prost_types::field_descriptor_proto::Type;

use super::errors::{ParseError, ParseResult};
use super::registry::{DescriptorWithFieldCache, FieldInfo, MessageRegistry};
use super::types::{
    convert_scalar_value, default_value_for_type, ComplexType, FieldValueRef, MapKeyRef,
    PackedField, ParsedMapValue, MAP_ENTRY_KEY_FIELD_NUM, MAP_ENTRY_VALUE_FIELD_NUM,
    MAX_NESTING_DEPTH,
};
use super::wire::{try_parse_field, WireValue};

/// Pre-parsed message with all nested messages recursively parsed in a single pass.
/// Uses separate storage for scalars (hot path) vs complex fields.
#[derive(Debug)]
pub struct ParsedMessage<'a> {
    /// Scalar storage - direct Option<FieldValueRef> to optimize for hot path.
    /// Index corresponds to FieldInfo.storage_index for scalar fields.
    scalars: Box<[Option<FieldValueRef<'a>>]>,
    /// Complex field storage (messages, repeated, maps).
    /// Index corresponds to FieldInfo.storage_index for non-scalar fields.
    complex: Box<[ComplexType<'a>]>,
    /// Reference to the descriptor for ordinal -> index lookups.
    descriptor: &'a DescriptorWithFieldCache,
}

impl<'a> ParsedMessage<'a> {
    /// Creates a new ParsedMessage with separate scalar and complex arrays.
    #[inline(always)]
    fn with_descriptor(descriptor: &'a DescriptorWithFieldCache) -> Self {
        let scalars = vec![None; descriptor.scalar_count].into_boxed_slice();
        let complex = (0..descriptor.complex_count)
            .map(|_| ComplexType::Empty)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            scalars,
            complex,
            descriptor,
        }
    }

    #[inline(always)]
    pub fn has_field(&self, field_num: i32) -> bool {
        let Some(field_info) = self.descriptor.get_field(field_num) else {
            return false;
        };
        if field_info.is_scalar {
            self.scalars[field_info.storage_index].is_some()
        } else {
            !matches!(self.complex[field_info.storage_index], ComplexType::Empty)
        }
    }

    #[inline(always)]
    pub fn get_field(&self, field_num: i32) -> Option<ParsedFieldValue<'_, 'a>> {
        let field_info = self.descriptor.get_field(field_num)?;
        Some(if field_info.is_scalar {
            ParsedFieldValue::Scalar(self.scalars[field_info.storage_index]?)
        } else {
            ParsedFieldValue::Complex(&self.complex[field_info.storage_index])
        })
    }

    // Get a scalar field value. Returns None if not present.
    #[inline(always)]
    pub fn get_scalar(&self, field_num: i32) -> Option<&FieldValueRef<'a>> {
        let field_info = self.descriptor.get_field(field_num)?;
        self.scalars[field_info.storage_index].as_ref()
    }

    /// Get a message field value. Returns None if not present.
    pub fn get_message(&self, field_num: i32) -> Option<&ParsedMessage<'a>> {
        let field_info = self.descriptor.get_field(field_num)?;
        match &self.complex[field_info.storage_index] {
            ComplexType::Message(m) => Some(m),
            _ => None,
        }
    }

    // Get repeated scalar values. Returns empty slice if not present.
    #[inline(always)]
    pub fn get_repeated_scalars(&self, field_num: i32) -> &[FieldValueRef<'a>] {
        self.descriptor
            .get_field(field_num)
            .and_then(|f| match &self.complex[f.storage_index] {
                ComplexType::RepeatedScalar(v) => Some(v.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Get repeated message values. Returns empty slice if not present.
    pub fn get_repeated_messages(&self, field_num: i32) -> &[ParsedMessage<'a>] {
        self.descriptor
            .get_field(field_num)
            .and_then(|f| match &self.complex[f.storage_index] {
                ComplexType::RepeatedMessage(v) => Some(v.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Returns an iterator over map entries for the given field number.
    pub fn get_map_entries(
        &self,
        field_num: i32,
    ) -> impl Iterator<Item = (&MapKeyRef<'a>, &ParsedMapValue<'a>)> {
        self.descriptor
            .get_field(field_num)
            .and_then(|f| match &self.complex[f.storage_index] {
                ComplexType::Map(m) => Some(m),
                _ => None,
            })
            .into_iter()
            .flat_map(|m| m.iter())
    }

    /// Returns the number of map entries for the given field number.
    pub fn get_map_entries_count(&self, field_num: i32) -> usize {
        self.descriptor
            .get_field(field_num)
            .and_then(|f| match &self.complex[f.storage_index] {
                ComplexType::Map(m) => Some(m.len()),
                _ => None,
            })
            .unwrap_or(0)
    }

    #[inline(always)]
    fn set_scalar(&mut self, field_info: &FieldInfo, value: FieldValueRef<'a>) {
        self.scalars[field_info.storage_index] = Some(value);
    }

    /// Singular embedded message: if a value already exists at this slot,
    /// merge per protobuf `MergeFrom` semantics; otherwise install it. Callers
    /// must run `clear_oneof_siblings` first if the field is in a oneof — that
    /// preserves the spec rule that any oneof write clears its siblings while
    /// still allowing repeats of the same oneof member to merge with themselves.
    #[inline(always)]
    fn merge_or_set_message(&mut self, field_info: &FieldInfo, value: ParsedMessage<'a>) {
        let slot = &mut self.complex[field_info.storage_index];
        if let ComplexType::Message(existing) = slot {
            existing.merge_from(value);
        } else {
            *slot = ComplexType::Message(value);
        }
    }

    /// Protobuf `MergeFrom` semantics:
    /// - Singular scalars in `other` overwrite those in `self`.
    /// - Singular embedded messages are merged recursively.
    /// - Repeated fields are concatenated (`other` appended to `self`).
    /// - Map entries from `other` overwrite same-key entries in `self`.
    /// - Oneof: if `other` has any member set in a group, the other members
    ///   in `self` for that group are cleared first.
    ///
    /// Both messages must share the same descriptor.
    #[inline(always)]
    fn merge_from(&mut self, other: ParsedMessage<'a>) {
        debug_assert!(
            std::ptr::eq(self.descriptor, other.descriptor),
            "merge_from requires both messages to share a descriptor"
        );

        // Clear oneof siblings in self for any group active in other. `other`
        // was itself parsed with sibling-clearing, so at most one member is set
        // per group there.
        for group in self.descriptor.oneof_groups() {
            let active = group.iter().find(|m| {
                if m.is_scalar {
                    other.scalars[m.storage_index].is_some()
                } else {
                    !matches!(other.complex[m.storage_index], ComplexType::Empty)
                }
            });
            if let Some(active) = active {
                for m in group {
                    if m.is_scalar == active.is_scalar && m.storage_index == active.storage_index {
                        continue;
                    }
                    if m.is_scalar {
                        self.scalars[m.storage_index] = None;
                    } else {
                        self.complex[m.storage_index] = ComplexType::Empty;
                    }
                }
            }
        }

        let other_scalars = Vec::from(other.scalars);
        for (slot, value) in self.scalars.iter_mut().zip(other_scalars) {
            if value.is_some() {
                *slot = value;
            }
        }

        let other_complex = Vec::from(other.complex);
        for (slot, value) in self.complex.iter_mut().zip(other_complex) {
            match value {
                ComplexType::Empty => {}
                ComplexType::Message(om) => {
                    if let ComplexType::Message(sm) = slot {
                        sm.merge_from(om);
                    } else {
                        *slot = ComplexType::Message(om);
                    }
                }
                ComplexType::RepeatedScalar(ov) => {
                    if let ComplexType::RepeatedScalar(sv) = slot {
                        sv.extend(ov);
                    } else {
                        *slot = ComplexType::RepeatedScalar(ov);
                    }
                }
                ComplexType::RepeatedMessage(ov) => {
                    if let ComplexType::RepeatedMessage(sv) = slot {
                        sv.extend(ov);
                    } else {
                        *slot = ComplexType::RepeatedMessage(ov);
                    }
                }
                ComplexType::Map(om) => {
                    if let ComplexType::Map(sm) = slot {
                        sm.extend(om);
                    } else {
                        *slot = ComplexType::Map(om);
                    }
                }
            }
        }
    }

    /// Add a value to a repeated scalar field.
    #[inline(always)]
    fn add_repeated_scalar(
        &mut self,
        field_info: &FieldInfo,
        field_num: i32,
        value: FieldValueRef<'a>,
    ) -> ParseResult<()> {
        let complex_type = &mut self.complex[field_info.storage_index];
        match complex_type {
            ComplexType::RepeatedScalar(vec) => vec.push(value),
            ComplexType::Empty => *complex_type = ComplexType::RepeatedScalar(vec![value]),
            _ => {
                return Err(ParseError::ComplexTypeMismatch {
                    expected: "RepeatedScalar",
                    actual: complex_type.as_str(),
                    field_num,
                });
            }
        }
        Ok(())
    }

    /// Add a value to a repeated message field.
    fn add_repeated_message(
        &mut self,
        field_info: &FieldInfo,
        field_num: i32,
        value: ParsedMessage<'a>,
    ) -> ParseResult<()> {
        let complex_type = &mut self.complex[field_info.storage_index];
        match complex_type {
            ComplexType::RepeatedMessage(vec) => vec.push(value),
            ComplexType::Empty => *complex_type = ComplexType::RepeatedMessage(vec![value]),
            _ => {
                return Err(ParseError::ComplexTypeMismatch {
                    expected: "RepeatedMessage",
                    actual: complex_type.as_str(),
                    field_num,
                });
            }
        }
        Ok(())
    }

    /// Add a map entry. Duplicate keys are overwritten (last one wins).
    fn add_map_entry(
        &mut self,
        field_info: &FieldInfo,
        field_num: i32,
        key: MapKeyRef<'a>,
        value: ParsedMapValue<'a>,
    ) -> ParseResult<()> {
        let complex_type = &mut self.complex[field_info.storage_index];
        match complex_type {
            ComplexType::Map(map) => {
                map.insert(key, value);
            }
            ComplexType::Empty => {
                let mut map = HashMap::new();
                map.insert(key, value);
                *complex_type = ComplexType::Map(map);
            }
            _ => {
                return Err(ParseError::ComplexTypeMismatch {
                    expected: "Map",
                    actual: complex_type.as_str(),
                    field_num,
                });
            }
        }
        Ok(())
    }

    /// Clears all other members in a oneof group, leaving only the current field.
    /// Scalars are set to None, complex fields are set to Empty.
    #[cold]
    fn clear_oneof_siblings(&mut self, oneof_index: i32, field_info: &FieldInfo) {
        for member in self.descriptor.get_oneof_group(oneof_index) {
            // Skip the current field being set.
            if member.is_scalar == field_info.is_scalar
                && member.storage_index == field_info.storage_index
            {
                continue;
            }
            if member.is_scalar {
                self.scalars[member.storage_index] = None;
            } else {
                self.complex[member.storage_index] = ComplexType::Empty;
            }
        }
    }

    /// Parse a protobuf message recursively in a single O(N) pass.
    #[inline(always)]
    pub fn parse(bytes: &'a [u8], registry: &'a MessageRegistry) -> ParseResult<ParsedMessage<'a>> {
        Self::parse_internal(
            bytes, None, /* type_name */
            registry, 0, /* depth */
        )
    }

    #[inline(always)]
    fn parse_internal(
        bytes: &'a [u8],
        type_name: Option<&str>,
        registry: &'a MessageRegistry,
        depth: usize,
    ) -> ParseResult<ParsedMessage<'a>> {
        if depth > MAX_NESTING_DEPTH {
            return Err(ParseError::MaxNestingDepthExceeded {
                max: MAX_NESTING_DEPTH,
            });
        }

        let descriptor = match type_name {
            Some(name) => registry
                .get(name)
                .ok_or_else(|| ParseError::UnknownTypeName {
                    type_name: name.to_string(),
                })?,
            None => &registry.root_descriptor,
        };

        let mut result = ParsedMessage::with_descriptor(descriptor);
        let mut remaining = bytes;

        while !remaining.is_empty() {
            let (parsed_field, rest) = try_parse_field(remaining)?;
            remaining = rest;

            let field_num = parsed_field.field_num;
            let Some(field_info) = descriptor.get_field(field_num) else {
                // Per protobuf spec, unknown fields are ignored.
                continue;
            };

            // Hot path: singular scalar fields.
            // Check is_scalar first to optimize for branch prediction.
            // is_scalar == true means: !is_repeated && field_type != Message.
            if field_info.is_scalar {
                let value = convert_scalar_value(
                    field_info.field_type,
                    &parsed_field.value,
                    parsed_field.field_num,
                )?;
                // Clear sibling oneof fields before setting this one.
                // oneof_index is inlined in FieldInfo to avoid a HashMap lookup on the hot path.
                if let Some(idx) = field_info.oneof_index {
                    result.clear_oneof_siblings(idx, field_info);
                }
                result.set_scalar(field_info, value);
                continue;
            }

            // Cold path: complex types (messages, repeated fields, maps).
            if field_info.field_type == Type::Message {
                let nested_bytes = parsed_field.value.try_as_bytes(parsed_field.field_num)?;
                let nested_type_name = field_info.type_name.as_deref().unwrap_or("");

                // Check if this is a map entry.
                if let Some(nested_desc) = registry.get(nested_type_name) {
                    if nested_desc.is_map_entry {
                        let (key, value) = ParsedMessage::parse_map_entry_recursive(
                            nested_bytes,
                            nested_desc,
                            registry,
                            depth + 1,
                        )?;
                        result.add_map_entry(field_info, field_num, key, value)?;
                        continue;
                    }
                }

                // Parse nested message recursively.
                let nested = ParsedMessage::parse_internal(
                    nested_bytes,
                    Some(nested_type_name),
                    registry,
                    depth + 1,
                )?;

                if field_info.is_repeated {
                    result.add_repeated_message(field_info, field_num, nested)?;
                } else {
                    // Clear sibling oneof fields before merging into this one;
                    // repeats of the same oneof member fall through to the
                    // merge path, matching protobuf MergeFrom semantics.
                    if let Some(idx) = field_info.oneof_index {
                        result.clear_oneof_siblings(idx, field_info);
                    }
                    result.merge_or_set_message(field_info, nested);
                }
            } else {
                // Repeated scalar field (is_scalar is false, but not a Message).
                let is_packed = PackedField::is_packable_type(field_info.field_type)
                    && matches!(parsed_field.value, WireValue::Len(_));

                if is_packed {
                    let bytes = parsed_field.value.try_as_bytes(parsed_field.field_num)?;
                    let packed = PackedField::from_bytes(
                        bytes,
                        field_info.field_type,
                        parsed_field.field_num,
                    )?;
                    let complex_type = &mut result.complex[field_info.storage_index];
                    if matches!(complex_type, ComplexType::Empty) {
                        *complex_type = ComplexType::RepeatedScalar(Vec::new());
                    }
                    let values_vec = match complex_type {
                        ComplexType::RepeatedScalar(vec) => vec,
                        _ => {
                            return Err(ParseError::ComplexTypeMismatch {
                                expected: "RepeatedScalar",
                                actual: complex_type.as_str(),
                                field_num: parsed_field.field_num,
                            });
                        }
                    };
                    packed.expand_into(
                        field_info.field_type,
                        values_vec,
                        parsed_field.field_num,
                    )?;
                } else {
                    let value = convert_scalar_value(
                        field_info.field_type,
                        &parsed_field.value,
                        parsed_field.field_num,
                    )?;
                    result.add_repeated_scalar(field_info, parsed_field.field_num, value)?;
                }
            }
        }

        Ok(result)
    }

    /// Parse a map entry and recursively parse value if it's a message.
    fn parse_map_entry_recursive(
        bytes: &'a [u8],
        descriptor: &'a DescriptorWithFieldCache,
        registry: &'a MessageRegistry,
        depth: usize,
    ) -> ParseResult<(MapKeyRef<'a>, ParsedMapValue<'a>)> {
        let mut key: Option<FieldValueRef<'a>> = None;
        let mut value: Option<ParsedMapValue<'a>> = None;
        let mut remaining = bytes;

        let key_info = descriptor.get_field(MAP_ENTRY_KEY_FIELD_NUM);
        let value_info = descriptor.get_field(MAP_ENTRY_VALUE_FIELD_NUM);

        while !remaining.is_empty() {
            let (parsed_field, rest) = try_parse_field(remaining)?;
            remaining = rest;

            let field_num = parsed_field.field_num;

            if let Some(field_info) = descriptor.get_field(field_num) {
                match field_num {
                    MAP_ENTRY_KEY_FIELD_NUM => {
                        // Key field (always scalar).
                        let k = convert_scalar_value(
                            field_info.field_type,
                            &parsed_field.value,
                            MAP_ENTRY_KEY_FIELD_NUM,
                        )?;
                        key = Some(k);
                    }
                    MAP_ENTRY_VALUE_FIELD_NUM => {
                        // Value field (scalar or message).
                        if field_info.field_type == Type::Message {
                            let nested_bytes =
                                parsed_field.value.try_as_bytes(parsed_field.field_num)?;
                            let new_value = Self::parse_map_message_value(
                                field_info.type_name.as_deref().unwrap_or(""),
                                nested_bytes,
                                registry,
                                depth,
                            )?;
                            // Repeated value-field within a single map entry:
                            // protobuf MergeFrom rules apply (merge embedded
                            // messages). Mismatched prior variants are replaced.
                            match (value.as_mut(), new_value) {
                                (
                                    Some(ParsedMapValue::Message(existing)),
                                    ParsedMapValue::Message(new_msg),
                                ) => existing.merge_from(new_msg),
                                (_, new_value) => value = Some(new_value),
                            }
                        } else {
                            let v = convert_scalar_value(
                                field_info.field_type,
                                &parsed_field.value,
                                MAP_ENTRY_VALUE_FIELD_NUM,
                            )?;
                            value = Some(ParsedMapValue::Scalar(v));
                        }
                    }
                    _ => {}
                }
            }
        }

        let key_type = key_info.map(|f| f.field_type).unwrap_or(Type::Bytes);
        let value_type = value_info.map(|f| f.field_type).unwrap_or(Type::Bytes);

        let key_field_value = key.unwrap_or_else(|| default_value_for_type(key_type));
        let value = match value {
            Some(v) => v,
            // An absent value on a message-typed map must materialize as an
            // empty ParsedMessage; a scalar default would be misclassified as
            // bytes by downstream validators.
            None if value_type == Type::Message => {
                let type_name = value_info
                    .and_then(|f| f.type_name.as_deref())
                    .unwrap_or_default();
                Self::parse_map_message_value(type_name, &[], registry, depth)?
            }
            None => ParsedMapValue::Scalar(default_value_for_type(value_type)),
        };
        let map_key =
            MapKeyRef::from_field_value(key_field_value).ok_or(ParseError::InvalidMapKeyType {
                field_num: MAP_ENTRY_KEY_FIELD_NUM,
            })?;

        Ok((map_key, value))
    }

    fn parse_map_message_value(
        type_name: &str,
        bytes: &'a [u8],
        registry: &'a MessageRegistry,
        depth: usize,
    ) -> ParseResult<ParsedMapValue<'a>> {
        let nested = ParsedMessage::parse_internal(bytes, Some(type_name), registry, depth)?;
        Ok(ParsedMapValue::Message(nested))
    }
}

#[derive(Debug)]
pub enum ParsedFieldValue<'s, 'a> {
    Scalar(FieldValueRef<'a>),
    Complex(&'s ComplexType<'a>),
}

impl<'a, 'b> std::ops::Deref for ParsedFieldValue<'a, 'b> {
    type Target = Self;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
pub mod tests {
    use prost_types::field_descriptor_proto::Type;
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, MessageOptions, OneofDescriptorProto,
    };

    use super::*;
    use crate::zeroparser::sparse_field_map::MAX_INLINE_CAPACITY;

    const LABEL_OPTIONAL: i32 = 1;
    const LABEL_REPEATED: i32 = 3;

    pub fn make_field(
        number: i32,
        name: &str,
        field_type: Type,
        repeated: bool,
        type_name: Option<&str>,
    ) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.to_string()),
            number: Some(number),
            label: Some(if repeated {
                LABEL_REPEATED
            } else {
                LABEL_OPTIONAL
            }),
            r#type: Some(field_type as i32),
            type_name: type_name.map(|s| s.to_string()),
            extendee: None,
            default_value: None,
            oneof_index: None,
            json_name: None,
            options: None,
            proto3_optional: None,
        }
    }

    pub fn make_descriptor(name: &str, fields: Vec<FieldDescriptorProto>) -> DescriptorProto {
        DescriptorProto {
            name: Some(name.to_string()),
            field: fields,
            extension: vec![],
            nested_type: vec![],
            enum_type: vec![],
            extension_range: vec![],
            oneof_decl: vec![],
            options: None,
            reserved_range: vec![],
            reserved_name: vec![],
        }
    }

    fn make_map_entry_descriptor(name: &str, key_type: Type, value_type: Type) -> DescriptorProto {
        let mut desc = make_descriptor(
            name,
            vec![
                make_field(1, "key", key_type, false, None),
                make_field(2, "value", value_type, false, None),
            ],
        );
        desc.options = Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });
        desc
    }

    fn assert_scalar(parsed: &ParsedMessage, expected: FieldValueRef, field_num: i32) {
        let actual = parsed
            .get_scalar(field_num)
            .unwrap_or_else(|| panic!("Field {} not found", field_num));
        assert_eq!(*actual, expected, "Field {} mismatch", field_num);
    }

    /// Length-delimited field encoding: tag = (field<<3)|2, single-byte len, payload.
    /// Suitable for small test payloads (<128 bytes).
    fn ld(field: u8, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 128, "ld helper assumes single-byte length");
        let mut v = Vec::with_capacity(payload.len() + 2);
        v.push(field << 3 | 2);
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn parse_scalar_fields() {
        let cases: Vec<(i32, &str, Type, &[u8], FieldValueRef)> = vec![
            (
                1,
                "id",
                Type::Int32,
                &[8, 0x96, 0x01],
                FieldValueRef::Int32(150),
            ),
            (
                1,
                "big",
                Type::Int64,
                &[8, 0xAC, 0x02],
                FieldValueRef::Int64(300),
            ),
            (
                1,
                "count",
                Type::Uint32,
                &[8, 42],
                FieldValueRef::UInt32(42),
            ),
            (
                1,
                "ts",
                Type::Uint64,
                &[8, 0xE8, 0x07],
                FieldValueRef::UInt64(1000),
            ),
            (1, "delta", Type::Sint32, &[8, 1], FieldValueRef::Int32(-1)),
            (1, "offset", Type::Sint64, &[8, 3], FieldValueRef::Int64(-2)),
            (1, "flag", Type::Bool, &[8, 1], FieldValueRef::Bool(true)),
            (1, "flag", Type::Bool, &[8, 0], FieldValueRef::Bool(false)),
            (
                1,
                "f32",
                Type::Fixed32,
                &[13, 0x78, 0x56, 0x34, 0x12],
                FieldValueRef::UInt32(0x12345678),
            ),
            (
                1,
                "f64",
                Type::Fixed64,
                &[9, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
                FieldValueRef::UInt64(0x0102030405060708),
            ),
            (
                1,
                "sf32",
                Type::Sfixed32,
                &[13, 0xFF, 0xFF, 0xFF, 0xFF],
                FieldValueRef::Int32(-1),
            ),
            (
                1,
                "sf64",
                Type::Sfixed64,
                &[9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                FieldValueRef::Int64(-1),
            ),
            (
                1,
                "name",
                Type::String,
                &[10, 5, b'h', b'e', b'l', b'l', b'o'],
                FieldValueRef::String("hello"),
            ),
            (
                1,
                "data",
                Type::Bytes,
                &[10, 3, 0xDE, 0xAD, 0xBE],
                FieldValueRef::Bytes(&[0xDE, 0xAD, 0xBE]),
            ),
        ];

        for (field_num, field_name, field_type, wire_bytes, expected_value) in cases {
            let desc = make_descriptor(
                "Test",
                vec![make_field(field_num, field_name, field_type, false, None)],
            );
            let registry = MessageRegistry::from_descriptor(&desc);
            let parsed = ParsedMessage::parse(wire_bytes, &registry).expect("parse failed");
            assert_scalar(&parsed, expected_value, field_num);
        }
    }

    #[test]
    fn parse_float_double() {
        let float_bits = std::f32::consts::PI.to_bits().to_le_bytes();
        let float_bytes = [&[13u8][..], &float_bits[..]].concat();
        let desc = make_descriptor("Test", vec![make_field(1, "val", Type::Float, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&float_bytes, &registry).unwrap();
        match parsed.get_scalar(1) {
            Some(&FieldValueRef::Float(f)) => assert!((f - std::f32::consts::PI).abs() < 0.001),
            other => panic!("Expected Float, got {:?}", other),
        }

        let double_bits = std::f64::consts::E.to_bits().to_le_bytes();
        let double_bytes = [&[9u8][..], &double_bits[..]].concat();
        let desc = make_descriptor(
            "Test",
            vec![make_field(1, "val", Type::Double, false, None)],
        );
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&double_bytes, &registry).unwrap();
        match parsed.get_scalar(1) {
            Some(&FieldValueRef::Double(d)) => assert!((d - std::f64::consts::E).abs() < 0.00001),
            other => panic!("Expected Double, got {:?}", other),
        }
    }

    #[test]
    fn parse_empty_message() {
        let desc = make_descriptor("Empty", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&[], &registry).unwrap();
        assert!(!parsed.has_field(1));

        // Edge case: negative field numbers should safely return false/None.
        assert!(!parsed.has_field(-1));
        assert!(!parsed.has_field(i32::MIN));
        assert_eq!(parsed.get_scalar(-1), None);
        assert_eq!(parsed.get_scalar(i32::MIN), None);
    }

    #[test]
    fn parse_multiple_fields() {
        let desc = make_descriptor(
            "Multi",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(2, "name", Type::String, false, None),
            ],
        );
        let registry = MessageRegistry::from_descriptor(&desc);
        let wire = &[8, 42, 18, 2, b'h', b'i'];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        assert_scalar(&parsed, FieldValueRef::Int32(42), 1 /* field_num */);
        assert_scalar(&parsed, FieldValueRef::String("hi"), 2 /* field_num */);
    }

    #[test]
    fn parse_repeated_scalars() {
        let desc = make_descriptor("Test", vec![make_field(1, "nums", Type::Int32, true, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let wire = &[8, 1, 8, 2, 8, 3];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        let values = parsed.get_repeated_scalars(1);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], FieldValueRef::Int32(1));
        assert_eq!(values[1], FieldValueRef::Int32(2));
        assert_eq!(values[2], FieldValueRef::Int32(3));
    }

    #[test]
    fn parse_packed_and_mixed_repeated() {
        let cases: Vec<(&str, Type, &[u8], Vec<FieldValueRef>)> = vec![
            // Packed-only cases.
            (
                "int32_packed",
                Type::Int32,
                &[10, 3, 1, 2, 127],
                vec![
                    FieldValueRef::Int32(1),
                    FieldValueRef::Int32(2),
                    FieldValueRef::Int32(127),
                ],
            ),
            (
                "fixed32_packed",
                Type::Fixed32,
                &[10, 8, 1, 0, 0, 0, 2, 0, 0, 0],
                vec![FieldValueRef::UInt32(1), FieldValueRef::UInt32(2)],
            ),
            (
                "fixed64_packed",
                Type::Fixed64,
                &[10, 16, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
                vec![FieldValueRef::UInt64(1), FieldValueRef::UInt64(2)],
            ),
            // Empty packed arrays (length = 0).
            ("int32_empty", Type::Int32, &[10, 0], vec![]),
            ("fixed32_empty", Type::Fixed32, &[10, 0], vec![]),
            ("fixed64_empty", Type::Fixed64, &[10, 0], vec![]),
            // Mixed packed/unpacked: [unpacked: 1] [packed: 2,3] [unpacked: 4] -> [1,2,3,4].
            (
                "int32_mixed",
                Type::Int32,
                &[8, 1, 10, 2, 2, 3, 8, 4],
                vec![
                    FieldValueRef::Int32(1),
                    FieldValueRef::Int32(2),
                    FieldValueRef::Int32(3),
                    FieldValueRef::Int32(4),
                ],
            ),
            // Multiple packed occurrences: [packed: 1,2] [packed: 3,4] -> [1,2,3,4].
            (
                "int32_multi_packed",
                Type::Int32,
                &[10, 2, 1, 2, 10, 2, 3, 4],
                vec![
                    FieldValueRef::Int32(1),
                    FieldValueRef::Int32(2),
                    FieldValueRef::Int32(3),
                    FieldValueRef::Int32(4),
                ],
            ),
            // Mixed packed/unpacked for other types.
            (
                "uint32_mixed",
                Type::Uint32,
                &[8, 10, 10, 2, 20, 30, 8, 40],
                vec![
                    FieldValueRef::UInt32(10),
                    FieldValueRef::UInt32(20),
                    FieldValueRef::UInt32(30),
                    FieldValueRef::UInt32(40),
                ],
            ),
            (
                "bool_mixed",
                Type::Bool,
                &[8, 1, 10, 2, 0, 1, 8, 0],
                vec![
                    FieldValueRef::Bool(true),
                    FieldValueRef::Bool(false),
                    FieldValueRef::Bool(true),
                    FieldValueRef::Bool(false),
                ],
            ),
            (
                "fixed32_mixed",
                Type::Fixed32,
                &[
                    13, 1, 0, 0, 0, // Unpacked: 1
                    10, 8, 2, 0, 0, 0, 3, 0, 0, 0, // Packed: [2, 3]
                    13, 4, 0, 0, 0, // Unpacked: 4
                ],
                vec![
                    FieldValueRef::UInt32(1),
                    FieldValueRef::UInt32(2),
                    FieldValueRef::UInt32(3),
                    FieldValueRef::UInt32(4),
                ],
            ),
        ];

        for (name, field_type, wire_bytes, expected_values) in cases {
            let desc = make_descriptor("Test", vec![make_field(1, "arr", field_type, true, None)]);
            let registry = MessageRegistry::from_descriptor(&desc);
            let parsed = ParsedMessage::parse(wire_bytes, &registry)
                .unwrap_or_else(|_| panic!("{}: parse failed", name));

            let values = parsed.get_repeated_scalars(1);
            assert_eq!(
                values.len(),
                expected_values.len(),
                "{}: length mismatch",
                name
            );
            for (i, expected_val) in expected_values.iter().enumerate() {
                assert_eq!(values[i], *expected_val, "{}: value {} mismatch", name, i);
            }
        }
    }

    #[test]
    fn parse_nested_struct_recursive() {
        let inner = make_descriptor(
            "Inner",
            vec![
                make_field(1, "a", Type::Int32, false, None),
                make_field(2, "b", Type::String, false, None),
            ],
        );

        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "inner",
                Type::Message,
                false,
                Some(".Outer.Inner"),
            )],
        );
        outer.nested_type.push(inner);

        let registry = MessageRegistry::from_descriptor(&outer);

        let inner_wire: &[u8] = &[8, 42, 18, 5, b'h', b'e', b'l', b'l', b'o'];
        let mut wire = vec![10, inner_wire.len() as u8];
        wire.extend_from_slice(inner_wire);

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let inner_parsed = parsed.get_message(1).expect("inner should be parsed");
        assert_eq!(inner_parsed.get_scalar(1), Some(&FieldValueRef::Int32(42)));
        assert_eq!(
            inner_parsed.get_scalar(2),
            Some(&FieldValueRef::String("hello"))
        );
    }

    #[test]
    fn parse_repeated_messages() {
        let item = make_descriptor("Item", vec![make_field(1, "id", Type::Int32, false, None)]);
        let mut container = make_descriptor(
            "Container",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Container.Item"),
            )],
        );
        container.nested_type.push(item);

        let registry = MessageRegistry::from_descriptor(&container);
        let wire = &[10, 2, 8, 1, 10, 2, 8, 2];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        let items = parsed.get_repeated_messages(1);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].get_scalar(1), Some(&FieldValueRef::Int32(1)));
        assert_eq!(items[1].get_scalar(1), Some(&FieldValueRef::Int32(2)));
    }

    #[test]
    fn parse_map_scalar_values() {
        // Test map<string, int32>.
        let map_entry = make_map_entry_descriptor("MapEntry", Type::String, Type::Int32);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Outer.MapEntry"),
            )],
        );
        outer.nested_type.push(map_entry);

        let registry = MessageRegistry::from_descriptor(&outer);
        let wire = &[10, 7, 10, 3, b'f', b'o', b'o', 16, 42];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        assert_eq!(parsed.get_map_entries_count(1), 1);
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(*entries[0].0, MapKeyRef::String("foo"));
        match entries[0].1 {
            ParsedMapValue::Scalar(v) => assert_eq!(v, &FieldValueRef::Int32(42)),
            _ => panic!("Expected scalar value"),
        }

        // Test map<int32, string> - integer keys are also valid in protobuf.
        let int_key_map_entry = make_map_entry_descriptor("IntKeyMap", Type::Int32, Type::String);
        let mut outer2 = make_descriptor(
            "Outer2",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Outer2.IntKeyMap"),
            )],
        );
        outer2.nested_type.push(int_key_map_entry);

        let registry2 = MessageRegistry::from_descriptor(&outer2);
        // Entry: key=42 (tag 8, varint 42), value="hi" (tag 18, len 2, "hi").
        let wire2 = &[10, 6, 8, 42, 18, 2, b'h', b'i'];
        let parsed2 = ParsedMessage::parse(wire2, &registry2).unwrap();

        assert_eq!(parsed2.get_map_entries_count(1), 1);
        let entries2: Vec<_> = parsed2.get_map_entries(1).collect();
        assert_eq!(*entries2[0].0, MapKeyRef::Int32(42));
        match entries2[0].1 {
            ParsedMapValue::Scalar(v) => assert_eq!(v, &FieldValueRef::String("hi")),
            _ => panic!("Expected scalar value"),
        }
    }

    #[test]
    fn parse_map_message_values() {
        let value_msg = make_descriptor(
            "ValueMsg",
            vec![make_field(1, "x", Type::Int32, false, None)],
        );
        let mut map_entry = make_descriptor(
            "MapEntry",
            vec![
                make_field(1, "key", Type::String, false, None),
                make_field(2, "value", Type::Message, false, Some(".Outer.ValueMsg")),
            ],
        );
        map_entry.options = Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });

        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Outer.MapEntry"),
            )],
        );
        outer.nested_type.push(map_entry);
        outer.nested_type.push(value_msg);

        let registry = MessageRegistry::from_descriptor(&outer);
        // Entry: key="k" (3 bytes), value={x=99} (4 bytes) = 7 bytes total.
        let wire = &[10, 7, 10, 1, b'k', 18, 2, 8, 99];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        assert_eq!(parsed.get_map_entries_count(1), 1);
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(*entries[0].0, MapKeyRef::String("k"));
        match entries[0].1 {
            ParsedMapValue::Message(m) => {
                assert_eq!(m.get_scalar(1), Some(&FieldValueRef::Int32(99)))
            }
            _ => panic!("Expected message value"),
        }

        // Entry with the message-valued field omitted must still materialize
        // as an empty ParsedMessage, not a scalar default.
        let wire_missing_value = &[10, 3, 10, 1, b'k'];
        let parsed = ParsedMessage::parse(wire_missing_value, &registry).unwrap();
        assert_eq!(parsed.get_map_entries_count(1), 1);
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(*entries[0].0, MapKeyRef::String("k"));
        match entries[0].1 {
            ParsedMapValue::Message(m) => assert_eq!(m.get_scalar(1), None),
            other => panic!("Expected empty message value, got {:?}", other),
        }

        // Entry with both key and value omitted: key defaults to "" and
        // value still materializes as an empty ParsedMessage.
        let wire_empty_entry = &[10, 0];
        let parsed = ParsedMessage::parse(wire_empty_entry, &registry).unwrap();
        assert_eq!(parsed.get_map_entries_count(1), 1);
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(*entries[0].0, MapKeyRef::String(""));
        match entries[0].1 {
            ParsedMapValue::Message(m) => assert_eq!(m.get_scalar(1), None),
            other => panic!("Expected empty message value, got {:?}", other),
        }
    }

    #[test]
    fn parse_map_with_defaults() {
        let cases: Vec<(&str, &[u8], MapKeyRef, FieldValueRef)> = vec![
            (
                "both",
                &[10, 3, b'k', b'e', b'y', 16, 5],
                MapKeyRef::String("key"),
                FieldValueRef::Int32(5),
            ),
            (
                "no_value",
                &[10, 1, b'x'],
                MapKeyRef::String("x"),
                FieldValueRef::Int32(0),
            ),
            (
                "no_key",
                &[16, 99],
                MapKeyRef::String(""),
                FieldValueRef::Int32(99),
            ),
            ("empty", &[], MapKeyRef::String(""), FieldValueRef::Int32(0)),
        ];

        let map_entry = make_map_entry_descriptor("MapEntry", Type::String, Type::Int32);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "m",
                Type::Message,
                true,
                Some(".Outer.MapEntry"),
            )],
        );
        outer.nested_type.push(map_entry);
        let registry = MessageRegistry::from_descriptor(&outer);

        for (case_name, entry_wire, expected_key, expected_value) in cases {
            let mut wire = vec![10, entry_wire.len() as u8];
            wire.extend_from_slice(entry_wire);

            let parsed = ParsedMessage::parse(&wire, &registry).expect(case_name);
            assert_eq!(parsed.get_map_entries_count(1), 1, "case: {}", case_name);
            let entries: Vec<_> = parsed.get_map_entries(1).collect();
            assert_eq!(*entries[0].0, expected_key, "case: {} key", case_name);
            match entries[0].1 {
                ParsedMapValue::Scalar(v) => {
                    assert_eq!(v, &expected_value, "case: {} value", case_name)
                }
                _ => panic!("Expected scalar for case {}", case_name),
            }
        }
    }

    #[test]
    fn parse_errors() {
        let cases: Vec<(&str, Vec<FieldDescriptorProto>, &[u8], ParseError)> = vec![
            (
                "invalid_utf8",
                vec![make_field(1, "name", Type::String, false, None)],
                &[10, 2, 0xFF, 0xFE],
                ParseError::InvalidUtf8 { field_num: 1 },
            ),
            (
                "buffer_too_short",
                vec![make_field(1, "f", Type::Fixed32, false, None)],
                &[13, 0x01, 0x02],
                ParseError::BufferTooShort {
                    needed: 4,
                    available: 2,
                    field_num: 1,
                },
            ),
            (
                "invalid_wire_type",
                vec![make_field(1, "x", Type::Int32, false, None)],
                &[14],
                ParseError::InvalidWireType(6),
            ),
            (
                "truncated_varint",
                vec![make_field(1, "x", Type::Int32, false, None)],
                &[8, 0x80],
                ParseError::TruncatedVarint,
            ),
        ];

        for (case_name, fields, wire_bytes, expected_error) in cases {
            let desc = make_descriptor("Test", fields);
            let registry = MessageRegistry::from_descriptor(&desc);
            let result = ParsedMessage::parse(wire_bytes, &registry);
            assert!(result.is_err(), "case {} should fail", case_name);
            assert_eq!(result.unwrap_err(), expected_error, "case: {}", case_name);
        }
    }

    #[test]
    fn parse_unknown_type_returns_error() {
        let desc = make_descriptor("Test", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let result = ParsedMessage::parse_internal(&[8, 42], Some(".Unknown"), &registry, 0);
        assert!(matches!(
            result,
            Err(ParseError::UnknownTypeName { type_name }) if type_name == ".Unknown"
        ));
    }

    #[test]
    fn parse_max_nesting_depth_exceeded() {
        let desc = make_descriptor("Test", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        // Use parse_internal directly to test depth checking.
        let result = ParsedMessage::parse_internal(
            &[8, 42],
            Some(".Test"),
            &registry,
            MAX_NESTING_DEPTH + 1,
        );
        assert!(matches!(
            result,
            Err(ParseError::MaxNestingDepthExceeded { max })
                if max == MAX_NESTING_DEPTH
        ));
    }

    #[test]
    fn parse_last_occurrence_wins() {
        let desc = make_descriptor(
            "Test",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(2, "name", Type::String, false, None),
            ],
        );
        let registry = MessageRegistry::from_descriptor(&desc);
        let wire = &[
            8, 10, 18, 5, b'f', b'i', b'r', b's', b't', 8, 20, 8, 30, 18, 6, b's', b'e', b'c',
            b'o', b'n', b'd',
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(30)));
        assert_eq!(parsed.get_scalar(2), Some(&FieldValueRef::String("second")));
    }

    #[test]
    fn parse_deeply_nested() {
        let level2 = make_descriptor("L2", vec![make_field(1, "val", Type::Int32, false, None)]);
        let mut level1 = make_descriptor(
            "L1",
            vec![make_field(
                1,
                "l2",
                Type::Message,
                false,
                Some(".Root.L1.L2"),
            )],
        );
        level1.nested_type.push(level2);
        let mut root = make_descriptor(
            "Root",
            vec![make_field(1, "l1", Type::Message, false, Some(".Root.L1"))],
        );
        root.nested_type.push(level1);

        let registry = MessageRegistry::from_descriptor(&root);
        // Root { l1: L1 { l2: L2 { val: 42 } } }
        let wire = &[10, 4, 10, 2, 8, 42];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        let l1 = parsed.get_message(1).expect("l1");
        let l2 = l1.get_message(1).expect("l2");
        assert_eq!(l2.get_scalar(1), Some(&FieldValueRef::Int32(42)));
    }

    #[test]
    fn field_presence_all_scalar_types() {
        let desc = make_descriptor(
            "Test",
            vec![
                make_field(1, "int32_field", Type::Int32, false, None),
                make_field(2, "int64_field", Type::Int64, false, None),
                make_field(3, "uint32_field", Type::Uint32, false, None),
                make_field(4, "uint64_field", Type::Uint64, false, None),
                make_field(5, "bool_field", Type::Bool, false, None),
                make_field(6, "float_field", Type::Float, false, None),
                make_field(7, "double_field", Type::Double, false, None),
                make_field(8, "string_field", Type::String, false, None),
                make_field(9, "bytes_field", Type::Bytes, false, None),
            ],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire format with all fields set to their default values.
        let wire = &[
            8, 0, // int32 = 0
            16, 0, // int64 = 0
            24, 0, // uint32 = 0
            32, 0, // uint64 = 0
            40, 0, // bool = false
            53, 0, 0, 0, 0, // float = 0.0
            57, 0, 0, 0, 0, 0, 0, 0, 0, // double = 0.0
            66, 0, // string = ""
            74, 0, // bytes = []
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // All fields are present even though they have default values.
        for field_num in 1..=9 {
            assert!(
                parsed.has_field(field_num),
                "Field {} should be present",
                field_num
            );
        }

        // Case 2: Empty message - no fields present.
        let parsed_empty = ParsedMessage::parse(&[], &registry).unwrap();
        for field_num in 1..=9 {
            assert!(
                !parsed_empty.has_field(field_num),
                "Field {} should NOT be present",
                field_num
            );
        }
    }

    #[test]
    fn field_presence_partial_message() {
        let desc = make_descriptor(
            "Test",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(2, "name", Type::String, false, None),
                make_field(3, "age", Type::Int32, false, None),
                make_field(4, "email", Type::String, false, None),
            ],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire format with only fields 1 and 3 present.
        let wire = &[8, 42, 24, 25];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // Fields 1 and 3 are present.
        assert!(parsed.has_field(1));
        assert!(parsed.has_field(3));
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(42)));
        assert_eq!(parsed.get_scalar(3), Some(&FieldValueRef::Int32(25)));

        // Fields 2 and 4 are NOT present.
        assert!(!parsed.has_field(2));
        assert!(!parsed.has_field(4));
        assert_eq!(parsed.get_scalar(2), None);
        assert_eq!(parsed.get_scalar(4), None);
    }

    #[test]
    fn field_presence_nested_messages() {
        let inner = make_descriptor(
            "Inner",
            vec![
                make_field(1, "value", Type::Int32, false, None),
                make_field(2, "flag", Type::Bool, false, None),
            ],
        );
        let mut outer = make_descriptor(
            "Outer",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(2, "inner", Type::Message, false, Some(".Outer.Inner")),
            ],
        );
        outer.nested_type.push(inner);

        let registry = MessageRegistry::from_descriptor(&outer);

        // Case 1: Outer message with only id field, no inner message.
        let wire_no_inner = &[8, 100];
        let parsed_no_inner = ParsedMessage::parse(wire_no_inner, &registry).unwrap();
        assert!(parsed_no_inner.has_field(1));
        assert!(!parsed_no_inner.has_field(2));
        assert!(parsed_no_inner.get_message(2).is_none());

        // Case 2: Outer message with inner message, but inner has only one field.
        let inner_wire = &[8, 42];
        let mut wire_with_inner = vec![8, 100, 18, inner_wire.len() as u8];
        wire_with_inner.extend_from_slice(inner_wire);
        let parsed_with_inner = ParsedMessage::parse(&wire_with_inner, &registry).unwrap();
        assert!(parsed_with_inner.has_field(1));
        assert!(parsed_with_inner.has_field(2));

        let inner_msg = parsed_with_inner.get_message(2).unwrap();
        assert!(inner_msg.has_field(1));
        assert!(!inner_msg.has_field(2));
        assert_eq!(inner_msg.get_scalar(1), Some(&FieldValueRef::Int32(42)));
        assert_eq!(inner_msg.get_scalar(2), None);
    }

    #[test]
    fn field_presence_repeated_and_map_return_empty() {
        // Test that repeated scalars, repeated messages, and maps all return empty.
        let item = make_descriptor("Item", vec![make_field(1, "id", Type::Int32, false, None)]);
        let map_entry = make_map_entry_descriptor("MapEntry", Type::String, Type::Int32);
        let mut desc = make_descriptor(
            "Test",
            vec![
                make_field(1, "scalars", Type::Int32, true, None),
                make_field(2, "messages", Type::Message, true, Some(".Test.Item")),
                make_field(3, "map", Type::Message, true, Some(".Test.MapEntry")),
            ],
        );
        desc.nested_type.push(item);
        desc.nested_type.push(map_entry);
        let registry = MessageRegistry::from_descriptor(&desc);

        // Empty message - all repeated/map fields return empty.
        let parsed = ParsedMessage::parse(&[], &registry).unwrap();
        assert!(parsed.get_repeated_scalars(1).is_empty());
        assert!(parsed.get_repeated_messages(2).is_empty());
        assert_eq!(parsed.get_map_entries_count(3), 0);

        // Message with values present.
        let wire = &[8, 1, 18, 2, 8, 42, 26, 5, 10, 1, b'k', 16, 99];
        let parsed_with_values = ParsedMessage::parse(wire, &registry).unwrap();
        assert_eq!(parsed_with_values.get_repeated_scalars(1).len(), 1);
        assert_eq!(parsed_with_values.get_repeated_messages(2).len(), 1);
        assert_eq!(parsed_with_values.get_map_entries_count(3), 1);
    }

    #[test]
    fn parse_ignores_unknown_fields() {
        // Schema only knows field 1, but wire data has fields 1 and 99.
        // Per protobuf spec, unknown fields should be silently ignored.
        let desc = make_descriptor("Test", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);

        // Field 1 = 42, unknown field 99 = 123.
        // Tag for field 99: (99 << 3) | 0 = 792 = 0x318 -> varint [0x98, 0x06].
        let wire = &[8, 42, 0x98, 0x06, 123];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // Known field should be parsed.
        assert!(parsed.has_field(1));
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(42)));

        // Unknown field should not be present.
        assert!(!parsed.has_field(99));
        assert_eq!(parsed.get_scalar(99), None);
    }

    #[test]
    fn parse_large_field_number() {
        // Test field numbers >= MAX_INLINE_CAPACITY (128) which use HashMap storage.
        assert_eq!(MAX_INLINE_CAPACITY, 128);
        let desc = make_descriptor(
            "Test",
            vec![
                make_field(127, "at_boundary", Type::Int32, false, None),
                make_field(128, "first_large", Type::Int32, false, None),
                make_field(200, "big", Type::String, false, None),
            ],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Tag for field 127: (127 << 3) | 0 = 1016 = 0x3F8 -> varint [0xF8, 0x07].
        // Tag for field 128: (128 << 3) | 0 = 1024 = 0x400 -> varint [0x80, 0x08].
        // Tag for field 200: (200 << 3) | 2 = 1602 = 0x642 -> varint [0xC2, 0x0C].
        let wire = &[
            0xF8, 0x07, 127, // field 127 = 127
            0x80, 0x08, 0x80, 0x01, // field 128 = 128
            0xC2, 0x0C, 3, b'a', b'b', b'c', // field 200 = "abc"
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // Field 127 uses inline array (last slot).
        assert!(parsed.has_field(127));
        assert_eq!(parsed.get_scalar(127), Some(&FieldValueRef::Int32(127)));

        // Fields 128 and 200 use HashMap (overflow).
        assert!(parsed.has_field(128));
        assert_eq!(parsed.get_scalar(128), Some(&FieldValueRef::Int32(128)));

        assert!(parsed.has_field(200));
        assert_eq!(parsed.get_scalar(200), Some(&FieldValueRef::String("abc")));
    }

    #[test]
    fn parse_empty_nested_message() {
        // Test parsing a nested message with 0 bytes (valid in proto3).
        let inner = make_descriptor(
            "Inner",
            vec![
                make_field(1, "value", Type::Int32, false, None),
                make_field(2, "name", Type::String, false, None),
            ],
        );
        let mut outer = make_descriptor(
            "Outer",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(2, "inner", Type::Message, false, Some(".Outer.Inner")),
            ],
        );
        outer.nested_type.push(inner);

        let registry = MessageRegistry::from_descriptor(&outer);

        // Outer { id: 42, inner: Inner {} } - inner message has 0 bytes.
        // Tag for field 2 (message): (2 << 3) | 2 = 18, length = 0.
        let wire = &[8, 42, 18, 0];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        assert!(parsed.has_field(1));
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(42)));

        // Empty inner message should be present but have no fields.
        assert!(parsed.has_field(2));
        let inner_msg = parsed.get_message(2).expect("inner should exist");
        assert!(!inner_msg.has_field(1));
        assert!(!inner_msg.has_field(2));
        assert_eq!(inner_msg.get_scalar(1), None);
        assert_eq!(inner_msg.get_scalar(2), None);
    }

    #[test]
    fn parse_multiple_map_entries_and_duplicate_keys() {
        let map_entry = make_map_entry_descriptor("MapEntry", Type::String, Type::Int32);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Outer.MapEntry"),
            )],
        );
        outer.nested_type.push(map_entry);

        let registry = MessageRegistry::from_descriptor(&outer);

        // Map with 3 entries: {"a": 1, "b": 2, "c": 3}.
        // Each entry: tag=10 (field 1, Len), length, key (tag=10, len, bytes), value (tag=16, varint).
        let wire = &[
            10, 5, 10, 1, b'a', 16, 1, // entry: "a" -> 1
            10, 5, 10, 1, b'b', 16, 2, // entry: "b" -> 2
            10, 5, 10, 1, b'c', 16, 3, // entry: "c" -> 3
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        assert_eq!(parsed.get_map_entries_count(1), 3);

        // Collect entries into a HashMap for order-independent verification.
        let entries: std::collections::HashMap<_, _> = parsed.get_map_entries(1).collect();

        assert!(matches!(
            entries.get(&MapKeyRef::String("a")),
            Some(ParsedMapValue::Scalar(FieldValueRef::Int32(1)))
        ));
        assert!(matches!(
            entries.get(&MapKeyRef::String("b")),
            Some(ParsedMapValue::Scalar(FieldValueRef::Int32(2)))
        ));
        assert!(matches!(
            entries.get(&MapKeyRef::String("c")),
            Some(ParsedMapValue::Scalar(FieldValueRef::Int32(3)))
        ));

        // Test duplicate keys: {"x": 10, "x": 20}.
        // Per protobuf spec, last value wins.
        let wire_dup = &[
            10, 5, 10, 1, b'x', 16, 10, // entry: "x" -> 10
            10, 5, 10, 1, b'x', 16, 20, // entry: "x" -> 20
        ];
        let parsed_dup = ParsedMessage::parse(wire_dup, &registry).unwrap();

        // Last entry wins per protobuf spec.
        assert_eq!(parsed_dup.get_map_entries_count(1), 1);
        let dup_entries: Vec<_> = parsed_dup.get_map_entries(1).collect();
        assert_eq!(*dup_entries[0].0, MapKeyRef::String("x"));
        assert!(matches!(
            dup_entries[0].1,
            ParsedMapValue::Scalar(FieldValueRef::Int32(20))
        ));
    }

    #[test]
    fn parse_map_with_repeated_message_values() {
        // Test map<string, Message> where Message has repeated fields.
        // This tests that map values can be complex nested structures.
        let value_msg = make_descriptor(
            "ValueMsg",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(2, "tags", Type::String, true, None),
            ],
        );
        let mut map_entry = make_descriptor(
            "MapEntry",
            vec![
                make_field(1, "key", Type::String, false, None),
                make_field(2, "value", Type::Message, false, Some(".Outer.ValueMsg")),
            ],
        );
        map_entry.options = Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });

        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Outer.MapEntry"),
            )],
        );
        outer.nested_type.push(map_entry);
        outer.nested_type.push(value_msg);

        let registry = MessageRegistry::from_descriptor(&outer);

        // Map entry: key="k1", value=ValueMsg{id=99, tags=["a", "b"]}.
        // ValueMsg: tag=8 (id), 99, tag=18 (tags), len=1, "a", tag=18, len=1, "b".
        let value_msg_bytes = &[
            8, 99, // id=99
            18, 1, b'a', // tags="a"
            18, 1, b'b', // tags="b"
        ];
        let mut entry_wire = vec![
            10,
            2,
            b'k',
            b'1', // key="k1"
            18,
            value_msg_bytes.len() as u8, // value=ValueMsg
        ];
        entry_wire.extend_from_slice(value_msg_bytes);

        let mut wire = vec![10, entry_wire.len() as u8]; // Field 1, len-delimited.
        wire.extend_from_slice(&entry_wire);

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();

        assert_eq!(parsed.get_map_entries_count(1), 1);
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(*entries[0].0, MapKeyRef::String("k1"));

        match entries[0].1 {
            ParsedMapValue::Message(msg) => {
                assert_eq!(msg.get_scalar(1), Some(&FieldValueRef::Int32(99)));
                let tags = msg.get_repeated_scalars(2);
                assert_eq!(tags.len(), 2);
                assert_eq!(tags[0], FieldValueRef::String("a"));
                assert_eq!(tags[1], FieldValueRef::String("b"));
            }
            _ => panic!("Expected message value"),
        }
    }

    #[test]
    fn parse_multibyte_utf8_strings() {
        let desc = make_descriptor(
            "Test",
            vec![
                make_field(1, "emoji", Type::String, false, None),
                make_field(2, "cjk", Type::String, false, None),
                make_field(3, "mixed", Type::String, false, None),
            ],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Field 1: "Hello 👋 World".
        let emoji = "Hello 👋 World";
        let mut wire = vec![10, emoji.len() as u8];
        wire.extend_from_slice(emoji.as_bytes());

        // Field 2: "你好世界" (Chinese for "Hello World").
        let cjk = "你好世界";
        wire.push(18); // Tag for field 2.
        wire.push(cjk.len() as u8);
        wire.extend_from_slice(cjk.as_bytes());

        // Field 3: Mixed scripts "Привет🌍World".
        let mixed = "Привет🌍World";
        wire.push(26); // Tag for field 3.
        wire.push(mixed.len() as u8);
        wire.extend_from_slice(mixed.as_bytes());

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();

        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::String(emoji)));
        assert_eq!(parsed.get_scalar(2), Some(&FieldValueRef::String(cjk)));
        assert_eq!(parsed.get_scalar(3), Some(&FieldValueRef::String(mixed)));
    }

    #[test]
    fn parse_singular_message_merges_scalars_per_spec() {
        // Spec: "all singular scalar fields in the latter instance replace
        // those in the former". Covers all three scalar merge paths in one
        // shot — gain (other.Some, self.None), last-wins (both Some), preserve
        // (other.None, self.Some).
        let inner = make_descriptor(
            "Inner",
            vec![
                make_field(1, "x", Type::Int32, false, None),
                make_field(2, "y", Type::Int32, false, None),
                make_field(3, "z", Type::String, false, None),
            ],
        );
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "inner",
                Type::Message,
                false,
                Some(".Outer.Inner"),
            )],
        );
        outer.nested_type.push(inner);
        let registry = MessageRegistry::from_descriptor(&outer);

        // inner1: y=1, z="z1" (no x); inner2: x=10, y=2 (no z).
        let mut wire = ld(1, &[16, 1, 26, 2, b'z', b'1']);
        wire.extend(ld(1, &[8, 10, 16, 2]));

        let m = ParsedMessage::parse(&wire, &registry).unwrap();
        let i = m.get_message(1).expect("inner");
        assert_eq!(i.get_scalar(1), Some(&FieldValueRef::Int32(10))); // gain
        assert_eq!(i.get_scalar(2), Some(&FieldValueRef::Int32(2))); // last-wins
        assert_eq!(i.get_scalar(3), Some(&FieldValueRef::String("z1"))); // preserve
    }

    #[test]
    fn parse_singular_message_merge_recurses_through_nested() {
        // A { B b { C c { x, y } } } — outer A appears twice with different
        // scalars in C; merge must walk through B into C.
        let c = make_descriptor(
            "C",
            vec![
                make_field(1, "x", Type::Int32, false, None),
                make_field(2, "y", Type::Int32, false, None),
            ],
        );
        let mut b = make_descriptor(
            "B",
            vec![make_field(1, "c", Type::Message, false, Some(".A.B.C"))],
        );
        b.nested_type.push(c);
        let mut a = make_descriptor(
            "A",
            vec![make_field(1, "b", Type::Message, false, Some(".A.B"))],
        );
        a.nested_type.push(b);
        let registry = MessageRegistry::from_descriptor(&a);

        let mut wire = ld(1, &ld(1, &[8, 7])); // A { B { C{x=7} } }
        wire.extend(ld(1, &ld(1, &[16, 9]))); // A { B { C{y=9} } }

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let c = parsed.get_message(1).expect("b").get_message(1).expect("c");
        assert_eq!(c.get_scalar(1), Some(&FieldValueRef::Int32(7)));
        assert_eq!(c.get_scalar(2), Some(&FieldValueRef::Int32(9)));
    }

    #[test]
    fn parse_singular_message_merge_handles_oneofs() {
        // Outer wraps Wrapper{oneof payload {int32 a; string b; Inner msg}}.
        // When Outer's `w` appears twice on the wire, merge_from must apply
        // MergeFrom rules to the oneof: writes from `other` clear pre-existing
        // siblings in `self`, and same-member message repeats merge.
        let inner = make_descriptor("Inner", vec![make_field(1, "x", Type::Int32, false, None)]);
        let mut wrapper = make_descriptor_with_oneofs(
            "Wrapper",
            vec![
                make_oneof_field(1, "a", Type::Int32, false, None, Some(0)),
                make_oneof_field(2, "b", Type::String, false, None, Some(0)),
                make_oneof_field(
                    3,
                    "msg",
                    Type::Message,
                    false,
                    Some(".Outer.Wrapper.Inner"),
                    Some(0),
                ),
            ],
            vec!["payload"],
        );
        wrapper.nested_type.push(inner);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "w",
                Type::Message,
                false,
                Some(".Outer.Wrapper"),
            )],
        );
        outer.nested_type.push(wrapper);
        let registry = MessageRegistry::from_descriptor(&outer);

        // A: scalar `a` then message `msg` — merge_from clears scalar `a`.
        let mut wire = ld(1, &[8, 7]);
        wire.extend(ld(1, &ld(3, &[8, 1])));
        let p = ParsedMessage::parse(&wire, &registry).unwrap();
        let w = p.get_message(1).unwrap();
        assert!(!w.has_field(1) && !w.has_field(2));
        assert_eq!(
            w.get_message(3).unwrap().get_scalar(1),
            Some(&FieldValueRef::Int32(1))
        );

        // B: same message member twice — inner messages merge (Inner has only x,
        // so scalar last-wins semantics surface inside the merged inner).
        let mut wire = ld(1, &ld(3, &[8, 1]));
        wire.extend(ld(1, &ld(3, &[8, 10])));
        let p = ParsedMessage::parse(&wire, &registry).unwrap();
        assert_eq!(
            p.get_message(1)
                .unwrap()
                .get_message(3)
                .unwrap()
                .get_scalar(1),
            Some(&FieldValueRef::Int32(10))
        );

        // C: message `msg` then scalar `b` — merge_from clears the message
        // slot before installing the scalar.
        let mut wire = ld(1, &ld(3, &[8, 1]));
        wire.extend(ld(1, &[18, 2, b'h', b'i']));
        let p = ParsedMessage::parse(&wire, &registry).unwrap();
        let w = p.get_message(1).unwrap();
        assert!(w.get_message(3).is_none());
        assert_eq!(w.get_scalar(2), Some(&FieldValueRef::String("hi")));
    }

    #[test]
    fn parse_singular_message_merges_complex_variants() {
        // Wrapper carries repeated scalars, repeated messages, and a map.
        // When Outer's singular `w` appears twice, merge_from must concatenate
        // repeated variants and union Map variants (last-wins on common keys).
        let item = make_descriptor("Item", vec![make_field(1, "v", Type::Int32, false, None)]);
        let map_entry = make_map_entry_descriptor("CE", Type::String, Type::Int32);
        let mut wrapper = make_descriptor(
            "Wrapper",
            vec![
                make_field(1, "vals", Type::Int32, true, None),
                make_field(2, "items", Type::Message, true, Some(".Outer.Wrapper.Item")),
                make_field(3, "counts", Type::Message, true, Some(".Outer.Wrapper.CE")),
            ],
        );
        wrapper.nested_type.push(item);
        wrapper.nested_type.push(map_entry);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "w",
                Type::Message,
                false,
                Some(".Outer.Wrapper"),
            )],
        );
        outer.nested_type.push(wrapper);
        let registry = MessageRegistry::from_descriptor(&outer);

        // w1: vals=[1,2], items=[Item{v=1}], counts={"a":10}.
        // w2: vals=[3],   items=[Item{v=2}], counts={"a":99, "b":20}. "a" overlaps.
        let mut w1 = vec![8u8, 1, 8, 2];
        w1.extend(ld(2, &[8, 1]));
        w1.extend(ld(3, &[10, 1, b'a', 16, 10]));
        let mut w2 = vec![8u8, 3];
        w2.extend(ld(2, &[8, 2]));
        w2.extend(ld(3, &[10, 1, b'a', 16, 99]));
        w2.extend(ld(3, &[10, 1, b'b', 16, 20]));
        let mut wire = ld(1, &w1);
        wire.extend(ld(1, &w2));

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let w = parsed.get_message(1).expect("w");

        assert_eq!(
            w.get_repeated_scalars(1),
            &[
                FieldValueRef::Int32(1),
                FieldValueRef::Int32(2),
                FieldValueRef::Int32(3),
            ]
        );
        let item_vs: Vec<_> = w
            .get_repeated_messages(2)
            .iter()
            .map(|m| m.get_scalar(1).copied())
            .collect();
        assert_eq!(
            item_vs,
            vec![Some(FieldValueRef::Int32(1)), Some(FieldValueRef::Int32(2))]
        );

        let counts: std::collections::HashMap<_, i32> = w
            .get_map_entries(3)
            .map(|(k, v)| match v {
                ParsedMapValue::Scalar(FieldValueRef::Int32(n)) => (*k, *n),
                _ => panic!("non-int value"),
            })
            .collect();
        assert_eq!(counts.get(&MapKeyRef::String("a")), Some(&99)); // last-wins
        assert_eq!(counts.get(&MapKeyRef::String("b")), Some(&20));
    }

    #[test]
    fn parse_singular_message_merge_preserves_untouched_oneof() {
        // When the second occurrence doesn't touch the oneof at all,
        // merge_from must NOT clear the oneof member set by the first
        // occurrence. Covers the oneof block path where `other` has no
        // active member (`find` returns None).
        let mut wrapper = make_descriptor_with_oneofs(
            "Wrapper",
            vec![
                make_oneof_field(1, "a", Type::Int32, false, None, Some(0)),
                make_oneof_field(2, "b", Type::String, false, None, Some(0)),
                make_field(4, "always", Type::Int32, false, None),
            ],
            vec!["payload"],
        );
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "w",
                Type::Message,
                false,
                Some(".Outer.Wrapper"),
            )],
        );
        outer.nested_type.push(std::mem::take(&mut wrapper));
        let registry = MessageRegistry::from_descriptor(&outer);

        // First: Wrapper{a=7}. Second: Wrapper{always=42} (tag for field 4
        // scalar varint = 4<<3 = 32). Result: a=7 preserved, always=42.
        let mut wire = ld(1, &[8, 7]);
        wire.extend(ld(1, &[32, 42]));
        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let w = parsed.get_message(1).unwrap();
        assert_eq!(w.get_scalar(1), Some(&FieldValueRef::Int32(7)));
        assert_eq!(w.get_scalar(4), Some(&FieldValueRef::Int32(42)));
        assert!(!w.has_field(2));
    }

    #[test]
    fn parse_singular_message_merge_installs_into_empty_complex_slots() {
        // Self has Empty in Message and Map slots; other populates them.
        // merge_from's complex loop must install (gain) rather than skip.
        let inner = make_descriptor("Inner", vec![make_field(1, "x", Type::Int32, false, None)]);
        let map_entry = make_map_entry_descriptor("CE", Type::String, Type::Int32);
        let mut wrapper = make_descriptor(
            "Wrapper",
            vec![
                make_field(1, "id", Type::Int32, false, None),
                make_field(
                    2,
                    "inner",
                    Type::Message,
                    false,
                    Some(".Outer.Wrapper.Inner"),
                ),
                make_field(3, "counts", Type::Message, true, Some(".Outer.Wrapper.CE")),
            ],
        );
        wrapper.nested_type.push(inner);
        wrapper.nested_type.push(map_entry);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "w",
                Type::Message,
                false,
                Some(".Outer.Wrapper"),
            )],
        );
        outer.nested_type.push(wrapper);
        let registry = MessageRegistry::from_descriptor(&outer);

        // w1: id=1 (no inner, no counts). w2: inner={x=5}, counts={"a":7}.
        let mut wire = ld(1, &[8, 1]);
        let mut w2 = ld(2, &[8, 5]);
        w2.extend(ld(3, &[10, 1, b'a', 16, 7]));
        wire.extend(ld(1, &w2));

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let w = parsed.get_message(1).unwrap();
        assert_eq!(w.get_scalar(1), Some(&FieldValueRef::Int32(1))); // preserved
        assert_eq!(
            w.get_message(2).unwrap().get_scalar(1),
            Some(&FieldValueRef::Int32(5))
        ); // installed
        let counts: Vec<_> = w.get_map_entries(3).collect();
        assert_eq!(counts.len(), 1);
        assert_eq!(*counts[0].0, MapKeyRef::String("a"));
    }

    #[test]
    fn parse_singular_message_merge_no_op_when_other_is_empty() {
        // Second occurrence parses to a completely empty ParsedMessage;
        // merge_from must leave self untouched. Targets the "all None / Empty
        // in other" path of every loop in merge_from.
        let wrapper = make_descriptor(
            "Wrapper",
            vec![make_field(1, "id", Type::Int32, false, None)],
        );
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "w",
                Type::Message,
                false,
                Some(".Outer.Wrapper"),
            )],
        );
        outer.nested_type.push(wrapper);
        let registry = MessageRegistry::from_descriptor(&outer);

        // First Wrapper{id=10}, second empty Wrapper{} (zero-length payload).
        let mut wire = ld(1, &[8, 10]);
        wire.extend(ld(1, &[]));
        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let w = parsed.get_message(1).unwrap();
        assert_eq!(w.get_scalar(1), Some(&FieldValueRef::Int32(10)));
    }

    #[test]
    fn parse_map_entry_single_message_value_field_installs() {
        // Targets parse_map_entry_recursive's "prior None + new Message" arm
        // (the `(_, new_value)` catch-all). Single map entry, single value
        // field, message-typed.
        let inner = make_descriptor("Inner", vec![make_field(1, "x", Type::Int32, false, None)]);
        let mut map_entry = make_descriptor(
            "ME",
            vec![
                make_field(1, "key", Type::String, false, None),
                make_field(2, "value", Type::Message, false, Some(".Outer.Inner")),
            ],
        );
        map_entry.options = Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(1, "m", Type::Message, true, Some(".Outer.ME"))],
        );
        outer.nested_type.push(inner);
        outer.nested_type.push(map_entry);
        let registry = MessageRegistry::from_descriptor(&outer);

        let mut entry = vec![10u8, 1, b'k'];
        entry.extend(ld(2, &[8, 42]));
        let wire = ld(1, &entry);

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(entries.len(), 1);
        let (k, v) = entries[0];
        assert_eq!(*k, MapKeyRef::String("k"));
        let ParsedMapValue::Message(m) = v else {
            panic!("expected Message value");
        };
        assert_eq!(m.get_scalar(1), Some(&FieldValueRef::Int32(42)));
    }

    #[test]
    fn parse_map_entry_repeated_value_field_merges_for_messages() {
        // A single map entry whose message-typed value field appears twice;
        // parse_map_entry_recursive must merge per MergeFrom rules.
        let inner = make_descriptor(
            "Inner",
            vec![
                make_field(1, "x", Type::Int32, false, None),
                make_field(2, "y", Type::Int32, false, None),
            ],
        );
        let mut map_entry = make_descriptor(
            "ME",
            vec![
                make_field(1, "key", Type::String, false, None),
                make_field(2, "value", Type::Message, false, Some(".Outer.Inner")),
            ],
        );
        map_entry.options = Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(1, "m", Type::Message, true, Some(".Outer.ME"))],
        );
        outer.nested_type.push(inner);
        outer.nested_type.push(map_entry);
        let registry = MessageRegistry::from_descriptor(&outer);

        // Entry: key="k", value=Inner{x=10}, value=Inner{y=20}.
        let mut entry = vec![10u8, 1, b'k'];
        entry.extend(ld(2, &[8, 10]));
        entry.extend(ld(2, &[16, 20]));
        let wire = ld(1, &entry);

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(entries.len(), 1);
        let (k, v) = entries[0];
        assert_eq!(*k, MapKeyRef::String("k"));
        let ParsedMapValue::Message(m) = v else {
            panic!("expected Message value");
        };
        assert_eq!(m.get_scalar(1), Some(&FieldValueRef::Int32(10)));
        assert_eq!(m.get_scalar(2), Some(&FieldValueRef::Int32(20)));
    }

    #[test]
    fn parse_map_entry_with_extra_fields() {
        // Map entries should only use fields 1 (key) and 2 (value).
        // Extra fields should be silently ignored per protobuf spec.
        let mut map_entry = make_descriptor(
            "MapEntry",
            vec![
                make_field(1, "key", Type::String, false, None),
                make_field(2, "value", Type::Int32, false, None),
                make_field(3, "extra", Type::String, false, None), // Extra field.
            ],
        );
        map_entry.options = Some(MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });

        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "items",
                Type::Message,
                true,
                Some(".Outer.MapEntry"),
            )],
        );
        outer.nested_type.push(map_entry);

        let registry = MessageRegistry::from_descriptor(&outer);

        // Map entry: key="k", value=42, extra="ignored".
        // Tag 10 (key), len 1, "k", tag 16 (value), 42, tag 26 (extra), len 7, "ignored".
        let entry_wire = &[
            10, 1, b'k', // key="k"
            16, 42, // value=42
            26, 7, b'i', b'g', b'n', b'o', b'r', b'e', b'd', // extra="ignored"
        ];
        let mut wire = vec![10, entry_wire.len() as u8]; // Field 1, len-delimited.
        wire.extend_from_slice(entry_wire);

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();

        assert_eq!(parsed.get_map_entries_count(1), 1);
        let entries: Vec<_> = parsed.get_map_entries(1).collect();
        assert_eq!(*entries[0].0, MapKeyRef::String("k"));
        match entries[0].1 {
            ParsedMapValue::Scalar(v) => assert_eq!(v, &FieldValueRef::Int32(42)),
            _ => panic!("Expected scalar value"),
        }
        // Extra field should be silently ignored (no way to access it from parsed result).
    }

    #[test]
    fn map_key_invalid_types_rejected() {
        // Test that invalid map key types (float, double, bytes) are rejected.
        // Note: We only test float/double/bytes here because:
        // - message (structs) → comes through as Bytes in wire format, so already covered
        // - repeated/map → invalid protobuf syntax, can't be declared as key types
        let invalid_key_types = vec![
            ("float", Type::Float),
            ("double", Type::Double),
            ("bytes", Type::Bytes),
        ];

        for (type_name, key_type) in invalid_key_types {
            let map_entry = make_map_entry_descriptor("MapEntry", key_type, Type::Int32);
            let mut outer = make_descriptor(
                "Outer",
                vec![make_field(
                    1,
                    "items",
                    Type::Message,
                    true,
                    Some(".Outer.MapEntry"),
                )],
            );
            outer.nested_type.push(map_entry);

            let registry = MessageRegistry::from_descriptor(&outer);

            // Create wire data for a map entry with the invalid key type.
            // For float/double: use fixed32/fixed64 wire format.
            // For bytes: use len-delimited wire format.
            let entry_wire: Vec<u8> = match key_type {
                Type::Float => vec![
                    13, 0, 0, 128, 63, // key = 1.0f (fixed32 wire type)
                    16, 42, // value = 42
                ],
                Type::Double => vec![
                    9, 0, 0, 0, 0, 0, 0, 240, 63, // key = 1.0 (fixed64 wire type)
                    16, 42, // value = 42
                ],
                Type::Bytes => vec![
                    10, 3, b'a', b'b', b'c', // key = "abc" (bytes)
                    16, 42, // value = 42
                ],
                _ => unreachable!(),
            };

            let mut wire = vec![10, entry_wire.len() as u8];
            wire.extend_from_slice(&entry_wire);

            let result = ParsedMessage::parse(&wire, &registry);
            assert!(
                result.is_err(),
                "Expected error for invalid map key type: {}",
                type_name
            );
            assert!(
                matches!(result, Err(ParseError::InvalidMapKeyType { .. })),
                "Expected InvalidMapKeyType error for {}, got {:?}",
                type_name,
                result
            );
        }
    }

    #[test]
    fn map_key_valid_types_all_supported() {
        // Test that all valid map key types are supported.
        let valid_key_cases: Vec<(&str, Type, &[u8], MapKeyRef)> = vec![
            (
                "string",
                Type::String,
                &[10, 3, b'f', b'o', b'o'], // key = "foo"
                MapKeyRef::String("foo"),
            ),
            (
                "int32",
                Type::Int32,
                &[8, 42], // key = 42
                MapKeyRef::Int32(42),
            ),
            (
                "int64",
                Type::Int64,
                &[8, 0x80, 0x01], // key = 128
                MapKeyRef::Int64(128),
            ),
            (
                "uint32",
                Type::Uint32,
                &[8, 100], // key = 100
                MapKeyRef::UInt32(100),
            ),
            (
                "uint64",
                Type::Uint64,
                &[8, 200, 1], // key = 200
                MapKeyRef::UInt64(200),
            ),
            (
                "sint32",
                Type::Sint32,
                &[8, 1], // zigzag encoded -1
                MapKeyRef::Int32(-1),
            ),
            (
                "sint64",
                Type::Sint64,
                &[8, 3], // zigzag encoded -2
                MapKeyRef::Int64(-2),
            ),
            (
                "fixed32",
                Type::Fixed32,
                &[13, 0x78, 0x56, 0x34, 0x12], // key = 0x12345678
                MapKeyRef::UInt32(0x12345678),
            ),
            (
                "fixed64",
                Type::Fixed64,
                &[9, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01], // key = 0x0102030405060708
                MapKeyRef::UInt64(0x0102030405060708),
            ),
            (
                "sfixed32",
                Type::Sfixed32,
                &[13, 0xFF, 0xFF, 0xFF, 0xFF], // key = -1
                MapKeyRef::Int32(-1),
            ),
            (
                "sfixed64",
                Type::Sfixed64,
                &[9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // key = -1
                MapKeyRef::Int64(-1),
            ),
            (
                "bool_true",
                Type::Bool,
                &[8, 1], // key = true
                MapKeyRef::Bool(true),
            ),
            (
                "bool_false",
                Type::Bool,
                &[8, 0], // key = false
                MapKeyRef::Bool(false),
            ),
        ];

        for (case_name, key_type, key_wire, expected_key) in valid_key_cases {
            let map_entry = make_map_entry_descriptor("MapEntry", key_type, Type::Int32);
            let mut outer = make_descriptor(
                "Outer",
                vec![make_field(
                    1,
                    "items",
                    Type::Message,
                    true,
                    Some(".Outer.MapEntry"),
                )],
            );
            outer.nested_type.push(map_entry);

            let registry = MessageRegistry::from_descriptor(&outer);

            // Build entry wire: key + value (tag=16, varint 99).
            let mut entry_wire = key_wire.to_vec();
            entry_wire.extend_from_slice(&[16, 99]); // value = 99

            let mut wire = vec![10, entry_wire.len() as u8];
            wire.extend_from_slice(&entry_wire);

            let parsed = ParsedMessage::parse(&wire, &registry)
                .unwrap_or_else(|e| panic!("Failed to parse for case {}: {:?}", case_name, e));

            assert_eq!(parsed.get_map_entries_count(1), 1, "case: {}", case_name);
            let entries: Vec<_> = parsed.get_map_entries(1).collect();
            assert_eq!(
                *entries[0].0, expected_key,
                "case: {} key mismatch",
                case_name
            );
            match entries[0].1 {
                ParsedMapValue::Scalar(v) => {
                    assert_eq!(v, &FieldValueRef::Int32(99), "case: {} value", case_name)
                }
                _ => panic!("Expected scalar value for case {}", case_name),
            }
        }
    }

    /// Create a field descriptor with an optional oneof_index.
    fn make_oneof_field(
        number: i32,
        name: &str,
        field_type: Type,
        repeated: bool,
        type_name: Option<&str>,
        oneof_index: Option<i32>,
    ) -> FieldDescriptorProto {
        let mut field = make_field(number, name, field_type, repeated, type_name);
        field.oneof_index = oneof_index;
        field
    }

    /// Create a descriptor with oneof declarations.
    fn make_descriptor_with_oneofs(
        name: &str,
        fields: Vec<FieldDescriptorProto>,
        oneof_names: Vec<&str>,
    ) -> DescriptorProto {
        let mut desc = make_descriptor(name, fields);
        desc.oneof_decl = oneof_names
            .into_iter()
            .map(|n| OneofDescriptorProto {
                name: Some(n.to_string()),
                options: None,
            })
            .collect();
        desc
    }

    #[test]
    fn oneof_last_writer_wins_scalars() {
        // Oneof group with two scalar fields: field 2 (name) and field 3 (id).
        // Setting field 3 after field 2 should clear field 2.
        let desc = make_descriptor_with_oneofs(
            "Test",
            vec![
                make_field(1, "always_present", Type::Int32, false, None),
                make_oneof_field(2, "name", Type::String, false, None, Some(0)),
                make_oneof_field(3, "id", Type::Int32, false, None, Some(0)),
            ],
            vec!["value"],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire: always_present=42, name="hi", id=99.
        // Last writer (id=99) should win; name should be cleared.
        // Field 2 (string) tag = (2<<3)|2 = 18; field 3 (int32) tag = (3<<3)|0 = 24.
        let wire = &[
            8, 42, // field 1 = 42
            18, 2, b'h', b'i', // field 2 (name) = "hi"
            24, 99, // field 3 (id) = 99
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // Field 1 (not in oneof) should be unaffected.
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(42)));
        // Field 2 (name) should be cleared because field 3 was set last.
        assert!(!parsed.has_field(2));
        assert_eq!(parsed.get_scalar(2), None);
        // Field 3 (id) should be present.
        assert_eq!(parsed.get_scalar(3), Some(&FieldValueRef::Int32(99)));
    }

    #[test]
    fn oneof_last_writer_wins_reverse_order() {
        // Same oneof but fields arrive in reverse order: id first, then name.
        let desc = make_descriptor_with_oneofs(
            "Test",
            vec![
                make_oneof_field(1, "name", Type::String, false, None, Some(0)),
                make_oneof_field(2, "id", Type::Int32, false, None, Some(0)),
            ],
            vec!["value"],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire: id=99, name="winner".
        let wire = &[
            16, 99, // field 2 (id) = 99
            10, 6, b'w', b'i', b'n', b'n', b'e', b'r', // field 1 (name) = "winner"
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // Field 1 (name) should win since it was set last.
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::String("winner")));
        // Field 2 (id) should be cleared.
        assert!(!parsed.has_field(2));
    }

    #[test]
    fn oneof_mixed_scalar_and_message() {
        // Oneof group with a scalar and a message field.
        let inner = make_descriptor("Inner", vec![make_field(1, "x", Type::Int32, false, None)]);
        let mut desc = make_descriptor_with_oneofs(
            "Outer",
            vec![
                make_field(1, "tag", Type::Int32, false, None),
                make_oneof_field(2, "str_val", Type::String, false, None, Some(0)),
                make_oneof_field(
                    3,
                    "msg_val",
                    Type::Message,
                    false,
                    Some(".Outer.Inner"),
                    Some(0),
                ),
            ],
            vec!["payload"],
        );
        desc.nested_type.push(inner);

        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire: str_val="hello", msg_val={x=42}. Last writer (msg_val) wins.
        let inner_wire = &[8, 42]; // Inner { x: 42 }
        let mut wire = vec![
            8,
            1, // tag=1
            18,
            5,
            b'h',
            b'e',
            b'l',
            b'l',
            b'o', // str_val="hello"
            26,
            inner_wire.len() as u8, // msg_val (field 3, len-delimited)
        ];
        wire.extend_from_slice(inner_wire);

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();

        // tag field (not in oneof) should be present.
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(1)));
        // str_val should be cleared.
        assert!(!parsed.has_field(2));
        // msg_val should be present.
        let msg = parsed.get_message(3).expect("msg_val should be present");
        assert_eq!(msg.get_scalar(1), Some(&FieldValueRef::Int32(42)));
    }

    #[test]
    fn oneof_message_then_scalar_clears_message() {
        // Oneof with message field set first, then scalar. Scalar should clear the message.
        let inner = make_descriptor("Inner", vec![make_field(1, "x", Type::Int32, false, None)]);
        let mut desc = make_descriptor_with_oneofs(
            "Outer",
            vec![
                make_oneof_field(2, "str_val", Type::String, false, None, Some(0)),
                make_oneof_field(
                    3,
                    "msg_val",
                    Type::Message,
                    false,
                    Some(".Outer.Inner"),
                    Some(0),
                ),
            ],
            vec!["payload"],
        );
        desc.nested_type.push(inner);

        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire: msg_val={x=42}, str_val="wins". Last writer (str_val) wins.
        let inner_wire = &[8, 42];
        let mut wire = vec![26, inner_wire.len() as u8];
        wire.extend_from_slice(inner_wire);
        wire.extend_from_slice(&[18, 4, b'w', b'i', b'n', b's']); // str_val="wins"

        let parsed = ParsedMessage::parse(&wire, &registry).unwrap();

        // str_val should be present.
        assert_eq!(parsed.get_scalar(2), Some(&FieldValueRef::String("wins")));
        // msg_val should be cleared.
        assert!(!parsed.has_field(3));
        assert!(parsed.get_message(3).is_none());
    }

    #[test]
    fn oneof_non_oneof_fields_unaffected() {
        // Verify that fields not in any oneof are never cleared by oneof logic.
        let desc = make_descriptor_with_oneofs(
            "Test",
            vec![
                make_field(1, "regular_a", Type::Int32, false, None),
                make_field(2, "regular_b", Type::String, false, None),
                make_oneof_field(3, "choice_a", Type::Int32, false, None, Some(0)),
                make_oneof_field(4, "choice_b", Type::Int32, false, None, Some(0)),
            ],
            vec!["choice"],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire: regular_a=1, regular_b="ok", choice_a=10, choice_b=20.
        let wire = &[
            8, 1, // field 1 = 1
            18, 2, b'o', b'k', // field 2 = "ok"
            24, 10, // field 3 (choice_a) = 10
            32, 20, // field 4 (choice_b) = 20
        ];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        // Regular fields should be unaffected.
        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(1)));
        assert_eq!(parsed.get_scalar(2), Some(&FieldValueRef::String("ok")));
        // choice_a should be cleared, choice_b wins.
        assert!(!parsed.has_field(3));
        assert_eq!(parsed.get_scalar(4), Some(&FieldValueRef::Int32(20)));
    }

    #[test]
    fn oneof_proto3_optional_excluded() {
        // Proto3 optional fields have a synthetic oneof but should not participate
        // in oneof clearing logic.
        let mut field2 = make_oneof_field(2, "opt_field", Type::Int32, false, None, Some(0));
        field2.proto3_optional = Some(true);

        let desc = make_descriptor_with_oneofs(
            "Test",
            vec![
                make_oneof_field(1, "real_a", Type::Int32, false, None, Some(0)),
                field2,
            ],
            vec!["_opt_field"],
        );
        let registry = MessageRegistry::from_descriptor(&desc);

        // Wire: real_a=10, opt_field=20. Both should be present because
        // opt_field's oneof_index is filtered out (proto3_optional).
        let wire = &[8, 10, 16, 20];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        assert_eq!(parsed.get_scalar(1), Some(&FieldValueRef::Int32(10)));
        assert_eq!(parsed.get_scalar(2), Some(&FieldValueRef::Int32(20)));
    }

    #[test]
    fn get_field_returns_scalar() {
        let desc = make_descriptor("Test", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&[8, 42], &registry).unwrap();

        let field = parsed.get_field(1).unwrap();
        match field {
            ParsedFieldValue::Scalar(FieldValueRef::Int32(42)) => {}
            other => panic!("Expected Scalar(Int32(42)), got {:?}", other),
        }
    }

    #[test]
    fn get_field_returns_message() {
        let inner = make_descriptor("Inner", vec![make_field(1, "a", Type::Int32, false, None)]);
        let mut outer = make_descriptor(
            "Outer",
            vec![make_field(
                1,
                "inner",
                Type::Message,
                false,
                Some(".Outer.Inner"),
            )],
        );
        outer.nested_type.push(inner);

        let registry = MessageRegistry::from_descriptor(&outer);
        let wire = &[10, 2, 8, 7];
        let parsed = ParsedMessage::parse(wire, &registry).unwrap();

        let field = parsed.get_field(1).unwrap();
        match field {
            ParsedFieldValue::Complex(ComplexType::Message(msg)) => {
                assert_eq!(msg.get_scalar(1), Some(&FieldValueRef::Int32(7)));
            }
            other => panic!("Expected Message(Message(_)), got {:?}", other),
        }
    }

    #[test]
    fn get_field_returns_repeated() {
        let desc = make_descriptor("Test", vec![make_field(1, "nums", Type::Int32, true, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&[8, 1, 8, 2], &registry).unwrap();

        let field = parsed.get_field(1).unwrap();
        match field {
            ParsedFieldValue::Complex(ComplexType::RepeatedScalar(v)) => {
                assert_eq!(v.len(), 2);
            }
            other => panic!("Expected RepeatedScalar, got {:?}", other),
        }
    }

    #[test]
    fn get_field_returns_empty_for_unset_complex() {
        let desc = make_descriptor("Test", vec![make_field(1, "nums", Type::Int32, true, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&[], &registry).unwrap();

        let field = parsed.get_field(1).unwrap();
        match field {
            ParsedFieldValue::Complex(ComplexType::Empty) => {}
            other => panic!("Expected Message(Empty), got {:?}", other),
        }
    }

    #[test]
    fn get_field_returns_none_for_unset_scalar() {
        let desc = make_descriptor("Test", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&[], &registry).unwrap();
        assert!(parsed.get_field(1).is_none());
    }

    #[test]
    fn get_field_returns_none_for_unknown() {
        let desc = make_descriptor("Test", vec![make_field(1, "id", Type::Int32, false, None)]);
        let registry = MessageRegistry::from_descriptor(&desc);
        let parsed = ParsedMessage::parse(&[], &registry).unwrap();
        assert!(parsed.get_field(99).is_none());
    }
}
