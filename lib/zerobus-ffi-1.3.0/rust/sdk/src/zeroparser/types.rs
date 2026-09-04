//! Public types for parsed field values.

use std::collections::HashMap;
use std::fmt;

use prost_types::field_descriptor_proto::Type;

use super::errors::{ParseError, ParseResult};
use super::wire::{decode_zigzag32, decode_zigzag64, try_read_varint, WireValue};

/// Maximum allowed nesting depth for protobuf messages.
/// Protobuf messages can be nested arbitrarily deep, but to prevent stack overflow
/// and excessive resource consumption from malicious or malformed input, we limit
/// parsing to 100 levels of nesting.
pub const MAX_NESTING_DEPTH: usize = 100;

/// Protobuf map entries always use field number 1 for the key.
pub const MAP_ENTRY_KEY_FIELD_NUM: i32 = 1;
/// Protobuf map entries always use field number 2 for the value.
pub const MAP_ENTRY_VALUE_FIELD_NUM: i32 = 2;

/// Zero-copy field value passed to callbacks. All data is borrowed from the input bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FieldValueRef<'a> {
    String(&'a str),
    Int32(i32),
    Int64(i64),
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Float(f32),
    Double(f64),
    Bytes(&'a [u8]),
}

/// Convert a wire value to a scalar FieldValueRef based on the field type.
/// This handles non-packed scalar values (used by both message parsing and map entry parsing).
#[inline(always)]
pub(crate) fn convert_scalar_value<'a>(
    field_type: Type,
    wire_value: &WireValue<'a>,
    field_num: i32,
) -> ParseResult<FieldValueRef<'a>> {
    match field_type {
        Type::String => Ok(FieldValueRef::String(wire_value.try_as_str(field_num)?)),
        Type::Int32 => Ok(FieldValueRef::Int32(wire_value.try_as_i32(field_num)?)),
        Type::Sint32 => Ok(FieldValueRef::Int32(decode_zigzag32(
            wire_value.try_as_u32(field_num)?,
        ))),
        Type::Int64 => Ok(FieldValueRef::Int64(wire_value.try_as_i64(field_num)?)),
        Type::Sint64 => Ok(FieldValueRef::Int64(decode_zigzag64(
            wire_value.try_as_u64(field_num)?,
        ))),
        Type::Uint32 | Type::Fixed32 => {
            Ok(FieldValueRef::UInt32(wire_value.try_as_u32(field_num)?))
        }
        Type::Uint64 | Type::Fixed64 => {
            Ok(FieldValueRef::UInt64(wire_value.try_as_u64(field_num)?))
        }
        Type::Sfixed32 => Ok(FieldValueRef::Int32(wire_value.try_as_i32(field_num)?)),
        Type::Sfixed64 => Ok(FieldValueRef::Int64(wire_value.try_as_i64(field_num)?)),
        Type::Bool => Ok(FieldValueRef::Bool(wire_value.try_as_bool(field_num)?)),
        Type::Float => Ok(FieldValueRef::Float(wire_value.try_as_float(field_num)?)),
        Type::Double => Ok(FieldValueRef::Double(wire_value.try_as_double(field_num)?)),
        Type::Bytes => Ok(FieldValueRef::Bytes(wire_value.try_as_bytes(field_num)?)),
        Type::Enum => Ok(FieldValueRef::Int32(wire_value.try_as_i32(field_num)?)),
        Type::Message => Ok(FieldValueRef::Bytes(wire_value.try_as_bytes(field_num)?)),
        Type::Group => Err(ParseError::UnsupportedGroupFieldType { field_num }),
    }
}

/// Get the default value for a field type (used for missing map keys/values).
pub(crate) fn default_value_for_type(field_type: Type) -> FieldValueRef<'static> {
    match field_type {
        Type::String => FieldValueRef::String(""),
        Type::Int32 | Type::Sint32 | Type::Sfixed32 => FieldValueRef::Int32(0),
        Type::Int64 | Type::Sint64 | Type::Sfixed64 => FieldValueRef::Int64(0),
        Type::Uint32 | Type::Fixed32 => FieldValueRef::UInt32(0),
        Type::Uint64 | Type::Fixed64 => FieldValueRef::UInt64(0),
        Type::Bool => FieldValueRef::Bool(false),
        Type::Float => FieldValueRef::Float(0.0),
        Type::Double => FieldValueRef::Double(0.0),
        Type::Bytes | Type::Message => FieldValueRef::Bytes(&[]),
        Type::Enum => FieldValueRef::Int32(0),
        Type::Group => FieldValueRef::Bytes(&[]),
    }
}

/// Internal representation of packed repeated field data.
/// Packed encoding stores multiple values in a single length-delimited bytes field
/// for space efficiency. This type provides an interface to expand packed data
/// into individual scalar values.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PackedField<'a> {
    /// Varint-encoded packed values (int32, int64, uint32, uint64, sint32, sint64, bool, enum).
    Varint(&'a [u8]),
    /// Fixed32-encoded packed values (fixed32, sfixed32, float).
    Fixed32(&'a [u8]),
    /// Fixed64-encoded packed values (fixed64, sfixed64, double).
    Fixed64(&'a [u8]),
}

impl PackedField<'_> {
    /// Returns true if the given field type supports packed encoding.
    /// Only numeric scalar types (integers, floats, bools, enums) can be packed.
    /// Strings, bytes, and messages cannot be packed.
    #[inline(always)]
    pub(crate) const fn is_packable_type(field_type: Type) -> bool {
        matches!(
            field_type,
            Type::Int32
                | Type::Sint32
                | Type::Int64
                | Type::Sint64
                | Type::Uint32
                | Type::Uint64
                | Type::Bool
                | Type::Enum
                | Type::Fixed32
                | Type::Sfixed32
                | Type::Float
                | Type::Fixed64
                | Type::Sfixed64
                | Type::Double
        )
    }

    /// Creates the appropriate PackedField variant for the given field type and bytes.
    /// Returns None if the field type is not packable.
    pub(crate) const fn from_bytes<'a>(
        bytes: &'a [u8],
        field_type: Type,
        field_num: i32,
    ) -> ParseResult<PackedField<'a>> {
        match field_type {
            Type::Int32
            | Type::Sint32
            | Type::Int64
            | Type::Sint64
            | Type::Uint32
            | Type::Uint64
            | Type::Bool
            | Type::Enum => Ok(PackedField::Varint(bytes)),
            Type::Fixed32 | Type::Sfixed32 | Type::Float => Ok(PackedField::Fixed32(bytes)),
            Type::Fixed64 | Type::Sfixed64 | Type::Double => Ok(PackedField::Fixed64(bytes)),
            _ => Err(ParseError::InvalidPackedFieldType { field_num }),
        }
    }
}

impl<'a> PackedField<'a> {
    /// Expand packed values into individual scalars based on the field type.
    /// This decodes the packed bytes and pushes each value to the destination vector.
    pub(crate) fn expand_into(
        self,
        field_type: Type,
        dest: &mut Vec<FieldValueRef<'a>>,
        field_num: i32,
    ) -> ParseResult<()> {
        match self {
            PackedField::Varint(bytes) => {
                Self::expand_packed_varints(bytes, field_type, dest, field_num)
            }
            PackedField::Fixed32(bytes) => {
                Self::expand_packed_fixed32(bytes, field_type, dest, field_num)
            }
            PackedField::Fixed64(bytes) => {
                Self::expand_packed_fixed64(bytes, field_type, dest, field_num)
            }
        }
    }

    /// Expand packed varint-encoded values (int32, int64, uint32, uint64, sint32, sint64, bool, enum).
    fn expand_packed_varints(
        bytes: &'a [u8],
        field_type: Type,
        dest: &mut Vec<FieldValueRef<'a>>,
        field_num: i32,
    ) -> ParseResult<()> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let (val, rest) = try_read_varint(remaining)?;
            remaining = rest;

            let value = match field_type {
                Type::Int32 | Type::Enum => FieldValueRef::Int32(val as i32),
                Type::Sint32 => FieldValueRef::Int32(decode_zigzag32(val as u32)),
                Type::Int64 => FieldValueRef::Int64(val as i64),
                Type::Sint64 => FieldValueRef::Int64(decode_zigzag64(val)),
                Type::Uint32 => FieldValueRef::UInt32(val as u32),
                Type::Uint64 => FieldValueRef::UInt64(val),
                Type::Bool => FieldValueRef::Bool(val != 0),
                _ => return Err(ParseError::InvalidPackedFieldType { field_num }),
            };
            dest.push(value);
        }
        Ok(())
    }

    /// Expand packed fixed32-encoded values (fixed32, sfixed32, float).
    fn expand_packed_fixed32(
        bytes: &'a [u8],
        field_type: Type,
        dest: &mut Vec<FieldValueRef<'a>>,
        field_num: i32,
    ) -> ParseResult<()> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let raw_value =
                u32::from_le_bytes(*Self::read_fixed_chunk::<4>(&mut remaining, field_num)?);
            let value = match field_type {
                Type::Fixed32 => FieldValueRef::UInt32(raw_value),
                Type::Sfixed32 => FieldValueRef::Int32(raw_value as i32),
                Type::Float => FieldValueRef::Float(f32::from_bits(raw_value)),
                _ => return Err(ParseError::InvalidPackedFieldType { field_num }),
            };
            dest.push(value);
        }
        Ok(())
    }

    /// Expand packed fixed64-encoded values (fixed64, sfixed64, double).
    fn expand_packed_fixed64(
        bytes: &'a [u8],
        field_type: Type,
        dest: &mut Vec<FieldValueRef<'a>>,
        field_num: i32,
    ) -> ParseResult<()> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let raw_value =
                u64::from_le_bytes(*Self::read_fixed_chunk::<8>(&mut remaining, field_num)?);
            let value = match field_type {
                Type::Fixed64 => FieldValueRef::UInt64(raw_value),
                Type::Sfixed64 => FieldValueRef::Int64(raw_value as i64),
                Type::Double => FieldValueRef::Double(f64::from_bits(raw_value)),
                _ => return Err(ParseError::InvalidPackedFieldType { field_num }),
            };
            dest.push(value);
        }
        Ok(())
    }

    /// Read a fixed-size chunk from remaining bytes.
    fn read_fixed_chunk<const N: usize>(
        remaining: &mut &'a [u8],
        field_num: i32,
    ) -> ParseResult<&'a [u8; N]> {
        let chunk: &'a [u8; N] = remaining.get(..N).and_then(|s| s.try_into().ok()).ok_or(
            ParseError::BufferTooShort {
                needed: N,
                available: remaining.len(),
                field_num,
            },
        )?;
        *remaining = &remaining[N..];
        Ok(chunk)
    }
}

/// Map key type that only includes types valid as protobuf map keys.
/// Protobuf restricts map keys to integral types, bool, and string.
///
/// NOT allowed as map keys per protobuf spec:
/// - `float`, `double` - rejected (no stable Hash/Eq semantics)
/// - `bytes` - rejected
/// - `message` (structs) - rejected (comes through as Bytes in wire format)
/// - `repeated` (arrays) - invalid protobuf syntax, can't be declared as key type
/// - `map` - invalid protobuf syntax, can't nest maps as keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapKeyRef<'a> {
    String(&'a str),
    Int32(i32),
    Int64(i64),
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
}

impl<'a> MapKeyRef<'a> {
    /// Convert a FieldValueRef to a MapKeyRef if it's a valid map key type.
    #[inline(always)]
    pub fn from_field_value(value: FieldValueRef<'a>) -> Option<MapKeyRef<'a>> {
        match value {
            FieldValueRef::String(s) => Some(MapKeyRef::String(s)),
            FieldValueRef::Int32(v) => Some(MapKeyRef::Int32(v)),
            FieldValueRef::Int64(v) => Some(MapKeyRef::Int64(v)),
            FieldValueRef::UInt32(v) => Some(MapKeyRef::UInt32(v)),
            FieldValueRef::UInt64(v) => Some(MapKeyRef::UInt64(v)),
            FieldValueRef::Bool(v) => Some(MapKeyRef::Bool(v)),
            FieldValueRef::Float(_) | FieldValueRef::Double(_) | FieldValueRef::Bytes(_) => None,
        }
    }

    // Convert a MapKeyRef to a FieldValueRef.
    #[inline(always)]
    pub fn to_field_value(&self) -> FieldValueRef<'a> {
        match *self {
            MapKeyRef::String(s) => FieldValueRef::String(s),
            MapKeyRef::Int32(v) => FieldValueRef::Int32(v),
            MapKeyRef::Int64(v) => FieldValueRef::Int64(v),
            MapKeyRef::UInt32(v) => FieldValueRef::UInt32(v),
            MapKeyRef::UInt64(v) => FieldValueRef::UInt64(v),
            MapKeyRef::Bool(v) => FieldValueRef::Bool(v),
        }
    }
}

/// Map value - either scalar or pre-parsed nested message.
#[derive(Debug)]
pub enum ParsedMapValue<'a> {
    Scalar(FieldValueRef<'a>),
    Message(super::parser::ParsedMessage<'a>),
}

/// Storage type for complex (non-scalar) field types.
#[derive(Debug)]
pub enum ComplexType<'a> {
    /// Field not present in the message.
    Empty,
    /// Singular message field.
    Message(super::parser::ParsedMessage<'a>),
    /// Repeated scalar field.
    RepeatedScalar(Vec<FieldValueRef<'a>>),
    /// Repeated message field.
    RepeatedMessage(Vec<super::parser::ParsedMessage<'a>>),
    /// Map field.
    Map(HashMap<MapKeyRef<'a>, ParsedMapValue<'a>>),
}

impl ComplexType<'_> {
    /// Returns a static string representation of the type variant.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            ComplexType::Empty => "empty",
            ComplexType::Message(_) => "message",
            ComplexType::RepeatedScalar(_) => "repeated scalar",
            ComplexType::RepeatedMessage(_) => "repeated message",
            ComplexType::Map(_) => "map",
        }
    }
}

impl fmt::Display for ComplexType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_value_ref_traits() {
        assert_eq!(FieldValueRef::Int32(42), FieldValueRef::Int32(42));
        assert_ne!(FieldValueRef::Int32(42), FieldValueRef::Int64(42));
        assert_eq!(
            FieldValueRef::String("hello"),
            FieldValueRef::String("hello")
        );

        let val = FieldValueRef::UInt64(12345);
        let copy = val;
        assert_eq!(val, copy);
    }

    #[test]
    fn convert_scalar_value_all_types() {
        let wire_val = WireValue::Len(b"test");
        assert_eq!(
            convert_scalar_value(Type::String, &wire_val, 1).unwrap(),
            FieldValueRef::String("test")
        );

        let wire_val = WireValue::Len(&[0xAA, 0xBB]);
        assert_eq!(
            convert_scalar_value(Type::Bytes, &wire_val, 1).unwrap(),
            FieldValueRef::Bytes(&[0xAA, 0xBB])
        );

        let wire_val = WireValue::Varint(42);
        assert_eq!(
            convert_scalar_value(Type::Int32, &wire_val, 1).unwrap(),
            FieldValueRef::Int32(42)
        );

        let wire_val = WireValue::Varint(9999);
        assert_eq!(
            convert_scalar_value(Type::Int64, &wire_val, 1).unwrap(),
            FieldValueRef::Int64(9999)
        );

        let wire_val = WireValue::Varint(100);
        assert_eq!(
            convert_scalar_value(Type::Uint32, &wire_val, 1).unwrap(),
            FieldValueRef::UInt32(100)
        );

        let wire_val = WireValue::Varint(500);
        assert_eq!(
            convert_scalar_value(Type::Uint64, &wire_val, 1).unwrap(),
            FieldValueRef::UInt64(500)
        );

        let wire_val = WireValue::I32(12345);
        assert_eq!(
            convert_scalar_value(Type::Fixed32, &wire_val, 1).unwrap(),
            FieldValueRef::UInt32(12345)
        );

        let wire_val = WireValue::I64(67890);
        assert_eq!(
            convert_scalar_value(Type::Fixed64, &wire_val, 1).unwrap(),
            FieldValueRef::UInt64(67890)
        );

        let wire_val = WireValue::I32((-1i32) as u32);
        assert_eq!(
            convert_scalar_value(Type::Sfixed32, &wire_val, 1).unwrap(),
            FieldValueRef::Int32(-1)
        );

        let wire_val = WireValue::I64((-100i64) as u64);
        assert_eq!(
            convert_scalar_value(Type::Sfixed64, &wire_val, 1).unwrap(),
            FieldValueRef::Int64(-100)
        );

        let wire_val = WireValue::Varint(1);
        assert_eq!(
            convert_scalar_value(Type::Sint32, &wire_val, 1).unwrap(),
            FieldValueRef::Int32(-1)
        );

        let wire_val = WireValue::Varint(3);
        assert_eq!(
            convert_scalar_value(Type::Sint64, &wire_val, 1).unwrap(),
            FieldValueRef::Int64(-2)
        );

        let wire_val = WireValue::Varint(1);
        assert_eq!(
            convert_scalar_value(Type::Bool, &wire_val, 1).unwrap(),
            FieldValueRef::Bool(true)
        );
        let wire_val = WireValue::Varint(0);
        assert_eq!(
            convert_scalar_value(Type::Bool, &wire_val, 1).unwrap(),
            FieldValueRef::Bool(false)
        );

        let float_bits = 1.5f32.to_bits();
        let wire_val = WireValue::I32(float_bits);
        match convert_scalar_value(Type::Float, &wire_val, 1).unwrap() {
            FieldValueRef::Float(f) => assert!((f - 1.5).abs() < 0.01),
            _ => panic!("Expected Float"),
        }

        let double_bits = 2.5f64.to_bits();
        let wire_val = WireValue::I64(double_bits);
        match convert_scalar_value(Type::Double, &wire_val, 1).unwrap() {
            FieldValueRef::Double(d) => assert!((d - 2.5).abs() < 0.00001),
            _ => panic!("Expected Double"),
        }

        let wire_val = WireValue::Varint(5);
        assert_eq!(
            convert_scalar_value(Type::Enum, &wire_val, 1).unwrap(),
            FieldValueRef::Int32(5)
        );

        let wire_val = WireValue::Len(&[1, 2, 3]);
        assert_eq!(
            convert_scalar_value(Type::Message, &wire_val, 1).unwrap(),
            FieldValueRef::Bytes(&[1, 2, 3])
        );
    }

    #[test]
    fn convert_scalar_value_type_mismatches() {
        let wire_val = WireValue::Varint(42);
        assert!(matches!(
            convert_scalar_value(Type::String, &wire_val, 1),
            Err(ParseError::TypeMismatch { .. })
        ));

        let wire_val = WireValue::I64(100);
        assert!(matches!(
            convert_scalar_value(Type::Int32, &wire_val, 1),
            Err(ParseError::TypeMismatch { .. })
        ));

        let wire_val = WireValue::Varint(42);
        assert!(matches!(
            convert_scalar_value(Type::Float, &wire_val, 1),
            Err(ParseError::TypeMismatch { .. })
        ));

        let wire_val = WireValue::Varint(42);
        assert!(matches!(
            convert_scalar_value(Type::Double, &wire_val, 1),
            Err(ParseError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn convert_scalar_value_group_unsupported() {
        let wire_val = WireValue::Len(&[1, 2, 3]);
        assert_eq!(
            convert_scalar_value(Type::Group, &wire_val, 42),
            Err(ParseError::UnsupportedGroupFieldType { field_num: 42 })
        );
    }

    #[test]
    fn default_value_for_all_types() {
        assert_eq!(
            default_value_for_type(Type::String),
            FieldValueRef::String("")
        );
        assert_eq!(default_value_for_type(Type::Int32), FieldValueRef::Int32(0));
        assert_eq!(default_value_for_type(Type::Int64), FieldValueRef::Int64(0));
        assert_eq!(
            default_value_for_type(Type::Uint32),
            FieldValueRef::UInt32(0)
        );
        assert_eq!(
            default_value_for_type(Type::Uint64),
            FieldValueRef::UInt64(0)
        );
        assert_eq!(
            default_value_for_type(Type::Sint32),
            FieldValueRef::Int32(0)
        );
        assert_eq!(
            default_value_for_type(Type::Sint64),
            FieldValueRef::Int64(0)
        );
        assert_eq!(
            default_value_for_type(Type::Fixed32),
            FieldValueRef::UInt32(0)
        );
        assert_eq!(
            default_value_for_type(Type::Fixed64),
            FieldValueRef::UInt64(0)
        );
        assert_eq!(
            default_value_for_type(Type::Sfixed32),
            FieldValueRef::Int32(0)
        );
        assert_eq!(
            default_value_for_type(Type::Sfixed64),
            FieldValueRef::Int64(0)
        );
        assert_eq!(
            default_value_for_type(Type::Bool),
            FieldValueRef::Bool(false)
        );
        assert_eq!(
            default_value_for_type(Type::Float),
            FieldValueRef::Float(0.0)
        );
        assert_eq!(
            default_value_for_type(Type::Double),
            FieldValueRef::Double(0.0)
        );
        assert_eq!(
            default_value_for_type(Type::Bytes),
            FieldValueRef::Bytes(&[])
        );
        assert_eq!(
            default_value_for_type(Type::Message),
            FieldValueRef::Bytes(&[])
        );
        assert_eq!(default_value_for_type(Type::Enum), FieldValueRef::Int32(0));
        assert_eq!(
            default_value_for_type(Type::Group),
            FieldValueRef::Bytes(&[])
        );
    }

    #[test]
    fn packed_field_is_packable_type() {
        // Packable types.
        assert!(PackedField::is_packable_type(Type::Int32));
        assert!(PackedField::is_packable_type(Type::Int64));
        assert!(PackedField::is_packable_type(Type::Uint32));
        assert!(PackedField::is_packable_type(Type::Uint64));
        assert!(PackedField::is_packable_type(Type::Sint32));
        assert!(PackedField::is_packable_type(Type::Sint64));
        assert!(PackedField::is_packable_type(Type::Fixed32));
        assert!(PackedField::is_packable_type(Type::Fixed64));
        assert!(PackedField::is_packable_type(Type::Sfixed32));
        assert!(PackedField::is_packable_type(Type::Sfixed64));
        assert!(PackedField::is_packable_type(Type::Bool));
        assert!(PackedField::is_packable_type(Type::Float));
        assert!(PackedField::is_packable_type(Type::Double));
        assert!(PackedField::is_packable_type(Type::Enum));

        // Non-packable types.
        assert!(!PackedField::is_packable_type(Type::String));
        assert!(!PackedField::is_packable_type(Type::Bytes));
        assert!(!PackedField::is_packable_type(Type::Message));
        assert!(!PackedField::is_packable_type(Type::Group));
    }

    #[test]
    fn packed_field_expand_varint_types() {
        // Int32.
        let varint_bytes = &[1, 2, 127];
        let mut dest = Vec::new();
        PackedField::Varint(varint_bytes)
            .expand_into(Type::Int32, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 3);
        assert_eq!(dest[0], FieldValueRef::Int32(1));
        assert_eq!(dest[1], FieldValueRef::Int32(2));
        assert_eq!(dest[2], FieldValueRef::Int32(127));

        // Uint64.
        let mut dest = Vec::new();
        PackedField::Varint(&[1, 99])
            .expand_into(Type::Uint64, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 2);
        assert_eq!(dest[0], FieldValueRef::UInt64(1));
        assert_eq!(dest[1], FieldValueRef::UInt64(99));

        // Bool.
        let mut dest = Vec::new();
        PackedField::Varint(&[0, 1, 1, 0])
            .expand_into(Type::Bool, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 4);
        assert_eq!(dest[0], FieldValueRef::Bool(false));
        assert_eq!(dest[1], FieldValueRef::Bool(true));
        assert_eq!(dest[2], FieldValueRef::Bool(true));
        assert_eq!(dest[3], FieldValueRef::Bool(false));

        // Empty packed field.
        let mut dest = Vec::new();
        PackedField::Varint(&[])
            .expand_into(Type::Int32, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 0);
    }

    #[test]
    fn packed_field_expand_fixed32_types() {
        // Fixed32.
        let fixed32_bytes = &[1, 0, 0, 0, 2, 0, 0, 0];
        let mut dest = Vec::new();
        PackedField::Fixed32(fixed32_bytes)
            .expand_into(Type::Fixed32, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 2);
        assert_eq!(dest[0], FieldValueRef::UInt32(1));
        assert_eq!(dest[1], FieldValueRef::UInt32(2));

        // Float.
        let float_bytes = &[0, 0, 128, 63]; // 1.0f32.to_le_bytes()
        let mut dest = Vec::new();
        PackedField::Fixed32(float_bytes)
            .expand_into(Type::Float, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 1);
        assert_eq!(dest[0], FieldValueRef::Float(1.0));

        // Empty.
        let mut dest = Vec::new();
        PackedField::Fixed32(&[])
            .expand_into(Type::Fixed32, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 0);
    }

    #[test]
    fn packed_field_expand_fixed64_types() {
        // Fixed64.
        let fixed64_bytes = &[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        let mut dest = Vec::new();
        PackedField::Fixed64(fixed64_bytes)
            .expand_into(Type::Fixed64, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 2);
        assert_eq!(dest[0], FieldValueRef::UInt64(1));
        assert_eq!(dest[1], FieldValueRef::UInt64(2));

        // Double.
        let double_bytes = &[0, 0, 0, 0, 0, 0, 240, 63]; // 1.0f64.to_le_bytes()
        let mut dest = Vec::new();
        PackedField::Fixed64(double_bytes)
            .expand_into(Type::Double, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 1);
        assert_eq!(dest[0], FieldValueRef::Double(1.0));

        // Empty.
        let mut dest = Vec::new();
        PackedField::Fixed64(&[])
            .expand_into(Type::Fixed64, &mut dest, 1 /* field_num */)
            .unwrap();
        assert_eq!(dest.len(), 0);
    }

    #[test]
    fn packed_field_expand_error_on_invalid_type() {
        // Varint with non-varint type.
        let mut dest = Vec::new();
        let result = PackedField::Varint(&[1, 2]).expand_into(
            Type::String,
            &mut dest,
            1, /* field_num */
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::InvalidPackedFieldType { field_num: 1 })
        ));

        // Fixed32 with non-fixed32 type.
        let mut dest = Vec::new();
        let result = PackedField::Fixed32(&[1, 0, 0, 0]).expand_into(
            Type::Int64,
            &mut dest,
            1, /* field_num */
        );
        assert!(result.is_err());

        // Fixed64 with non-fixed64 type.
        let mut dest = Vec::new();
        let result = PackedField::Fixed64(&[1, 0, 0, 0, 0, 0, 0, 0]).expand_into(
            Type::Bool,
            &mut dest,
            1, /* field_num */
        );
        assert!(result.is_err());
    }

    #[test]
    fn packed_field_expand_error_on_truncated_data() {
        // Fixed32 with incomplete bytes (need 4, have 3).
        let mut dest = Vec::new();
        let result = PackedField::Fixed32(&[1, 0, 0]).expand_into(
            Type::Fixed32,
            &mut dest,
            1, /* field_num */
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::BufferTooShort {
                needed: 4,
                available: 3,
                field_num: 1,
            })
        ));

        // Fixed64 with incomplete bytes (need 8, have 7).
        let mut dest = Vec::new();
        let result = PackedField::Fixed64(&[1, 0, 0, 0, 0, 0, 0]).expand_into(
            Type::Fixed64,
            &mut dest,
            1, /* field_num */
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::BufferTooShort {
                needed: 8,
                available: 7,
                field_num: 1,
            })
        ));
    }

    #[test]
    fn map_key_ref_to_field_value() {
        // String.
        let key = MapKeyRef::String("hello");
        assert_eq!(key.to_field_value(), FieldValueRef::String("hello"));

        // Int32.
        let key = MapKeyRef::Int32(-42);
        assert_eq!(key.to_field_value(), FieldValueRef::Int32(-42));

        // Int64.
        let key = MapKeyRef::Int64(-1_000_000_000_000);
        assert_eq!(
            key.to_field_value(),
            FieldValueRef::Int64(-1_000_000_000_000)
        );

        // UInt32.
        let key = MapKeyRef::UInt32(42);
        assert_eq!(key.to_field_value(), FieldValueRef::UInt32(42));

        // UInt64.
        let key = MapKeyRef::UInt64(1_000_000_000_000);
        assert_eq!(
            key.to_field_value(),
            FieldValueRef::UInt64(1_000_000_000_000)
        );

        // Bool true.
        let key = MapKeyRef::Bool(true);
        assert_eq!(key.to_field_value(), FieldValueRef::Bool(true));

        // Bool false.
        let key = MapKeyRef::Bool(false);
        assert_eq!(key.to_field_value(), FieldValueRef::Bool(false));
    }
}
