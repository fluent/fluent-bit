//! Wire format types and low-level parsing functions.

pub use super::errors::{ParseError, ParseResult};

/// Raw wire value before schema interpretation.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum WireValue<'a> {
    Varint(u64),
    /// Fixed 8-byte value (fixed64, sfixed64, double).
    I64(u64),
    Len(&'a [u8]),
    /// Fixed 4-byte value (fixed32, sfixed32, float).
    I32(u32),
}

impl<'a> WireValue<'a> {
    /// Returns the wire type name for error messages.
    pub fn wire_type_name(&self) -> &'static str {
        match self {
            WireValue::Varint(_) => "Varint",
            WireValue::I64(_) => "I64",
            WireValue::Len(_) => "Len",
            WireValue::I32(_) => "I32",
        }
    }

    /// Try to get string value. Returns error if not a Len field or invalid UTF-8.
    #[inline(always)]
    pub fn try_as_str(&self, field_num: i32) -> ParseResult<&'a str> {
        let WireValue::Len(data) = self else {
            return Err(ParseError::TypeMismatch {
                expected: "Len",
                actual: self.wire_type_name(),
                field_num,
            });
        };
        std::str::from_utf8(data).map_err(|_| ParseError::InvalidUtf8 { field_num })
    }

    /// Try to get bytes value. Returns error if not a Len field.
    #[inline(always)]
    pub fn try_as_bytes(&self, field_num: i32) -> ParseResult<&'a [u8]> {
        let WireValue::Len(data) = self else {
            return Err(ParseError::TypeMismatch {
                expected: "Len",
                actual: self.wire_type_name(),
                field_num,
            });
        };
        Ok(data)
    }

    /// Try to get i32 value. Works with both Varint and I32 wire types.
    #[inline(always)]
    pub fn try_as_i32(&self, field_num: i32) -> ParseResult<i32> {
        match self {
            WireValue::Varint(value) => Ok(*value as i32),
            WireValue::I32(value) => Ok(*value as i32),
            _ => Err(ParseError::TypeMismatch {
                expected: "Varint or I32",
                actual: self.wire_type_name(),
                field_num,
            }),
        }
    }

    /// Try to get u32 value. Works with both Varint and I32 wire types.
    #[inline(always)]
    pub fn try_as_u32(&self, field_num: i32) -> ParseResult<u32> {
        match self {
            WireValue::Varint(value) => Ok(*value as u32),
            WireValue::I32(value) => Ok(*value),
            _ => Err(ParseError::TypeMismatch {
                expected: "Varint or I32",
                actual: self.wire_type_name(),
                field_num,
            }),
        }
    }

    /// Try to get i64 value. Works with both Varint and I64 wire types.
    #[inline(always)]
    pub fn try_as_i64(&self, field_num: i32) -> ParseResult<i64> {
        match self {
            WireValue::Varint(value) => Ok(*value as i64),
            WireValue::I64(value) => Ok(*value as i64),
            _ => Err(ParseError::TypeMismatch {
                expected: "Varint or I64",
                actual: self.wire_type_name(),
                field_num,
            }),
        }
    }

    /// Try to get u64 value. Works with both Varint and I64 wire types.
    #[inline(always)]
    pub fn try_as_u64(&self, field_num: i32) -> ParseResult<u64> {
        match self {
            WireValue::Varint(value) => Ok(*value),
            WireValue::I64(value) => Ok(*value),
            _ => Err(ParseError::TypeMismatch {
                expected: "Varint or I64",
                actual: self.wire_type_name(),
                field_num,
            }),
        }
    }

    /// Try to get bool value. Returns error if not a Varint field.
    #[inline(always)]
    pub fn try_as_bool(&self, field_num: i32) -> ParseResult<bool> {
        let WireValue::Varint(value) = self else {
            return Err(ParseError::TypeMismatch {
                expected: "Varint",
                actual: self.wire_type_name(),
                field_num,
            });
        };
        Ok(*value != 0)
    }

    /// Try to get float value. Returns error if not an I32 field.
    #[inline(always)]
    pub fn try_as_float(&self, field_num: i32) -> ParseResult<f32> {
        let WireValue::I32(value) = self else {
            return Err(ParseError::TypeMismatch {
                expected: "I32",
                actual: self.wire_type_name(),
                field_num,
            });
        };
        Ok(f32::from_bits(*value))
    }

    /// Try to get double value. Returns error if not an I64 field.
    #[inline(always)]
    pub fn try_as_double(&self, field_num: i32) -> ParseResult<f64> {
        let WireValue::I64(value) = self else {
            return Err(ParseError::TypeMismatch {
                expected: "I64",
                actual: self.wire_type_name(),
                field_num,
            });
        };
        Ok(f64::from_bits(*value))
    }
}

/// ZigZag decode a 32-bit value (used for sint32).
#[inline(always)]
pub fn decode_zigzag32(n: u32) -> i32 {
    ((n >> 1) as i32) ^ -((n & 1) as i32)
}

/// ZigZag decode a 64-bit value (used for sint64).
#[inline(always)]
pub fn decode_zigzag64(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

/// A wire type as seen on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum WireType {
    /// The Varint WireType indicates the value is a single VARINT.
    Varint = 0,
    /// The I64 WireType indicates that the value is precisely 8 bytes in
    /// little-endian order containing a 64-bit signed integer or double type.
    I64 = 1,
    /// The Len WireType indicates that the value is a length represented as a
    /// VARINT followed by exactly that number of bytes.
    Len = 2,
    /// Deprecated protobuf groups (start).
    StartGroup = 3,
    /// Deprecated protobuf groups (end).
    EndGroup = 4,
    /// The I32 WireType indicates that the value is precisely 4 bytes in
    /// little-endian order containing a 32-bit signed integer or float type.
    I32 = 5,
}

impl TryFrom<u64> for WireType {
    type Error = ParseError;

    #[inline(always)]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::I64),
            2 => Ok(WireType::Len),
            3 => Ok(WireType::StartGroup),
            4 => Ok(WireType::EndGroup),
            5 => Ok(WireType::I32),
            _ => Err(ParseError::InvalidWireType(value as u8)),
        }
    }
}

/// Parsed wire field with field number and raw value.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct WireField<'a> {
    pub field_num: i32,
    pub value: WireValue<'a>,
}

/// Parse a VARINT, returning the parsed value and the remaining bytes.
/// A 64-bit varint can require up to 10 bytes (64 bits / 7 bits per byte).
///
/// Optimized with fast paths for 1-5 byte varints (covers ~99.9% of cases).
///
/// Returns `Err(ParseError::TruncatedVarint)` if buffer is too short.
/// Returns `Err(ParseError::VarintTooLong)` if varint exceeds 10 bytes.
#[inline(always)]
pub fn try_read_varint(data: &[u8]) -> ParseResult<(u64, &[u8])> {
    match *data {
        // Empty buffer.
        [] => Err(ParseError::TruncatedVarint),
        // Fast path: 1-byte varint (values 0-127, very common for field tags and small ints).
        [b0, ref rest @ ..] if b0 < 0x80 => Ok((b0 as u64, rest)),
        // Only 1 byte but continuation bit set.
        [_] => Err(ParseError::TruncatedVarint),
        // Fast path: 2-byte varint (values 128-16383).
        [b0, b1, ref rest @ ..] if b1 < 0x80 => {
            Ok((((b0 & 0x7f) as u64) | ((b1 as u64) << 7), rest))
        }
        // Only 2 bytes but continuation bit set.
        [_, _] => Err(ParseError::TruncatedVarint),
        // Fast path: 3-byte varint (values 16384-2097151).
        [b0, b1, b2, ref rest @ ..] if b2 < 0x80 => Ok((
            ((b0 & 0x7f) as u64) | (((b1 & 0x7f) as u64) << 7) | ((b2 as u64) << 14),
            rest,
        )),
        // Only 3 bytes but continuation bit set.
        [_, _, _] => Err(ParseError::TruncatedVarint),
        // Fast path: 4-byte varint (values 2097152-268435455).
        [b0, b1, b2, b3, ref rest @ ..] if b3 < 0x80 => Ok((
            ((b0 & 0x7f) as u64)
                | (((b1 & 0x7f) as u64) << 7)
                | (((b2 & 0x7f) as u64) << 14)
                | ((b3 as u64) << 21),
            rest,
        )),
        // Only 4 bytes but continuation bit set.
        [_, _, _, _] => Err(ParseError::TruncatedVarint),
        // Fast path: 5-byte varint (values 268435456-34359738367).
        [b0, b1, b2, b3, b4, ref rest @ ..] if b4 < 0x80 => Ok((
            ((b0 & 0x7f) as u64)
                | (((b1 & 0x7f) as u64) << 7)
                | (((b2 & 0x7f) as u64) << 14)
                | (((b3 & 0x7f) as u64) << 21)
                | ((b4 as u64) << 28),
            rest,
        )),
        // Slow path: 6+ byte varints (rare).
        _ => parse_varint_slow(data),
    }
}

/// Slow path for varints with 6+ bytes.
#[inline(always)]
fn parse_varint_slow(data: &[u8]) -> ParseResult<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0;

    // Process bytes 0-8 (each contributes 7 bits).
    for i in 0..9 {
        let Some(&b) = data.get(i) else {
            return Err(ParseError::TruncatedVarint);
        };
        value |= ((b & 0x7f) as u64) << shift;
        if b < 0x80 {
            return Ok((value, &data[i + 1..]));
        }
        shift += 7;
    }

    // 10th byte (index 9): can only contribute bit 0 (9*7 + 1 = 64 bits total).
    // Bits 1-6 would overflow u64, bit 7 (continuation) would require 11+ bytes.
    let Some(&b) = data.get(9) else {
        return Err(ParseError::TruncatedVarint);
    };
    if b > 0x01 {
        return Err(ParseError::VarintTooLong);
    }
    value |= (b as u64) << shift;
    Ok((value, &data[10..]))
}

/// Convert a tag into a field number and a WireType.
/// Returns error if wire type is invalid or field number is out of range.
#[inline(always)]
fn try_unpack_tag(tag: u64) -> ParseResult<(i32, WireType)> {
    let field_num = (tag >> 3) as i32;
    let wire_type = WireType::try_from(tag & 0x7)?;

    // Validate field number range per protobuf spec.
    // Field numbers must be 1 to 536,870,911 (2^29 - 1).
    if !(1..=536_870_911).contains(&field_num) {
        return Err(ParseError::InvalidFieldNumber { field_num });
    }

    Ok((field_num, wire_type))
}
/// Parse a field, returning the field and remaining bytes.
///
/// Returns error on malformed input (truncated buffer, invalid wire type, etc.)
#[inline(always)]
pub fn try_parse_field(data: &[u8]) -> ParseResult<(WireField<'_>, &[u8])> {
    let (tag, remainder) = try_read_varint(data)?;
    let (field_num, wire_type) = try_unpack_tag(tag)?;
    let (fieldvalue, remainder) = match wire_type {
        WireType::Varint => {
            let (value, remainder) = try_read_varint(remainder)?;
            (WireValue::Varint(value), remainder)
        }
        WireType::I64 => {
            // Fixed 8 bytes in little-endian order.
            let bytes: &[u8; 8] = remainder.get(..8).and_then(|s| s.try_into().ok()).ok_or(
                ParseError::BufferTooShort {
                    needed: 8,
                    available: remainder.len(),
                    field_num,
                },
            )?;
            let value = u64::from_le_bytes(*bytes);
            (WireValue::I64(value), &remainder[8..])
        }
        WireType::Len => {
            let (len, remainder) = try_read_varint(remainder)?;
            let len = len as usize;
            if remainder.len() < len {
                return Err(ParseError::BufferTooShort {
                    needed: len,
                    available: remainder.len(),
                    field_num,
                });
            }
            let (value, remainder) = remainder.split_at(len);
            (WireValue::Len(value), remainder)
        }
        WireType::I32 => {
            // Fixed 4 bytes in little-endian order.
            let bytes: &[u8; 4] = remainder.get(..4).and_then(|s| s.try_into().ok()).ok_or(
                ParseError::BufferTooShort {
                    needed: 4,
                    available: remainder.len(),
                    field_num,
                },
            )?;
            let value = u32::from_le_bytes(*bytes);
            (WireValue::I32(value), &remainder[4..])
        }
        WireType::StartGroup | WireType::EndGroup => {
            return Err(ParseError::UnsupportedGroupWireType);
        }
    };
    Ok((
        WireField {
            field_num,
            value: fieldvalue,
        },
        remainder,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_parsing() {
        // Test cases: (input bytes, expected value, expected remaining bytes).
        let cases = [
            // 1-byte varints.
            (&[0x00][..], 0, &[][..]),
            (&[0x01][..], 1, &[][..]),
            (&[0x7F][..], 127, &[][..]),
            // 2-byte varints.
            (&[0x80, 0x01][..], 128, &[][..]),
            // 3-byte varints.
            (&[0x80, 0x80, 0x01][..], 16384, &[][..]),
            // 4-byte varints.
            (&[0x80, 0x80, 0x80, 0x01][..], 2097152, &[][..]),
            (&[0xFF, 0xFF, 0xFF, 0x7F][..], 268435455, &[][..]),
            // 5-byte varints.
            (&[0x80, 0x80, 0x80, 0x80, 0x01][..], 268435456, &[][..]),
            (&[0xFF, 0xFF, 0xFF, 0xFF, 0x7F][..], 34359738367, &[][..]),
            // With trailing bytes.
            (&[0x01, 0x02, 0x03][..], 1, &[0x02, 0x03][..]),
            (&[0x80, 0x80, 0x80, 0x01, 0xFF][..], 2097152, &[0xFF][..]),
        ];
        for (data, expected_val, expected_rest) in cases {
            let (value, rest) = try_read_varint(data).expect("Failed to parse varint");
            assert_eq!(value, expected_val, "data: {:?}", data);
            assert_eq!(rest, expected_rest, "data: {:?}", data);
        }
    }

    #[test]
    fn varint_errors() {
        // Truncated varints.
        assert_eq!(try_read_varint(&[0x80]), Err(ParseError::TruncatedVarint));
        assert_eq!(
            try_read_varint(&[0x80, 0x80]),
            Err(ParseError::TruncatedVarint)
        );
        assert_eq!(
            try_read_varint(&[0x80, 0x80, 0x80]),
            Err(ParseError::TruncatedVarint)
        );
        assert_eq!(
            try_read_varint(&[0x80, 0x80, 0x80, 0x80]),
            Err(ParseError::TruncatedVarint)
        );
        assert_eq!(
            try_read_varint(&[0x80, 0x80, 0x80, 0x80, 0x80]),
            Err(ParseError::TruncatedVarint)
        );

        // Varint too long (11 bytes).
        let too_long = &[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ];
        assert_eq!(try_read_varint(too_long), Err(ParseError::VarintTooLong));
    }

    #[test]
    fn varint_10th_byte_validation() {
        // 10-byte varints: bytes 0-8 all have continuation bit set, byte 9 is the 10th byte.
        // The 10th byte can only have bit 0 set (bits 1-6 would overflow u64, bit 7 would need 11+ bytes).

        // Valid: 10th byte = 0x00 (contributes 0 to the value).
        let valid_zero = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        let (value, rest) = try_read_varint(valid_zero).unwrap();
        assert_eq!(value, 0);
        assert!(rest.is_empty());

        // Valid: 10th byte = 0x01 (sets bit 63, gives 2^63).
        let valid_one = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let (value, rest) = try_read_varint(valid_one).unwrap();
        assert_eq!(value, 1u64 << 63);
        assert!(rest.is_empty());

        // Valid: u64::MAX = all bits set.
        let max_u64 = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let (value, rest) = try_read_varint(max_u64).unwrap();
        assert_eq!(value, u64::MAX);
        assert!(rest.is_empty());

        // Invalid: 10th byte = 0x02 (bit 1 set, would overflow u64).
        let overflow_bit1 = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(
            try_read_varint(overflow_bit1),
            Err(ParseError::VarintTooLong)
        );

        // Invalid: 10th byte = 0x7F (bits 1-6 all set, would overflow u64).
        let overflow_bits = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
        assert_eq!(
            try_read_varint(overflow_bits),
            Err(ParseError::VarintTooLong)
        );

        // Invalid: 10th byte = 0x80 (continuation bit set, would need 11+ bytes).
        let continuation = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
        assert_eq!(
            try_read_varint(continuation),
            Err(ParseError::VarintTooLong)
        );
    }

    #[test]
    fn zigzag_decoding() {
        let cases32 = [
            (0, 0),
            (1, -1),
            (2, 1),
            (3, -2),
            (4, 2),
            (99, -50),
            (100, 50),
        ];
        for (encoded, expected) in cases32 {
            assert_eq!(decode_zigzag32(encoded), expected, "zigzag32({})", encoded);
        }

        let cases64 = [(0, 0), (1, -1), (2, 1), (3, -2), (4, 2)];
        for (encoded, expected) in cases64 {
            assert_eq!(decode_zigzag64(encoded), expected, "zigzag64({})", encoded);
        }
    }

    #[test]
    fn wire_type_conversion() {
        let valid = [
            (0, WireType::Varint),
            (1, WireType::I64),
            (2, WireType::Len),
            (3, WireType::StartGroup),
            (4, WireType::EndGroup),
            (5, WireType::I32),
        ];
        for (val, expected) in valid {
            assert_eq!(WireType::try_from(val), Ok(expected));
        }

        assert_eq!(
            WireType::try_from(6u64),
            Err(ParseError::InvalidWireType(6))
        );
        assert_eq!(
            WireType::try_from(7u64),
            Err(ParseError::InvalidWireType(7))
        );
    }

    #[test]
    fn field_parsing() {
        // (data, expected_field_num, expected_value).
        let cases = [
            // Varint: field 1, value 150. Tag = 8, 150 = 0x96 0x01.
            (&[8, 0x96, 0x01][..], 1, WireValue::Varint(150)),
            // I32: field 1, tag = 13, value 0x01020304 little-endian.
            (
                &[13, 0x04, 0x03, 0x02, 0x01][..],
                1,
                WireValue::I32(0x01020304),
            ),
            // I64: field 1, tag = 9.
            (
                &[9, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..],
                1,
                WireValue::I64(0x0807060504030201),
            ),
            // Len: field 1, tag = 10, length 3.
            (
                &[10, 3, 0xAA, 0xBB, 0xCC][..],
                1,
                WireValue::Len(&[0xAA, 0xBB, 0xCC]),
            ),
        ];
        for (data, expected_num, expected_val) in cases {
            let (field, rest) = try_parse_field(data).unwrap();
            assert_eq!(field.field_num, expected_num, "data: {:?}", data);
            assert_eq!(field.value, expected_val, "data: {:?}", data);
            assert!(rest.is_empty(), "data: {:?}", data);
        }
    }

    #[test]
    fn field_parsing_errors() {
        // Invalid wire type 6: tag = (1 << 3) | 6 = 14.
        assert_eq!(try_parse_field(&[14]), Err(ParseError::InvalidWireType(6)));

        // Group wire type: tag = (1 << 3) | 3 = 11.
        assert_eq!(
            try_parse_field(&[11]),
            Err(ParseError::UnsupportedGroupWireType)
        );

        // Buffer too short for I32: tag 13, only 2 bytes.
        assert_eq!(
            try_parse_field(&[13, 0x01, 0x02]),
            Err(ParseError::BufferTooShort {
                needed: 4,
                available: 2,
                field_num: 1,
            })
        );

        // Buffer too short for I64: tag 9, only 4 bytes.
        assert_eq!(
            try_parse_field(&[9, 0x01, 0x02, 0x03, 0x04]),
            Err(ParseError::BufferTooShort {
                needed: 8,
                available: 4,
                field_num: 1,
            })
        );

        // Buffer too short for Len: tag 10, length 100, only 3 bytes.
        assert_eq!(
            try_parse_field(&[10, 100, 0x01, 0x02, 0x03]),
            Err(ParseError::BufferTooShort {
                needed: 100,
                available: 3,
                field_num: 1,
            })
        );

        // Invalid field number 0: tag = (0 << 3) | 0 = 0.
        assert_eq!(
            try_parse_field(&[0]),
            Err(ParseError::InvalidFieldNumber { field_num: 0 })
        );

        // Invalid field number 536_870_912 (2^29) - exceeds max valid field number 536_870_911.
        // Tag = (536_870_912 << 3) | 0 = 4_294_967_296 -> varint [0x80, 0x80, 0x80, 0x80, 0x10].
        assert_eq!(
            try_parse_field(&[0x80, 0x80, 0x80, 0x80, 0x10]),
            Err(ParseError::InvalidFieldNumber {
                field_num: 536_870_912
            })
        );

        // Max valid field number 536_870_911 (2^29 - 1) is okay.
        // Tag = (536_870_911 << 3) | 0 = 4_294_967_288 -> varint [0xF8, 0xFF, 0xFF, 0xFF, 0x0F].
        let (field, _) = try_parse_field(&[0xF8, 0xFF, 0xFF, 0xFF, 0x0F, 0x01]).unwrap();
        assert_eq!(field.field_num, 536_870_911);
    }

    #[test]
    fn wire_value_accessors() {
        assert_eq!(
            WireValue::Len(b"hello").try_as_str(1 /* field_num */),
            Ok("hello")
        );
        assert_eq!(
            WireValue::Len(&[0xFF, 0xFE]).try_as_str(1 /* field_num */),
            Err(ParseError::InvalidUtf8 { field_num: 1 })
        );
        assert!(matches!(
            WireValue::Varint(42).try_as_str(1 /* field_num */),
            Err(ParseError::TypeMismatch { .. })
        ));

        assert_eq!(
            WireValue::Len(&[1, 2, 3]).try_as_bytes(1 /* field_num */),
            Ok(&[1, 2, 3][..])
        );

        assert_eq!(WireValue::Varint(42).try_as_i32(1 /* field_num */), Ok(42));
        assert_eq!(WireValue::I32(100).try_as_i32(1 /* field_num */), Ok(100));

        assert_eq!(
            WireValue::Varint(1000).try_as_u64(1 /* field_num */),
            Ok(1000)
        );
        assert_eq!(WireValue::I64(2000).try_as_u64(1 /* field_num */), Ok(2000));

        assert_eq!(
            WireValue::Varint(0).try_as_bool(1 /* field_num */),
            Ok(false)
        );
        assert_eq!(
            WireValue::Varint(1).try_as_bool(1 /* field_num */),
            Ok(true)
        );
        assert_eq!(
            WireValue::Varint(42).try_as_bool(1 /* field_num */),
            Ok(true)
        );

        assert!(
            (WireValue::I32(std::f32::consts::PI.to_bits())
                .try_as_float(1 /* field_num */)
                .unwrap()
                - std::f32::consts::PI)
                .abs()
                < 0.001
        );
        assert!(
            (WireValue::I64(std::f64::consts::E.to_bits())
                .try_as_double(1 /* field_num */)
                .unwrap()
                - std::f64::consts::E)
                .abs()
                < 0.00001
        );

        assert_eq!(WireValue::Varint(0).wire_type_name(), "Varint");
        assert_eq!(WireValue::I64(0).wire_type_name(), "I64");
        assert_eq!(WireValue::Len(&[]).wire_type_name(), "Len");
        assert_eq!(WireValue::I32(0).wire_type_name(), "I32");
    }
}
