//! Error types for protobuf parsing.

use std::fmt;

/// Error type for protobuf parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter, strum::AsRefStr))]
pub enum ParseError {
    /// Not enough bytes to read a fixed-size field.
    BufferTooShort {
        needed: usize,
        available: usize,
        field_num: i32,
    },
    /// Complex field storage type doesn't match expected type.
    ComplexTypeMismatch {
        expected: &'static str,
        actual: &'static str,
        field_num: i32,
    },
    /// Field number out of valid range (1 to 536,870,911).
    InvalidFieldNumber { field_num: i32 },
    /// Invalid map key type (float, double, bytes are not allowed as map keys).
    InvalidMapKeyType { field_num: i32 },
    /// Invalid packed field type (non-packable type with packed encoding).
    InvalidPackedFieldType { field_num: i32 },
    /// String field contains invalid UTF-8.
    InvalidUtf8 { field_num: i32 },
    /// Invalid wire type value (must be 0-5).
    InvalidWireType(u8),
    /// Message nesting depth exceeds maximum allowed limit.
    MaxNestingDepthExceeded { max: usize },
    /// Not enough bytes to parse a varint.
    TruncatedVarint,
    /// Field value type doesn't match expected type.
    TypeMismatch {
        expected: &'static str,
        actual: &'static str,
        field_num: i32,
    },
    /// Unknown message type not found in registry.
    UnknownTypeName { type_name: String },
    /// Deprecated group field type in schema.
    UnsupportedGroupFieldType { field_num: i32 },
    /// Deprecated group wire types are not supported.
    UnsupportedGroupWireType,
    /// Varint encoding uses more than 10 bytes.
    VarintTooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BufferTooShort {
                needed,
                available,
                field_num,
            } => {
                write!(
                    f,
                    "Field #{}: Input buffer too short: need {} bytes, have {}",
                    field_num, needed, available
                )
            }
            ParseError::ComplexTypeMismatch {
                expected,
                actual,
                field_num,
            } => {
                write!(
                    f,
                    "Field #{}: Complex type mismatch: expected {}, got {}",
                    field_num, expected, actual
                )
            }
            ParseError::InvalidFieldNumber { field_num } => {
                write!(
                    f,
                    "Field number {} is out of valid range (must be 1 to 536,870,911)",
                    field_num
                )
            }
            ParseError::InvalidMapKeyType { field_num } => {
                write!(
                    f,
                    "Field #{}: Invalid map key type (float, double, bytes are not allowed)",
                    field_num
                )
            }
            ParseError::InvalidPackedFieldType { field_num } => {
                write!(f, "Field #{}: Invalid packed field type", field_num)
            }
            ParseError::InvalidUtf8 { field_num } => {
                write!(f, "Field #{}: Invalid UTF-8 in string field", field_num)
            }
            ParseError::InvalidWireType(wt) => write!(f, "Invalid wire type: {}", wt),
            ParseError::MaxNestingDepthExceeded { max } => {
                write!(
                    f,
                    "Message nesting depth exceeds maximum allowed limit of {} levels",
                    max
                )
            }
            ParseError::TruncatedVarint => write!(f, "Truncated varint"),
            ParseError::TypeMismatch {
                expected,
                actual,
                field_num,
            } => {
                write!(
                    f,
                    "Field #{}: Type mismatch: expected {}, got {}",
                    field_num, expected, actual
                )
            }
            ParseError::UnknownTypeName { type_name } => {
                write!(f, "Unknown message type '{}' not in registry", type_name)
            }
            ParseError::UnsupportedGroupFieldType { field_num } => {
                write!(f, "Deprecated group field type for field {}", field_num)
            }
            ParseError::UnsupportedGroupWireType => write!(f, "Group wire types are not supported"),
            ParseError::VarintTooLong => write!(f, "Varint exceeds 10 bytes"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Result type for parsing operations.
pub type ParseResult<T> = Result<T, ParseError>;

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::ParseError;

    /// Verify ParseError variants are sorted alphabetically.
    ///
    /// If this fails, reorder the variants in the enum definition above.
    #[test]
    fn parse_error_variants_are_sorted() {
        let names: Vec<String> = ParseError::iter().map(|e| e.as_ref().to_string()).collect();

        let mut sorted = names.clone();
        sorted.sort();

        assert_eq!(
            names, sorted,
            "ParseError variants are not sorted alphabetically.\n\
             Current order: {:?}\n\
             Expected order: {:?}",
            names, sorted
        );
    }
}
