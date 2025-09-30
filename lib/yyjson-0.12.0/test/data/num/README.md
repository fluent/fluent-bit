# Number Test Data

This directory contains test cases used to validate JSON number parsing.

## Number Types

- `int` Integer (e.g., -123, -0)
- `real` Real number (e.g., 1.23, 1e23)
- `hex` Hexadecimal integer (e.g., 0x123)
- `literal` Special numeric literal (e.g., NaN, Infinity)

## Number Flags
- `(big)` Integer that exceeds the int64/uint64 range and should be read as real number
- `(inf)` Number (integer or real) that exceeds the double precision range
- `(ext)` Number valid only when the `EXT_NUMBER` flag is enabled
- `(fail)` Number that must be rejected under all flags
