# JSON Test Data


## test_parsing
Source: <https://github.com/nst/JSONTestSuite>

A comprehensive test suite for RFC 8259 compliant JSON parsers.
The name of these files tell if their contents should be accepted or rejected.

- `y_` content must be accepted by parsers
- `n_` content must be rejected by parsers
- `i_` parsers are free to accept or reject content


## test_transform
Source: <https://github.com/nst/JSONTestSuite>

These files contain weird structures and characters that parsers may understand differently, eg:

- huge numbers
- dictionaries with similar keys
- NULL characters
- escaped invalid strings


## test_checker
Source: <http://www.json.org/JSON_checker/>

If the JSON_checker is working correctly, it must accept all of the pass\*.json files and reject all of the fail\*.json files. (fail01.json is excluded as it is relaxed in RFC7159. fail18.json is excluded as depth of JSON is not specified.)


## test_roundtrip
Source: <https://github.com/miloyip/nativejson-benchmark>

27 condensed JSONs are parsed and stringified. The results are compared to the original JSONs.

yyjson add more test case in this directory.

## test_encoding
Source: <https://github.com/miloyip/nativejson-benchmark>

Same JSON encoded as UTF-8/UTF-16/UTF-32 with or without BOM. 
RFC 8259 only accept UTF-8 without BOM.


## test_yyjson
JSON files used for yyjson testing.

- `(fail)` content must be rejected
- `(comma)` content has trailing comma
- `(comment)` content has comment
- `(endcomment)` content has comment at end
- `(inf)` content has infinity literal
- `(nan)` content has nan literal
- `(bignum)` content has large number (double overflow)
- `(bighex)` content has large hex number (u64/i64 overflow)
- `(garbage)` content has garbage after document
- `(str_err)` content has invalid unicode
- `(bom)` content has byte order mask (BOM)
- `(ext_num)` content has extended number format
- `(ext_esc)` content has extended escape sequence
- `(ext_ws)` content has extended whitespace
- `(str_sq)` content has single-quoted string
- `(str_uq)` content has unquoted key
