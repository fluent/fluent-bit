/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#define JSON_ES	"["                             \
    "1448403340,"                               \
    "{"                                         \
    "\"key_0\": false,"                         \
    "\"key_1\": true,"                          \
    "\"key_2\": \"some string\","               \
    "\"key_3\": 0.12345678,"                    \
    "\"key.4\": 5000,"                          \
    "\"END_KEY\": \"JSON_END\""                 \
    "}]"


#define JSON_DOTS                                                       \
    "[1448403340,"                                                      \
    "{\".le.vel\":\"error\", \".fo.o\":[{\".o.k\": [{\".b.ar\": \"baz\"}]}]}]"

#define JSON_RESPONSE_SUCCESSES "{\"errors\":false,\"took\":0,\"items\":[" \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"dcfJBJIBHhdJuKsoC7Tm\",\"_version\":1,\"result\":\"created\"," \
    "\"_shards\":{\"total\":2,\"successful\":1,\"failed\":0},\"_seq_no\":6,\"_primary_term\":1,\"status\":201}}," \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"dsfJBJIBHhdJuKsoC7Tm\",\"_version\":1,\"result\":\"created\"," \
    "\"_shards\":{\"total\":2,\"successful\":1,\"failed\":0},\"_seq_no\":7,\"_primary_term\":1,\"status\":201}}," \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"d8fJBJIBHhdJuKsoC7Tm\",\"_version\":1,\"result\":\"created\"," \
    "\"_shards\":{\"total\":2,\"successful\":1,\"failed\":0},\"_seq_no\":8,\"_primary_term\":1,\"status\":201}}," \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"eMfJBJIBHhdJuKsoC7Tm\",\"_version\":1,\"result\":\"created\"," \
    "\"_shards\":{\"total\":2,\"successful\":1,\"failed\":0},\"_seq_no\":9,\"_primary_term\":1,\"status\":201}}]}"

#define JSON_RESPONSE_SUCCESSES_SIZE 783

#define JSON_RESPONSE_PARTIALLY_SUCCESS "{\"errors\":true,\"took\":316737025,\"items\":" \
    "[{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"hxELapEB_XqxG5Ydupgb\",\"_version\":1,\"result\":\"created\"," \
    "\"_shards\":{\"total\":2,\"successful\":1,\"failed\":0},\"_seq_no\":7,\"_primary_term\":1,\"status\":201}}," \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"iBELapEB_XqxG5Ydupgb\",\"status\":400," \
    "\"error\":{\"type\":\"document_parsing_exception\"," \
    "\"reason\":\"[1:65] failed to parse field [_id] of type [_id] in document with id 'iBELapEB_XqxG5Ydupgb'. " \
    "Preview of field's value: 'fhHraZEB_XqxG5Ydzpjv'\"," \
    "\"caused_by\":{\"type\":\"document_parsing_exception\"," \
    "\"reason\":\"[1:65] Field [_id] is a metadata field and cannot be added inside a document. " \
    "Use the index API request parameters.\"}}}}," \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"iRELapEB_XqxG5Ydupgb\",\"status\":400," \
    "\"error\":{\"type\":\"document_parsing_exception\"," \
    "\"reason\":\"[1:65] failed to parse field [_id] of type [_id] in document with id 'iRELapEB_XqxG5Ydupgb'. " \
    "Preview of field's value: 'fhHraZEB_XqxG5Ydzpjv'\"," \
    "\"caused_by\":{\"type\":\"document_parsing_exception\"," \
    "\"reason\":\"[1:65] Field [_id] is a metadata field and cannot be added inside a document. " \
    "Use the index API request parameters.\"}}}}," \
    "{\"create\":{\"_index\":\"fluent-bit\",\"_id\":\"ihELapEB_XqxG5Ydupgb\",\"_version\":1,\"result\":\"created\"," \
    "\"_shards\":{\"total\":2,\"successful\":1,\"failed\":0},\"_seq_no\":8,\"_primary_term\":1,\"status\":201}}]}"

#define JSON_RESPONSE_PARTIALLY_SUCCESS_SIZE 1322
