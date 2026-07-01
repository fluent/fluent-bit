/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "yyjson", "index.html", [
    [ "Introduction", "index.html", "index" ],
    [ "Building and testing", "building-and-testing.html", [
      [ "Source code", "building-and-testing.html#source-code", null ],
      [ "Package manager", "building-and-testing.html#package-manager", [
        [ "Use vcpkg", "building-and-testing.html#use-vcpkg", null ]
      ] ],
      [ "CMake", "building-and-testing.html#cmake", [
        [ "Use CMake to build the library", "building-and-testing.html#use-cmake-to-build-the-library", null ],
        [ "Use CMake as a dependency", "building-and-testing.html#use-cmake-as-a-dependency", null ],
        [ "Use CMake to generate project", "building-and-testing.html#use-cmake-to-generate-project", null ],
        [ "Use CMake to generate documentation", "building-and-testing.html#use-cmake-to-generate-documentation", null ],
        [ "Testing With CMake and CTest", "building-and-testing.html#testing-with-cmake-and-ctest", null ]
      ] ],
      [ "Compile-time Options", "building-and-testing.html#compile-time-options", [
        [ "YYJSON_DISABLE_READER", "building-and-testing.html#yyjson_disable_reader", null ],
        [ "YYJSON_DISABLE_WRITER", "building-and-testing.html#yyjson_disable_writer", null ],
        [ "YYJSON_DISABLE_INCR_READER", "building-and-testing.html#yyjson_disable_incr_reader", null ],
        [ "YYJSON_DISABLE_UTILS", "building-and-testing.html#yyjson_disable_utils", null ],
        [ "YYJSON_DISABLE_FAST_FP_CONV", "building-and-testing.html#yyjson_disable_fast_fp_conv", null ],
        [ "YYJSON_DISABLE_NON_STANDARD", "building-and-testing.html#yyjson_disable_non_standard", null ],
        [ "YYJSON_DISABLE_UTF8_VALIDATION", "building-and-testing.html#yyjson_disable_utf8_validation", null ],
        [ "YYJSON_EXPORTS", "building-and-testing.html#yyjson_exports", null ],
        [ "YYJSON_IMPORTS", "building-and-testing.html#yyjson_imports", null ]
      ] ]
    ] ],
    [ "API", "api.html", [
      [ "API Design", "api.html#api-design", [
        [ "API prefix", "api.html#api-prefix", null ],
        [ "API for immutable/mutable data", "api.html#api-for-immutablemutable-data", null ],
        [ "API for string", "api.html#api-for-string", null ]
      ] ],
      [ "Reading JSON", "api.html#reading-json", [
        [ "Read JSON from string", "api.html#read-json-from-string", null ],
        [ "Read JSON from file", "api.html#read-json-from-file", null ],
        [ "Read JSON from file pointer", "api.html#read-json-from-file-pointer", null ],
        [ "Read JSON with options", "api.html#read-json-with-options", null ],
        [ "Read JSON incrementally", "api.html#read-json-incrementally", [
          [ "Create the state for incremental reading", "api.html#create-the-state-for-incremental-reading", null ],
          [ "Perform incremental read", "api.html#perform-incremental-read", null ],
          [ "Free the state used for incremental reading", "api.html#free-the-state-used-for-incremental-reading", null ],
          [ "Sample code", "api.html#sample-code-1", null ]
        ] ],
        [ "Reader error handling", "api.html#reader-error-handling", null ],
        [ "Reader flag", "api.html#reader-flag", [
          [ "YYJSON_READ_NOFLAG = 0", "api.html#yyjson_read_noflag--0", null ],
          [ "YYJSON_READ_INSITU", "api.html#yyjson_read_insitu", null ],
          [ "YYJSON_READ_STOP_WHEN_DONE", "api.html#yyjson_read_stop_when_done", null ],
          [ "YYJSON_READ_ALLOW_TRAILING_COMMAS", "api.html#yyjson_read_allow_trailing_commas", null ],
          [ "YYJSON_READ_ALLOW_COMMENTS", "api.html#yyjson_read_allow_comments", null ],
          [ "YYJSON_READ_ALLOW_INF_AND_NAN", "api.html#yyjson_read_allow_inf_and_nan", null ],
          [ "YYJSON_READ_NUMBER_AS_RAW", "api.html#yyjson_read_number_as_raw", null ],
          [ "YYJSON_READ_BIGNUM_AS_RAW", "api.html#yyjson_read_bignum_as_raw", null ],
          [ "YYJSON_READ_ALLOW_INVALID_UNICODE", "api.html#yyjson_read_allow_invalid_unicode", null ],
          [ "YYJSON_READ_ALLOW_BOM", "api.html#yyjson_read_allow_bom", null ],
          [ "YYJSON_READ_ALLOW_EXT_NUMBER", "api.html#yyjson_read_allow_ext_number", null ],
          [ "YYJSON_READ_ALLOW_EXT_ESCAPE", "api.html#yyjson_read_allow_ext_escape", null ],
          [ "YYJSON_READ_ALLOW_EXT_WHITESPACE", "api.html#yyjson_read_allow_ext_whitespace", null ],
          [ "YYJSON_READ_ALLOW_SINGLE_QUOTED_STR", "api.html#yyjson_read_allow_single_quoted_str", null ],
          [ "YYJSON_READ_ALLOW_UNQUOTED_KEY", "api.html#yyjson_read_allow_unquoted_key", null ],
          [ "YYJSON_READ_JSON5", "api.html#yyjson_read_json5", null ]
        ] ]
      ] ],
      [ "Writing JSON", "api.html#writing-json", [
        [ "Write JSON to string", "api.html#write-json-to-string", null ],
        [ "Write JSON to file", "api.html#write-json-to-file", null ],
        [ "Write JSON to file pointer", "api.html#write-json-to-file-pointer", null ],
        [ "Write JSON with options", "api.html#write-json-with-options", null ],
        [ "Writer flag", "api.html#writer-flag", [
          [ "YYJSON_WRITE_NOFLAG = 0", "api.html#yyjson_write_noflag--0", null ],
          [ "YYJSON_WRITE_PRETTY", "api.html#yyjson_write_pretty", null ],
          [ "YYJSON_WRITE_PRETTY_TWO_SPACES", "api.html#yyjson_write_pretty_two_spaces", null ],
          [ "YYJSON_WRITE_ESCAPE_UNICODE", "api.html#yyjson_write_escape_unicode", null ],
          [ "YYJSON_WRITE_ESCAPE_SLASHES", "api.html#yyjson_write_escape_slashes", null ],
          [ "YYJSON_WRITE_ALLOW_INF_AND_NAN", "api.html#yyjson_write_allow_inf_and_nan", null ],
          [ "YYJSON_WRITE_INF_AND_NAN_AS_NULL", "api.html#yyjson_write_inf_and_nan_as_null", null ],
          [ "YYJSON_WRITE_ALLOW_INVALID_UNICODE", "api.html#yyjson_write_allow_invalid_unicode", null ],
          [ "YYJSON_WRITE_NEWLINE_AT_END", "api.html#yyjson_write_newline_at_end", null ],
          [ "YYJSON_WRITE_FP_TO_FLOAT", "api.html#yyjson_write_fp_to_float", null ],
          [ "YYJSON_WRITE_FP_TO_FIXED(prec)", "api.html#yyjson_write_fp_to_fixedprec", null ]
        ] ]
      ] ],
      [ "Accessing JSON Document", "api.html#accessing-json-document", [
        [ "JSON Document", "api.html#json-document", null ],
        [ "JSON Value", "api.html#json-value", null ],
        [ "JSON Array", "api.html#json-array", null ],
        [ "JSON Array Iterator", "api.html#json-array-iterator", null ],
        [ "JSON Object", "api.html#json-object", null ],
        [ "JSON Object Iterator", "api.html#json-object-iterator", null ]
      ] ],
      [ "Creating JSON Document", "api.html#creating-json-document", [
        [ "Mutable Document", "api.html#mutable-document", null ],
        [ "JSON Value Creation", "api.html#json-value-creation", null ],
        [ "JSON Array Creation", "api.html#json-array-creation", null ],
        [ "JSON Array Modification", "api.html#json-array-modification", null ],
        [ "JSON Object Creation", "api.html#json-object-creation", null ],
        [ "JSON Object Modification", "api.html#json-object-modification", null ]
      ] ],
      [ "JSON Pointer and Patch", "api.html#json-pointer-and-patch", [
        [ "JSON Pointer", "api.html#json-pointer", null ],
        [ "JSON Patch", "api.html#json-patch", null ],
        [ "JSON Merge Patch", "api.html#json-merge-patch", null ]
      ] ],
      [ "Number Processing", "api.html#number-processing", [
        [ "Number reader", "api.html#number-reader", null ],
        [ "Number writer", "api.html#number-writer", null ],
        [ "Number conversion function", "api.html#number-conversion-function", null ]
      ] ],
      [ "Text Processing", "api.html#text-processing", [
        [ "Character Encoding", "api.html#character-encoding", null ],
        [ "NUL Character", "api.html#nul-character", null ]
      ] ],
      [ "Memory Allocator", "api.html#memory-allocator", [
        [ "Single allocator for multiple JSON", "api.html#single-allocator-for-multiple-json", null ],
        [ "Stack memory allocator", "api.html#stack-memory-allocator", null ],
        [ "Use a third-party allocator library", "api.html#use-a-third-party-allocator-library", null ]
      ] ],
      [ "Stack Memory Usage", "api.html#stack-memory-usage", null ],
      [ "Null Check", "api.html#null-check", null ],
      [ "Thread Safety", "api.html#thread-safety", null ],
      [ "Locale Independence", "api.html#locale-independence", null ]
    ] ],
    [ "Data Structures", "data-structures.html", [
      [ "Immutable Value", "data-structures.html#immutable-value", null ],
      [ "Immutable Document", "data-structures.html#immutable-document", null ],
      [ "Mutable Value", "data-structures.html#mutable-value", null ],
      [ "Mutable Document", "data-structures.html#mutable-document-1", null ],
      [ "Memory Management", "data-structures.html#memory-management", null ]
    ] ],
    [ "Changelog", "md__c_h_a_n_g_e_l_o_g.html", [
      [ "0.12.0 (2025-08-18)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md0129-2025-08-18", null ],
      [ "0.11.1 (2025-05-14)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md0111-2025-05-14", null ],
      [ "0.11.0 (2025-05-05)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md0110-2025-05-05", null ],
      [ "0.10.0 (2024-07-09)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md0100-2024-07-09", null ],
      [ "0.9.0 (2024-04-08)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md090-2024-04-08", null ],
      [ "0.8.0 (2023-09-13)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md080-2023-09-13", null ],
      [ "0.7.0 (2023-05-25)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md070-2023-05-25", null ],
      [ "0.6.0 (2022-12-12)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md060-2022-12-12", null ],
      [ "0.5.1 (2022-06-17)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md051-2022-06-17", null ],
      [ "0.5.0 (2022-05-25)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md050-2022-05-25", null ],
      [ "0.4.0 (2021-12-12)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md040-2021-12-12", null ],
      [ "0.3.0 (2021-05-25)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md030-2021-05-25", null ],
      [ "0.2.0 (2020-12-12)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md020-2020-12-12", null ],
      [ "0.1.0 (2020-10-26)", "md__c_h_a_n_g_e_l_o_g.html#autotoc_md010-2020-10-26", null ]
    ] ],
    [ "Deprecated List", "deprecated.html", null ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", "globals_func" ],
        [ "Variables", "globals_vars.html", null ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Macros", "globals_defs.html", null ]
      ] ],
      [ "Data Structures", "annotated.html", [
        [ "Data Structures", "annotated.html", "annotated_dup" ],
        [ "Data Structure Index", "classes.html", null ],
        [ "Data Fields", "functions.html", [
          [ "All", "functions.html", null ],
          [ "Variables", "functions_vars.html", null ]
        ] ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"annotated.html",
"yyjson_8h.html#a2a9e116a307c8dbcebc82305eca91fd3",
"yyjson_8h.html#aa4b243e9de837405d83bcc3251156cea"
];

var SYNCONMSG = 'click to disable panel synchronization';
var SYNCOFFMSG = 'click to enable panel synchronization';