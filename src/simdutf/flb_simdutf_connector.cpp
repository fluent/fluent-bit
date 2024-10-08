/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <simdutf.h>
#include <fluent-bit/simdutf/flb_simdutf_connector.h>
#include <memory.h>
#include <memory>

int flb_simdutf_connector_utf8_length_from_utf16le(const char16_t *buf, size_t len)
{
    return simdutf::utf8_length_from_utf16le(buf, len);
}

int flb_simdutf_connector_utf8_length_from_utf16be(const char16_t *buf, size_t len)
{
    return simdutf::utf8_length_from_utf16be(buf, len);
}

int flb_simdutf_connector_utf8_length_from_utf16(const char16_t *buf, size_t len)
{
    return simdutf::utf8_length_from_utf16(buf, len);
}

int flb_simdutf_connector_validate_utf8(const char *buf, size_t len)
{
    return simdutf::validate_utf8(buf, len);
}

int flb_simdutf_connector_validate_utf16le(const char16_t *buf, size_t len)
{
    return simdutf::validate_utf16le(buf, len);
}

int flb_simdutf_connector_validate_utf16be(const char16_t *buf, size_t len)
{
    return simdutf::validate_utf16be(buf, len);
}

int flb_simdutf_connector_validate_utf16(const char16_t *buf, size_t len)
{
    return simdutf::validate_utf16(buf, len);
}

int flb_simdutf_connector_convert_utf16le_to_utf8(const char16_t *buf, size_t len,
                                                  char **utf8_output, size_t *out_size)
{
    size_t clen = 0;
    size_t converted = 0;
    simdutf::result result;

    clen = simdutf::utf8_length_from_utf16le(buf, len);
    /* convert_utfXXXX_to_utf8 function needs to pass allocated memory region with C++ style */
    std::unique_ptr<char[]> output{new char[clen]};
    converted = simdutf::convert_utf16le_to_utf8(buf, len, output.get());
    result = simdutf::validate_utf8_with_errors(output.get(), clen);
    if (result.error == simdutf::error_code::SUCCESS && converted > 0) {
        std::string result_string(output.get(), clen);

        *utf8_output = strdup(result_string.c_str());
        *out_size = converted;

        return FLB_SIMDUTF_ERROR_CODE_SUCCESS;
    }
    else {
        *utf8_output = NULL;
        *out_size = 0;

        return result.error;
    }
}

int flb_simdutf_connector_convert_utf16be_to_utf8(const char16_t *buf, size_t len,
                                                  char **utf8_output, size_t *out_size)
{
    size_t clen = 0;
    size_t converted = 0;
    simdutf::result result;

    clen = simdutf::utf8_length_from_utf16be(buf, len);
    /* convert_utfXXXX_to_utf8 function needs to pass allocated memory region with C++ style */
    std::unique_ptr<char[]> output{new char[clen]};
    converted = simdutf::convert_utf16be_to_utf8(buf, len, output.get());
    result = simdutf::validate_utf8_with_errors(output.get(), clen);
    if (result.error == simdutf::error_code::SUCCESS && converted > 0) {
        std::string result_string(output.get(), clen);

        *utf8_output = strdup(result_string.c_str());
        *out_size = converted;

        return FLB_SIMDUTF_ERROR_CODE_SUCCESS;
    }
    else {
        *utf8_output = NULL;
        *out_size = 0;

        return result.error;
    }
}

int flb_simdutf_connector_convert_utf16_to_utf8(const char16_t *buf, size_t len,
                                                char **utf8_output, size_t *out_size)
{
    size_t clen = 0;
    size_t converted = 0;
    simdutf::result result;

    clen = simdutf::utf8_length_from_utf16(buf, len);
    /* convert_utfXXXX_to_utf8 function needs to pass allocated memory region with C++ style */
    std::unique_ptr<char[]> output{new char[clen]};
    converted = simdutf::convert_utf16_to_utf8(buf, len, output.get());
    result = simdutf::validate_utf8_with_errors(output.get(), clen);
    if (result.error == simdutf::error_code::SUCCESS && converted > 0) {
        std::string result_string(output.get(), clen);

        *utf8_output = strdup(result_string.c_str());
        *out_size = converted;

        return FLB_SIMDUTF_ERROR_CODE_SUCCESS;
    }
    else {
        *utf8_output = NULL;
        *out_size = 0;

        return result.error;
    }
}

void flb_simdutf_connector_change_endianness_utf16(const char16_t *input, size_t length, char16_t *output)
{
    simdutf::change_endianness_utf16(input, length, output);
}

int flb_simdutf_connector_detect_encodings(const char *input, size_t length)
{
    return simdutf::detect_encodings(input, length);
}

int flb_simdutf_connector_convert_from_unicode(int preferred_encoding,
                                               const char *input, size_t length,
                                               char **output, size_t *out_size)
{
    size_t len = 0;
    size_t i = 0;
    int encoding = 0;
    std::u16string str16;

    if (preferred_encoding == FLB_SIMDUTF_ENCODING_TYPE_UNICODE_AUTO) {
        encoding = simdutf::detect_encodings(input, length);
    }
    else if (preferred_encoding != FLB_SIMDUTF_ENCODING_TYPE_UNSPECIFIED) {
        encoding = preferred_encoding;
    }
    else {
        /* forcibly nop on this condition */
        encoding = FLB_SIMDUTF_ENCODING_TYPE_UTF8;
    }
    if ((encoding & simdutf::encoding_type::UTF8) == simdutf::encoding_type::UTF8) {
        /* Nothing to do! */
        return FLB_SIMDUTF_CONNECTOR_CONVERT_NOP;
    }
    else if ((encoding & simdutf::encoding_type::UTF16_LE) == simdutf::encoding_type::UTF16_LE) {
        len = length;
        if (len % 2) {
            len--;
        }
        for (i = 0; i < len;) {
            if (i + 2 > len) {
                break;
            }
            /* little-endian */
            int lo = input[i++] & 0xFF;
            int hi = input[i++] & 0xFF;
            str16.push_back(hi << 8 | lo);
        }

        return flb_simdutf_connector_convert_utf16le_to_utf8(str16.c_str(), str16.size(),
                                                             output, out_size);
    }
    else if ((encoding & simdutf::encoding_type::UTF16_BE) == simdutf::encoding_type::UTF16_BE) {
        len = length;
        if (len % 2) {
            len--;
        }
        for (i = 0; i < len;) {
            if (i + 2 > len) {
                break;
            }
            /* big-endian */
            int lo = input[i++] & 0xFF;
            int hi = input[i++] & 0xFF;
            str16.push_back(lo | hi << 8);
        }

        return flb_simdutf_connector_convert_utf16be_to_utf8(str16.c_str(), str16.size(),
                                                             output, out_size);
    }
    else {
        /* Note: UTF-32LE and UTF-32BE are used for internal usages
         * nowadays. So, not to be provided for these encodings is reasonable. */
        /* When detected unsupported encodings, it will be reached here. */
        return FLB_SIMDUTF_CONNECTOR_CONVERT_UNSUPPORTED;
    }

    return FLB_SIMDUTF_CONNECTOR_CONVERT_OK;
}
