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
#include <memory>
extern "C"
{
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
}

typedef int (*conversion_function)(const char16_t *buf, size_t len,
                                   char **utf8_output, size_t *out_size);

static int convert_from_unicode(conversion_function convert,
                                const char *input, size_t length,
                                char **output, size_t *out_size)
{
    size_t len;
    std::unique_ptr<char16_t, decltype(&flb_free)> temp_buffer(NULL, flb_free);
    const char16_t *aligned_input = NULL;
    int status;

    len = length;
    if (len % 2) {
        len--;
    }
    if (len < 2) {
        return FLB_SIMDUTF_CONNECTOR_CONVERT_NOP;
    }

    /* Check alignment to determine whether to copy or not */
    if ((uintptr_t) input % 2 == 0) {
        aligned_input = (const char16_t *) input;
    }
    else {
        temp_buffer.reset((char16_t *) flb_malloc(len));
        if (temp_buffer.get() == NULL) {
            flb_errno();
            return FLB_SIMDUTF_CONNECTOR_CONVERT_ERROR;
        }
        memcpy(temp_buffer.get(), input, len);
        aligned_input = temp_buffer.get();
    }

    return convert(aligned_input, len / 2, output, out_size);
}

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
    simdutf::result result = {};

    clen = simdutf::utf8_length_from_utf16le(buf, len);
    *utf8_output = (char *) flb_malloc(clen + 1);
    if (*utf8_output == NULL) {
        flb_errno();
        return FLB_SIMDUTF_CONNECTOR_CONVERT_ERROR;
    }

    result = simdutf::convert_utf16le_to_utf8_with_errors(buf, len, *utf8_output);
    if (result.error == simdutf::error_code::SUCCESS && result.count > 0) {
        (*utf8_output)[result.count] = '\0';
        *out_size = result.count;

        return FLB_SIMDUTF_ERROR_CODE_SUCCESS;
    }
    else {
        flb_free(*utf8_output);
        *utf8_output = NULL;
        *out_size = 0;

        return result.error;
    }
}

int flb_simdutf_connector_convert_utf16be_to_utf8(const char16_t *buf, size_t len,
                                                  char **utf8_output, size_t *out_size)
{
    size_t clen = 0;
    simdutf::result result = {};

    clen = simdutf::utf8_length_from_utf16be(buf, len);
    *utf8_output = (char *) flb_malloc(clen + 1);
    if (*utf8_output == NULL) {
        flb_errno();
        return FLB_SIMDUTF_CONNECTOR_CONVERT_ERROR;
    }

    result = simdutf::convert_utf16be_to_utf8_with_errors(buf, len, *utf8_output);
    if (result.error == simdutf::error_code::SUCCESS && result.count > 0) {
        (*utf8_output)[result.count] = '\0';
        *out_size = result.count;

        return FLB_SIMDUTF_ERROR_CODE_SUCCESS;
    }
    else {
        flb_free(*utf8_output);
        *utf8_output = NULL;
        *out_size = 0;

        return result.error;
    }
}

int flb_simdutf_connector_convert_utf16_to_utf8(const char16_t *buf, size_t len,
                                                char **utf8_output, size_t *out_size)
{
    size_t clen = 0;
    simdutf::result result = {};

    clen = simdutf::utf8_length_from_utf16(buf, len);
    *utf8_output = (char *) flb_malloc(clen + 1);
    if (*utf8_output == NULL) {
        flb_errno();
        return FLB_SIMDUTF_CONNECTOR_CONVERT_ERROR;
    }

    result = simdutf::convert_utf16_to_utf8_with_errors(buf, len, *utf8_output);
    if (result.error == simdutf::error_code::SUCCESS && result.count > 0) {
        (*utf8_output)[result.count] = '\0';
        *out_size = result.count;

        return FLB_SIMDUTF_ERROR_CODE_SUCCESS;
    }
    else {
        flb_free(*utf8_output);
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
    int encoding = 0;
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
        /* Skip the UTF-16 BOM */
        if (length >= 2 && input[0] == '\xFF' && input[1] == '\xFE') {
            input += 2;
            length -= 2;
        }
        return convert_from_unicode(flb_simdutf_connector_convert_utf16le_to_utf8,
                                    input, length, output, out_size);
    }
    else if ((encoding & simdutf::encoding_type::UTF16_BE) == simdutf::encoding_type::UTF16_BE) {
        /* Skip the UTF-16 BOM */
        if (length >= 2 && input[0] == '\xFE' && input[1] == '\xFF') {
            input += 2;
            length -= 2;
        }
        return convert_from_unicode(flb_simdutf_connector_convert_utf16be_to_utf8,
                                    input, length, output, out_size);
    }
    else {
        /* Note: UTF-32LE and UTF-32BE are used for internal usages
         * nowadays. So, not to be provided for these encodings is reasonable. */
        /* When detected unsupported encodings, it will be reached here. */
        return FLB_SIMDUTF_CONNECTOR_CONVERT_UNSUPPORTED;
    }

    return FLB_SIMDUTF_CONNECTOR_CONVERT_OK;
}
