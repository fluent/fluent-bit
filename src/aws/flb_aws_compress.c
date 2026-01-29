/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_base64.h>

#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>

#include <stdint.h>
#include <string.h>

/*
 * Wrapper function to use Snappy Framing Format
 * (as documented by Google's framing_format.txt specification)
 *
 * Unlike raw snappy, framed format supports streaming/concatenation.
 * This makes it safe to compress data in chunks and concatenate the results.
 */
static int flb_snappy_compress_wrapper(void *in_data, size_t in_len,
                                       void **out_data, size_t *out_len)
{
    return flb_snappy_compress_framed_data((char *)in_data, in_len,
                                            (char **)out_data, out_len);
}

struct compression_option {
    int compression_type;
    char *compression_keyword;
    int(*compress)(void *in_data, size_t in_len, void **out_data, size_t *out_len);
};

/*
 * Library of compression options and format converters
 * AWS plugins that support compression will have these options.
 * Referenced function should return -1 on error and 0 on success.
 *
 * IMPORTANT NOTES:
 * 1. True compression algorithms: none, gzip, snappy, zstd
 * 2. Format converters:
 *    - ARROW: REMOVED - Arrow support has been removed as it was not a proper file format for S3
 *    - PARQUET: Valid file format converter (deprecated: use format=parquet instead)
 * 3. Supported S3 output formats: json (FLB_S3_FORMAT_JSON), parquet (FLB_S3_FORMAT_PARQUET)
 */
static const struct compression_option compression_options[] = {
    /* FLB_AWS_COMPRESS_NONE which is 0 is reserved for array footer */

    /* True compression algorithms */
    {
        FLB_AWS_COMPRESS_GZIP,
        "gzip",
        &flb_gzip_compress
    },
    {
        FLB_AWS_COMPRESS_SNAPPY,
        "snappy",
        &flb_snappy_compress_wrapper
    },
    {
        FLB_AWS_COMPRESS_ZSTD,
        "zstd",
        &flb_zstd_compress
    },

    { 0 }
};

int flb_aws_compression_get_type(const char *compression_keyword)
{
    int ret;
    const struct compression_option *o;

    if (strcmp(compression_keyword, "none") == 0) {
        return FLB_AWS_COMPRESS_NONE;
    }

    o = compression_options;

    while (o->compression_type != 0) {
        ret = strcmp(o->compression_keyword, compression_keyword);
        if (ret == 0) {
            return o->compression_type;
        }
        ++o;
    }

    flb_error("[aws_compress] unknown compression type: %s", compression_keyword);
    return -1;
}

int flb_aws_compression_compress(int compression_type, void *in_data, size_t in_len,
                                void **out_data, size_t *out_len)
{
    const struct compression_option *o;

    o = compression_options;

    while (o->compression_type != 0) {
        if (o->compression_type == compression_type) {
            return o->compress(in_data, in_len, out_data, out_len);
        }
        ++o;
    }

    flb_error("[aws_compress] invalid compression type: %i", compression_type);
    flb_errno();
    return -1;
}

int flb_aws_compression_b64_truncate_compress(int compression_type, size_t max_out_len,
                                             void *in_data, size_t in_len,
                                             void **out_data, size_t *out_len)
{
    static const void *truncation_suffix = "[Truncated...]";
    static const size_t truncation_suffix_len = 14;
    static const double truncation_reduction_percent = 90; /* % out of 100 */
    static const int truncation_compression_max_attempts = 10;

    int ret;
    int is_truncated;
    int compression_attempts;
    size_t truncated_in_len_prev;
    size_t truncated_in_len;
    void *truncated_in_buf;
    void *compressed_buf;
    size_t compressed_len;
    size_t original_b64_compressed_len;

    unsigned char *b64_compressed_buf;
    size_t b64_compressed_len;
    size_t b64_actual_len;

    /* Iterative approach to truncation */
    truncated_in_len = in_len;
    truncated_in_buf = in_data;
    is_truncated = FLB_FALSE;
    b64_compressed_len = SIZE_MAX;
    compression_attempts = 0;
    while (max_out_len < b64_compressed_len - 1) {

        /* Limit compression truncation attempts, just to be safe */
        if (compression_attempts >= truncation_compression_max_attempts) {
            if (is_truncated) {
                flb_free(truncated_in_buf);
            }
            flb_error("[aws_compress] truncation failed, too many compression attempts");
            return -1;
        }

        ret = flb_aws_compression_compress(compression_type, truncated_in_buf,
                                          truncated_in_len, &compressed_buf,
                                          &compressed_len);
        ++compression_attempts;
        if (ret != 0) {
            if (is_truncated) {
                flb_free(truncated_in_buf);
            }
            return -1;
        }

        /* Determine encoded base64 buffer size */
        b64_compressed_len = compressed_len / 3; /* Compute number of 4 sextet groups */
        b64_compressed_len += (compressed_len % 3 != 0); /* Add padding partial group */
        b64_compressed_len *= 4; /* Compute number of sextets */
        b64_compressed_len += 1; /* Add room for null character 0x00 */

        /* Truncation needed */
        if (max_out_len < b64_compressed_len - 1) {
            flb_debug("[aws_compress] iterative truncation round");

            /* This compressed_buf is the wrong size. Free */
            flb_free(compressed_buf);

            /* Base case: input compressed empty string, output still too large */
            if (truncated_in_len == 0) {
                if (is_truncated) {
                    flb_free(truncated_in_buf);
                }
                flb_error("[aws_compress] truncation failed, compressed empty input too "
                         "large");
                return -1;
            }

            /* Calculate corrected input size */
            truncated_in_len_prev = truncated_in_len;
            truncated_in_len = (max_out_len * truncated_in_len) / b64_compressed_len;
            truncated_in_len = (truncated_in_len * truncation_reduction_percent) / 100;

            /* Ensure working down */
            if (truncated_in_len >= truncated_in_len_prev) {
                truncated_in_len = truncated_in_len_prev - 1;
            }

            /* Allocate truncation buffer */
            if (!is_truncated) {
                is_truncated = FLB_TRUE;
                original_b64_compressed_len = b64_compressed_len;
                truncated_in_buf = flb_malloc(in_len);
                if (!truncated_in_buf) {
                    flb_errno();
                    return -1;
                }
                memcpy(truncated_in_buf, in_data, in_len);
            }

            /* Slap on truncation suffix */
            if (truncated_in_len < truncation_suffix_len) {
                /* No room for the truncation suffix. Terminal error */
                flb_error("[aws_compress] truncation failed, no room for suffix");
                flb_free(truncated_in_buf);
                return -1;
            }
            memcpy((char *) truncated_in_buf + truncated_in_len - truncation_suffix_len,
                  truncation_suffix, truncation_suffix_len);
        }
    }

    /* Truncate buffer free and compression buffer allocation */
    if (is_truncated) {
        flb_free(truncated_in_buf);
        flb_warn("[aws_compress][size=%zu] Truncating input for compressed output "
                "larger than %zu bytes, output from %zu to %zu bytes",
                in_len, max_out_len, original_b64_compressed_len - 1,
                b64_compressed_len - 1);
    }
    b64_compressed_buf = flb_malloc(b64_compressed_len);
    if (!b64_compressed_buf) {
        flb_errno();
        return -1;
    }

    /* Base64 encode compressed out bytes */
    ret = flb_base64_encode(b64_compressed_buf, b64_compressed_len, &b64_actual_len,
                               compressed_buf, compressed_len);
    flb_free(compressed_buf);

    if (ret == FLB_BASE64_ERR_BUFFER_TOO_SMALL) {
        flb_error("[aws_compress] compressed log base64 buffer too small");
        flb_free(b64_compressed_buf);
        return -1; /* not handle truncation at this point */
    }
    if (ret != 0) {
        flb_free(b64_compressed_buf);
        return -1;
    }

    /* Double check b64 buf len */
    if (b64_compressed_len - 1 != b64_actual_len) {
        flb_error("[aws_compress] buffer len should be 1 greater than actual len");
        flb_free(b64_compressed_buf);
        return -1;
    }

    *out_data = b64_compressed_buf;
    *out_len = b64_compressed_len - 1; /* disregard added null character */
    return 0;
}
