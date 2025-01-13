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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_zstd.h>

size_t flb_zstd_compress(void *in_data, size_t in_len, void **out_data, size_t *out_len)
{
    void *buf;
    size_t size;
    size_t bound;

    bound = ZSTD_compressBound(in_len);
    buf = flb_malloc(bound);
    if (!buf) {
        flb_errno();
        return -1;
    }

    size = ZSTD_compress(buf, bound, in_data, in_len, 1);
    if (ZSTD_isError(size)) {
        flb_error("[zstd] compression failed: %s", ZSTD_getErrorName(size));
        flb_free(buf);
        return -1;
    }

    *out_data = buf;
    *out_len = size;

    return 0;
}

size_t flb_zstd_uncompress(void *in_data, size_t in_len, void **out_data, size_t *out_len)
{
    void *buf;
    size_t size;

    size = ZSTD_getFrameContentSize(in_data, in_len);
    if (size == ZSTD_CONTENTSIZE_ERROR) {
        flb_error("[zstd] invalid content size");
        return -1;
    }

    buf = flb_malloc(size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    size = ZSTD_decompress(buf, size, in_data, in_len);
    if (ZSTD_isError(size)) {
        flb_error("[zstd] decompression failed: %s", ZSTD_getErrorName(size));
        flb_free(buf);
        return -1;
    }

    *out_data = buf;
    *out_len = size;

    return 0;
}

