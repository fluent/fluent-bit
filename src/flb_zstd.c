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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <zstd/lib/zstd.h>

int flb_zstd_compress(void *in_data, size_t in_len,
                      void **out_data, size_t *out_len)
{
    // NB(rob): out_data and out_len are never initialized
    // so we need to estimate compressed size and then alloc
    // the output buffer. 
    size_t max_compress_size = (size_t)ZSTD_compressBound(in_len);
    if (ZSTD_isError(max_compress_size) != 0) {
        size_t err = max_compress_size;
        flb_error("zstd compression failed estimatation: error_no=%zu", err);
        return -1;
    }

    void *out_buf = flb_malloc(max_compress_size);

    size_t ret = ZSTD_compress(out_buf,
                               max_compress_size,
                               (void *)in_data, 
                               in_len,
                               ZSTD_CLEVEL_DEFAULT);
    if (ZSTD_isError(ret) != 0) {
        flb_free(out_buf);
        size_t err = ret;
        flb_error("zstd compression failed: error_no=%zu", err);
        return -1;
    }

    *out_data = out_buf;
    *out_len = ret;
    return 0;
}

int flb_zstd_uncompress(void *in_data, size_t in_len,
                        void **out_data, size_t *out_len)
{
    // NB(rob): out_data and out_size are never initialized
    // so we need to estimate compressed size and then alloc
    // the output buffer. 
    size_t max_decompress_size = (size_t)ZSTD_getFrameContentSize(in_data, 
                                                                  in_len);
    if (ZSTD_isError(max_decompress_size) != 0) {
        size_t err = max_decompress_size;
        flb_error("zstd decompression failed estimatation: error_no=%zu", err);
        return -1;
    }

    void *out_buf = flb_malloc(max_decompress_size);

    size_t ret = ZSTD_decompress(out_buf, 
                                 max_decompress_size,
                                 (void *)in_data, 
                                 in_len);
    if (ZSTD_isError(ret) != 0) {
        flb_free(out_buf);
        size_t err = ret;
        flb_error("zstd decompression failed: error_no=%zu", err);
        return -1;
    }

    *out_data = out_buf;
    *out_len = ret;
    return 0;
}
