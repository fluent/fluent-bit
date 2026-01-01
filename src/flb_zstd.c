/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

struct flb_zstd_decompression_context {
    ZSTD_DCtx *dctx;
};

#define FLB_ZSTD_DEFAULT_CHUNK 64 * 1024  /* 64 KB buffer */

int flb_zstd_compress(void *in_data, size_t in_len, void **out_data, size_t *out_len)
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

static int zstd_uncompress_unknown_size(void *in_data, size_t in_len, void **out_data, size_t *out_len)
{
    int ret = 0;
    size_t out_size;
    char *tmp;
    void *buf;

    ZSTD_DCtx *dctx;
    ZSTD_inBuffer input;
    ZSTD_outBuffer output;

    /* create decompression context */
    dctx = ZSTD_createDCtx();
    if (!dctx) {
        flb_error("[zstd] cannot create decompression context");
        return -1;
    }

    /* initial output buffer */
    out_size = FLB_ZSTD_DEFAULT_CHUNK;
    buf = flb_malloc(out_size);
    if (!buf) {
        flb_errno();
        ZSTD_freeDCtx(dctx);
        return -1;
    }

    /* input */
    input.src = in_data;
    input.size = in_len;
    input.pos = 0;

    /* start the decompress loop */
    output.dst = buf;
    output.pos = 0;
    output.size = out_size;

    while (input.pos < input.size) {
        ret = ZSTD_decompressStream(dctx, &output, &input);
        if (ZSTD_isError(ret)) {
            flb_error("[zstd] decompression failed: %s", ZSTD_getErrorName(ret));
            flb_free(buf);
            ZSTD_freeDCtx(dctx);
            return -1;
        }

        /* check if we need more space */
        if (output.pos == out_size) {
            out_size *= 2;
            tmp = flb_realloc(buf, out_size);
            if (!tmp) {
                flb_errno();
                flb_free(buf);
                ZSTD_freeDCtx(dctx);
                return -1;
            }
            buf = tmp;
            output.dst = buf;
            output.size = out_size;
        }

        /* check if we have finished */
        if (ret == 0) {
            break;
        }
    }

    ZSTD_freeDCtx(dctx);

    *out_data = buf;
    *out_len = output.pos;
    return 0;
}

int flb_zstd_uncompress(void *in_data, size_t in_len, void **out_data, size_t *out_len)
{
    int ret;
    void *buf;
    unsigned long long size;

    size = ZSTD_getFrameContentSize(in_data, in_len);
    if (size == ZSTD_CONTENTSIZE_ERROR) {
        flb_error("[zstd] invalid content size");
        return -1;
    }
    else if (size == ZSTD_CONTENTSIZE_UNKNOWN) {
        ret = zstd_uncompress_unknown_size(in_data, in_len, out_data, out_len);
        return ret;
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

int flb_zstd_decompressor_dispatch(struct flb_decompression_context *context,
                                   void *output_buffer,
                                   size_t *output_length)
{
    struct flb_zstd_decompression_context *zstd_ctx;
    size_t compressed_frame_size;
    size_t decompressed_size;
    size_t original_output_length;
    size_t error_code;

    if (context == NULL || context->inner_context == NULL || output_length == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    zstd_ctx = (struct flb_zstd_decompression_context *) context->inner_context;
    original_output_length = *output_length;
    *output_length = 0;

    if (context->input_buffer_length == 0) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }

    compressed_frame_size = ZSTD_findFrameCompressedSize(context->read_buffer,
                                                         context->input_buffer_length);

    error_code = ZSTD_getErrorCode(compressed_frame_size);

    /*
     * Distinguish between recoverable and fatal errors.
     * If we get srcSize_wrong, it just means we need more data to find the
     * end of the frame. This is expected in a streaming scenario.
     */
    if (error_code == ZSTD_error_srcSize_wrong) {
        /* Not an error, just need more data. Return success with 0 bytes produced. */
        return FLB_DECOMPRESSOR_SUCCESS;
    }

    /* Check for any other, truly fatal error from finding the frame. */
    if (ZSTD_isError(compressed_frame_size)) {
        flb_error("[zstd] frame is corrupted: %s",
                  ZSTD_getErrorName(compressed_frame_size));
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;
        return FLB_DECOMPRESSOR_FAILURE;
    }

    /* We have a full frame. Decompress it in one shot using the robust API. */
    decompressed_size = ZSTD_decompressDCtx(zstd_ctx->dctx,
                                            output_buffer,
                                            original_output_length,
                                            context->read_buffer,
                                            compressed_frame_size);

    if (ZSTD_isError(decompressed_size)) {
        flb_error("[zstd] decompression failed: %s",
                  ZSTD_getErrorName(decompressed_size));
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;
        return FLB_DECOMPRESSOR_FAILURE;
    }

    /* Success. Update our pointers and report the decompressed size. */
    context->read_buffer         += compressed_frame_size;
    context->input_buffer_length -= compressed_frame_size;
    *output_length = decompressed_size;

    return FLB_DECOMPRESSOR_SUCCESS;
}

void *flb_zstd_decompression_context_create(void)
{
    struct flb_zstd_decompression_context *context;

    context = flb_calloc(1, sizeof(struct flb_zstd_decompression_context));

    if (context == NULL) {
        flb_errno();
        return NULL;
    }

    context->dctx = ZSTD_createDCtx();
    if (context->dctx == NULL) {
        flb_error("[zstd] could not create decompression context");
        flb_free(context);
        return NULL;
    }

    return (void *) context;
}

void flb_zstd_decompression_context_destroy(void *context)
{
    struct flb_zstd_decompression_context *zstd_ctx = context;

    if (zstd_ctx != NULL) {
        if (zstd_ctx->dctx != NULL) {
            ZSTD_freeDCtx(zstd_ctx->dctx);
        }
        flb_free(zstd_ctx);
    }
}
