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
    size_t frame_size;
    size_t input_offset;
};

#define FLB_ZSTD_DEFAULT_CHUNK      (64 * 1024)       /* 64 KB buffer */
#define FLB_ZSTD_DECOMPRESS_MAX     (100 * 1024 * 1024)  /* 100 MB limit */
#define FLB_ZSTD_WINDOW_LOG_MAX     27                 /* 128 MiB decoder window */

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
            if (out_size >= FLB_ZSTD_DECOMPRESS_MAX) {
                flb_error("[zstd] maximum decompression size reached (~100 MB)");
                flb_free(buf);
                ZSTD_freeDCtx(dctx);
                return -1;
            }
            out_size *= 2;
            if (out_size > FLB_ZSTD_DECOMPRESS_MAX) {
                out_size = FLB_ZSTD_DECOMPRESS_MAX;
            }
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

    if (size > FLB_ZSTD_DECOMPRESS_MAX) {
        flb_error("[zstd] maximum decompression size is %d bytes",
                  FLB_ZSTD_DECOMPRESS_MAX);
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

int flb_zstd_decompressor_dispatch(struct flb_decompression_context *context,
                                   void *output_buffer, size_t *output_length)
{
    struct flb_zstd_decompression_context *zstd_ctx;
    ZSTD_inBuffer input;
    ZSTD_outBuffer output;
    unsigned long long declared_size;
    size_t remaining;
    size_t ret;

    if (context == NULL || context->inner_context == NULL || output_length == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    zstd_ctx = context->inner_context;
    output.dst = output_buffer;
    output.size = *output_length;
    output.pos = 0;
    *output_length = 0;
    if (context->input_buffer_length == 0) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }
    if (zstd_ctx->frame_size == 0) {
        ret = ZSTD_findFrameCompressedSize(context->read_buffer, context->input_buffer_length);
        if (ZSTD_getErrorCode(ret) == ZSTD_error_srcSize_wrong) {
            return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
        }
        if (ZSTD_isError(ret)) {
            return FLB_DECOMPRESSOR_FAILURE;
        }
        zstd_ctx->frame_size = ret;
        remaining = context->output_limit - context->output_size;
        declared_size = ZSTD_getFrameContentSize(context->read_buffer, zstd_ctx->frame_size);
        if (declared_size != ZSTD_CONTENTSIZE_UNKNOWN && declared_size > remaining) {
            return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
        }
        if (context->output_limit != SIZE_MAX) {
            /* Bound decoder workspace independently of the remaining output budget. */
            ret = ZSTD_DCtx_setParameter(zstd_ctx->dctx, ZSTD_d_windowLogMax,
                                         FLB_ZSTD_WINDOW_LOG_MAX);
            if (ZSTD_isError(ret)) {
                return FLB_DECOMPRESSOR_FAILURE;
            }
        }
    }
    input.src = context->read_buffer;
    input.size = zstd_ctx->frame_size;
    input.pos = zstd_ctx->input_offset;
    ret = ZSTD_decompressStream(zstd_ctx->dctx, &output, &input);
    if (ZSTD_isError(ret)) {
        if (ZSTD_getErrorCode(ret) == ZSTD_error_frameParameter_windowTooLarge) {
            return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
        }
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;
        return FLB_DECOMPRESSOR_FAILURE;
    }
    zstd_ctx->input_offset = input.pos;
    *output_length = output.pos;
    if (ret == 0) {
        context->read_buffer += zstd_ctx->frame_size;
        context->input_buffer_length -= zstd_ctx->frame_size;
        zstd_ctx->frame_size = 0;
        zstd_ctx->input_offset = 0;
    }
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
