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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <pthread.h>

#include "s3.h"
#include "s3_store.h"

/* Parquet batch structure */
struct parquet_batch {
    char *tag;
    int tag_len;
    struct s3_file *chunk;
    time_t create_time;
    time_t last_append_time;
    size_t accumulated_size;
    int append_count;
    int conversion_attempts;
    struct mk_list _head;
};

/* Initialize Parquet batch management */
int parquet_batch_init(struct flb_s3 *ctx)
{
    int ret;

    mk_list_init(&ctx->parquet_batches);

    ret = pthread_mutex_init(&ctx->parquet_batch_lock, NULL);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "failed to initialize parquet batch mutex");
        return -1;
    }

    flb_plg_debug(ctx->ins,
                 "parquet batch manager initialized: batch_size=%zu, timeout=%ds",
                 ctx->file_size, (int)ctx->upload_timeout);

    return 0;
}

/* Cleanup Parquet batch management */
void parquet_batch_destroy(struct flb_s3 *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct parquet_batch *batch;

    pthread_mutex_lock(&ctx->parquet_batch_lock);

    mk_list_foreach_safe(head, tmp, &ctx->parquet_batches) {
        batch = mk_list_entry(head, struct parquet_batch, _head);
        mk_list_del(&batch->_head);

        if (batch->tag) {
            flb_free(batch->tag);
        }
        flb_free(batch);
    }

    pthread_mutex_unlock(&ctx->parquet_batch_lock);
    pthread_mutex_destroy(&ctx->parquet_batch_lock);
}

/* Get or create Parquet batch */
static struct parquet_batch *parquet_batch_get_or_create(struct flb_s3 *ctx,
                                                          const char *tag,
                                                          int tag_len)
{
    struct mk_list *head;
    struct parquet_batch *batch;
    struct parquet_batch *new_batch;
    time_t now = time(NULL);

    pthread_mutex_lock(&ctx->parquet_batch_lock);

    /* Find existing batch */
    mk_list_foreach(head, &ctx->parquet_batches) {
        batch = mk_list_entry(head, struct parquet_batch, _head);

        if (batch->tag_len == tag_len &&
            strncmp(batch->tag, tag, tag_len) == 0) {
            pthread_mutex_unlock(&ctx->parquet_batch_lock);
            return batch;
        }
    }

    /* Create new batch */
    new_batch = flb_calloc(1, sizeof(struct parquet_batch));
    if (!new_batch) {
        flb_errno();
        pthread_mutex_unlock(&ctx->parquet_batch_lock);
        return NULL;
    }

    new_batch->tag = flb_malloc(tag_len + 1);
    if (!new_batch->tag) {
        flb_errno();
        flb_free(new_batch);
        pthread_mutex_unlock(&ctx->parquet_batch_lock);
        return NULL;
    }

    memcpy(new_batch->tag, tag, tag_len);
    new_batch->tag[tag_len] = '\0';
    new_batch->tag_len = tag_len;
    new_batch->create_time = now;
    new_batch->last_append_time = now;
    new_batch->accumulated_size = 0;
    new_batch->append_count = 0;
    new_batch->conversion_attempts = 0;
    new_batch->chunk = NULL;

    mk_list_add(&new_batch->_head, &ctx->parquet_batches);

    flb_plg_debug(ctx->ins, "created parquet batch for tag: %s", new_batch->tag);

    pthread_mutex_unlock(&ctx->parquet_batch_lock);
    return new_batch;
}

/* Check if batch should be converted */
static int parquet_batch_should_convert(struct flb_s3 *ctx,
                                        struct parquet_batch *batch)
{
    time_t now = time(NULL);

    if (!batch || !batch->chunk) {
        return FLB_FALSE;
    }

    /* Check size threshold */
    if (batch->accumulated_size >= ctx->file_size) {
        flb_plg_debug(ctx->ins,
                     "batch '%s' reached size threshold: %zu/%zu bytes",
                     batch->tag, batch->accumulated_size, ctx->file_size);
        return FLB_TRUE;
    }

    /* Check timeout */
    if (now > (batch->create_time + ctx->upload_timeout)) {
        flb_plg_debug(ctx->ins,
                     "batch '%s' reached timeout: %ld seconds",
                     batch->tag, now - batch->create_time);
        return FLB_TRUE;
    }

    return FLB_FALSE;
}


/* Convert and upload Parquet batch */
static int parquet_batch_convert_and_upload(struct flb_s3 *ctx,
                                            struct parquet_batch *batch,
                                            struct multipart_upload *m_upload)
{
    int ret;
    char *json_buffer = NULL;
    size_t json_size = 0;
    char *parquet_buffer = NULL;
    size_t parquet_size = 0;
    struct flb_time start_time, end_time;
    uint64_t elapsed_ms;
    double compression_ratio;

    if (!batch || !batch->chunk) {
        flb_plg_error(ctx->ins, "invalid batch for conversion");
        return -1;
    }

    batch->conversion_attempts++;

    /* Record start time */
    flb_time_get(&start_time);

    flb_plg_debug(ctx->ins,
                 "converting batch '%s': size=%zu bytes, appends=%d, age=%ld seconds",
                 batch->tag, batch->accumulated_size, batch->append_count,
                 time(NULL) - batch->create_time);

    /* 1. Read JSON data */
    ret = s3_store_file_read(ctx, batch->chunk, &json_buffer, &json_size);
    if (ret < 0) {
        flb_plg_error(ctx->ins,
                     "failed to read buffered data for batch '%s'",
                     batch->tag);
        return -1;
    }

    /* 2. Convert to Parquet */
    ret = flb_aws_compression_compress(FLB_AWS_COMPRESS_PARQUET,
                                      json_buffer, json_size,
                                      (void **)&parquet_buffer, &parquet_size);

    if (ret < 0) {
        flb_plg_error(ctx->ins,
                     "parquet conversion failed for batch '%s'",
                     batch->tag);
        flb_free(json_buffer);

        /* Return error to trigger Fluent Bit retry mechanism */
        return -1;
    }

    flb_free(json_buffer);

    /* Record end time and calculate elapsed time */
    flb_time_get(&end_time);
    {
        struct flb_time diff_time;
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }

    flb_plg_debug(ctx->ins,
                 "parquet conversion: %zu bytes -> %zu bytes, %"PRIu64"ms",
                 json_size, parquet_size, elapsed_ms);

    /* 2.5. Apply additional compression if configured (gzip/zstd) */
    if (ctx->compression == FLB_AWS_COMPRESS_GZIP ||
        ctx->compression == FLB_AWS_COMPRESS_ZSTD) {
        void *compressed_buffer = NULL;
        size_t compressed_size = 0;
        size_t pre_compress_size = parquet_size;

        ret = flb_aws_compression_compress(ctx->compression,
                                          parquet_buffer, parquet_size,
                                          &compressed_buffer, &compressed_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins,
                         "failed to apply %s compression for batch '%s'",
                         ctx->compression == FLB_AWS_COMPRESS_GZIP ? "gzip" : "zstd",
                         batch->tag);
            flb_free(parquet_buffer);
            return -1;
        }

        flb_free(parquet_buffer);
        parquet_buffer = compressed_buffer;
        parquet_size = compressed_size;

        flb_plg_debug(ctx->ins,
                     "%s compression: %zu bytes -> %zu bytes",
                     ctx->compression == FLB_AWS_COMPRESS_GZIP ? "gzip" : "zstd",
                     pre_compress_size, compressed_size);
    }

    /* 3. Upload Parquet data */
    if (ctx->use_put_object == FLB_TRUE) {
        /* Check PutObject size limit */
        if (parquet_size > MAX_FILE_SIZE_PUT_OBJECT) {
            flb_plg_error(ctx->ins,
                         "parquet size %zu exceeds 1GB limit for use_put_object mode",
                         parquet_size);
            flb_free(parquet_buffer);
            return -1;
        }

        /* Use PutObject */
        ret = s3_put_object(ctx, batch->tag, batch->create_time,
                          parquet_buffer, parquet_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins,
                         "failed to upload batch '%s'",
                         batch->tag);
            flb_free(parquet_buffer);
            return -1;
        }
    } else if (parquet_size > MAX_FILE_SIZE_PUT_OBJECT) {
        /* Use multipart upload for large files */
        size_t offset = 0;

        flb_plg_debug(ctx->ins,
                     "using multipart upload: %zu bytes",
                     parquet_size);

        /* Ensure multipart upload is created */
        if (m_upload && m_upload->upload_state == MULTIPART_UPLOAD_STATE_NOT_CREATED) {
            ret = create_multipart_upload(ctx, m_upload, NULL);
            if (ret < 0) {
                flb_plg_error(ctx->ins,
                             "failed to create multipart upload for batch '%s'",
                             batch->tag);
                flb_free(parquet_buffer);
                return -1;
            }
            m_upload->upload_state = MULTIPART_UPLOAD_STATE_CREATED;
        }

        /* Upload each part */
        while (offset < parquet_size) {
            size_t chunk_size = (parquet_size - offset > ctx->upload_chunk_size) ?
                               ctx->upload_chunk_size : (parquet_size - offset);

            ret = upload_part(ctx, m_upload,
                            parquet_buffer + offset, chunk_size, NULL);
            if (ret < 0) {
                flb_plg_error(ctx->ins,
                             "failed to upload part for batch '%s'",
                             batch->tag);
                flb_free(parquet_buffer);
                return -1;
            }

            offset += chunk_size;
            m_upload->part_number++;
            m_upload->bytes += chunk_size;
        }

        /* Mark for completion */
        m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;

    } else {
        /* Small file: Use PutObject */
        ret = s3_put_object(ctx, batch->tag, batch->create_time,
                          parquet_buffer, parquet_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins,
                         "failed to upload batch '%s'",
                         batch->tag);
            flb_free(parquet_buffer);
            return -1;
        }
    }

    flb_free(parquet_buffer);

    /* 4. Delete temporary file */
    s3_store_file_delete(ctx, batch->chunk);
    batch->chunk = NULL;

    /* 5. Remove batch from list */
    pthread_mutex_lock(&ctx->parquet_batch_lock);
    mk_list_del(&batch->_head);
    pthread_mutex_unlock(&ctx->parquet_batch_lock);

    flb_free(batch->tag);
    flb_free(batch);

    return 0;
}
