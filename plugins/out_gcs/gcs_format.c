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
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mp.h>

#include <msgpack.h>

#include "gcs.h"

/* Format timestamp for JSON output */
static flb_sds_t format_timestamp(struct flb_gcs *ctx, struct flb_time *tm)
{
    flb_sds_t timestamp;
    char iso_time[64];
    struct tm *gmt;
    int len;

    if (ctx->json_date_format == 0) {
        /* Unix timestamp (epoch) */
        timestamp = flb_sds_create_size(32);
        if (!timestamp) {
            return NULL;
        }
        timestamp = flb_sds_printf(&timestamp, "%ld.%09ld",
                                  tm->tm.tv_sec, tm->tm.tv_nsec);
    }
    else {
        /* ISO 8601 format */
        gmt = gmtime(&tm->tm.tv_sec);
        len = strftime(iso_time, sizeof(iso_time) - 1, "%Y-%m-%dT%H:%M:%S", gmt);
        if (len > 0) {
            snprintf(iso_time + len, sizeof(iso_time) - len, ".%09ldZ", tm->tm.tv_nsec);
            timestamp = flb_sds_create(iso_time);
        }
        else {
            timestamp = flb_sds_create("1970-01-01T00:00:00.000000000Z");
        }
    }

    return timestamp;
}

/* Extract specific key from log record */
static int extract_log_key(struct flb_gcs *ctx, msgpack_object *record,
                          flb_sds_t *out_data)
{
    msgpack_object_kv *kv;
    msgpack_object *val;
    int i;

    if (!ctx->log_key || record->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    /* Search for the specified key */
    for (i = 0; i < record->via.map.size; i++) {
        kv = &record->via.map.ptr[i];
        
        if (kv->key.type == MSGPACK_OBJECT_STR &&
            strncmp(kv->key.via.str.ptr, ctx->log_key,
                   kv->key.via.str.size) == 0 &&
            strlen(ctx->log_key) == kv->key.via.str.size) {
            
            val = &kv->val;
            
            /* Convert value to string */
            if (val->type == MSGPACK_OBJECT_STR) {
                *out_data = flb_sds_create_len(val->via.str.ptr,
                                              val->via.str.size);
            }
            else if (val->type == MSGPACK_OBJECT_BIN) {
                *out_data = flb_sds_create_len(val->via.bin.ptr,
                                              val->via.bin.size);
            }
            else {
                /* Convert other types to JSON string */
                flb_sds_t json_str = flb_msgpack_to_json_str(val);
                *out_data = json_str;
            }
            
            return 0;
        }
    }

    return -1;
}

/* Format log record as JSON */
static flb_sds_t format_json_record(struct flb_gcs *ctx,
                                    struct flb_time *timestamp,
                                    msgpack_object *record)
{
    flb_sds_t json_line;
    flb_sds_t json_record;
    flb_sds_t timestamp_str;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object_kv *kv;
    int i;
    int date_key_found = 0;

    /* Check if we need to extract a specific key */
    if (ctx->log_key) {
        flb_sds_t extracted_data;
        int ret = extract_log_key(ctx, record, &extracted_data);
        if (ret == 0) {
            /* Add newline for JSON Lines format */
            extracted_data = flb_sds_cat(extracted_data, "\n", 1);
            return extracted_data;
        }
        /* If extraction failed, fall through to full record formatting */
    }

    /* Initialize msgpack buffer for modified record */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Format timestamp */
    timestamp_str = format_timestamp(ctx, timestamp);
    if (!timestamp_str) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return NULL;
    }

    /* Start building new record with timestamp */
    if (record->type == MSGPACK_OBJECT_MAP) {
        /* Count existing keys and check for date key */
        int new_size = record->via.map.size;
        
        for (i = 0; i < record->via.map.size; i++) {
            kv = &record->via.map.ptr[i];
            if (kv->key.type == MSGPACK_OBJECT_STR &&
                strncmp(kv->key.via.str.ptr, ctx->json_date_key,
                       kv->key.via.str.size) == 0 &&
                strlen(ctx->json_date_key) == kv->key.via.str.size) {
                date_key_found = 1;
                break;
            }
        }
        
        if (!date_key_found) {
            new_size++;
        }

        /* Pack modified map */
        msgpack_pack_map(&mp_pck, new_size);

        /* Add timestamp field */
        if (!date_key_found) {
            msgpack_pack_str(&mp_pck, strlen(ctx->json_date_key));
            msgpack_pack_str_body(&mp_pck, ctx->json_date_key, 
                                 strlen(ctx->json_date_key));
            msgpack_pack_str(&mp_pck, flb_sds_len(timestamp_str));
            msgpack_pack_str_body(&mp_pck, timestamp_str, 
                                 flb_sds_len(timestamp_str));
        }

        /* Copy existing fields */
        for (i = 0; i < record->via.map.size; i++) {
            kv = &record->via.map.ptr[i];
            
            /* Replace date key if it exists */
            if (date_key_found &&
                kv->key.type == MSGPACK_OBJECT_STR &&
                strncmp(kv->key.via.str.ptr, ctx->json_date_key,
                       kv->key.via.str.size) == 0 &&
                strlen(ctx->json_date_key) == kv->key.via.str.size) {
                
                msgpack_pack_object(&mp_pck, kv->key);
                msgpack_pack_str(&mp_pck, flb_sds_len(timestamp_str));
                msgpack_pack_str_body(&mp_pck, timestamp_str, 
                                     flb_sds_len(timestamp_str));
            }
            else {
                /* Copy key-value pair as-is */
                msgpack_pack_object(&mp_pck, kv->key);
                msgpack_pack_object(&mp_pck, kv->val);
            }
        }
    }
    else {
        /* Non-map record, create simple map with timestamp and data */
        msgpack_pack_map(&mp_pck, 2);
        
        /* Add timestamp */
        msgpack_pack_str(&mp_pck, strlen(ctx->json_date_key));
        msgpack_pack_str_body(&mp_pck, ctx->json_date_key, 
                             strlen(ctx->json_date_key));
        msgpack_pack_str(&mp_pck, flb_sds_len(timestamp_str));
        msgpack_pack_str_body(&mp_pck, timestamp_str, 
                             flb_sds_len(timestamp_str));
        
        /* Add original record */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "data", 4);
        msgpack_pack_object(&mp_pck, record);
    }

    flb_sds_destroy(timestamp_str);

    /* Convert to JSON */
    json_record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!json_record) {
        return NULL;
    }

    /* Create JSON Lines format (one JSON object per line) */
    json_line = flb_sds_create_size(flb_sds_len(json_record) + 2);
    if (!json_line) {
        flb_sds_destroy(json_record);
        return NULL;
    }

    json_line = flb_sds_cat(json_line, json_record, flb_sds_len(json_record));
    json_line = flb_sds_cat(json_line, "\n", 1);

    flb_sds_destroy(json_record);
    return json_line;
}

/* Format log record as plain text */
static flb_sds_t format_text_record(struct flb_gcs *ctx,
                                    struct flb_time *timestamp,
                                    msgpack_object *record)
{
    flb_sds_t text_line;
    flb_sds_t timestamp_str;
    char *record_str = NULL;
    size_t record_str_len;

    /* Check if we need to extract a specific key */
    if (ctx->log_key) {
        flb_sds_t extracted_data;
        int ret = extract_log_key(ctx, record, &extracted_data);
        if (ret == 0) {
            /* Add newline for text format */
            extracted_data = flb_sds_cat(extracted_data, "\n", 1);
            return extracted_data;
        }
    }

    /* Format timestamp */
    timestamp_str = format_timestamp(ctx, timestamp);
    if (!timestamp_str) {
        return NULL;
    }

    /* Convert record to string representation */
    if (record->type == MSGPACK_OBJECT_STR) {
        record_str = flb_strndup(record->via.str.ptr, record->via.str.size);
        record_str_len = record->via.str.size;
    }
    else if (record->type == MSGPACK_OBJECT_BIN) {
        record_str = flb_strndup(record->via.bin.ptr, record->via.bin.size);
        record_str_len = record->via.bin.size;
    }
    else {
        /* Convert to JSON for complex types */
        flb_sds_t json_str = flb_msgpack_to_json_str(record);
        if (json_str) {
            record_str = flb_strdup(json_str);
            record_str_len = flb_sds_len(json_str);
            flb_sds_destroy(json_str);
        }
    }

    if (!record_str) {
        flb_sds_destroy(timestamp_str);
        return NULL;
    }

    /* Create text line: timestamp + space + record + newline */
    text_line = flb_sds_create_size(flb_sds_len(timestamp_str) + 
                                   record_str_len + 3);
    if (!text_line) {
        flb_sds_destroy(timestamp_str);
        flb_free(record_str);
        return NULL;
    }

    text_line = flb_sds_cat(text_line, timestamp_str, flb_sds_len(timestamp_str));
    text_line = flb_sds_cat(text_line, " ", 1);
    text_line = flb_sds_cat(text_line, record_str, record_str_len);
    text_line = flb_sds_cat(text_line, "\n", 1);

    flb_sds_destroy(timestamp_str);
    flb_free(record_str);

    return text_line;
}

/* Format chunk of log events according to configured format */
int gcs_format_chunk(struct flb_gcs *ctx, const char *tag,
                     const void *data, size_t bytes,
                     flb_sds_t *formatted_data)
{
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    flb_sds_t output;
    flb_sds_t line;
    int ret;

    /* Initialize output buffer */
    output = flb_sds_create_size(bytes * 2); /* Estimate size */
    if (!output) {
        return -1;
    }

    /* Initialize log event decoder */
    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Failed to initialize log event decoder");
        flb_sds_destroy(output);
        return -1;
    }

    /* Process each log event */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        
        /* Format record according to configured format */
        switch (ctx->format) {
        case FLB_GCS_FORMAT_TEXT:
            line = format_text_record(ctx, &log_event.timestamp, 
                                     log_event.body);
            break;
        case FLB_GCS_FORMAT_JSON:
            line = format_json_record(ctx, &log_event.timestamp, 
                                     log_event.body);
            break;
        case FLB_GCS_FORMAT_PARQUET:
#ifdef FLB_HAVE_PARQUET
            /* TODO: Implement Parquet formatting */
            flb_plg_error(ctx->ins, "Parquet formatting not yet implemented");
            line = NULL;
#else
            flb_plg_error(ctx->ins, "Parquet support not compiled");
            line = NULL;
#endif
            break;
        default:
            flb_plg_error(ctx->ins, "Unknown format: %d", ctx->format);
            line = NULL;
        }

        if (!line) {
            flb_plg_warn(ctx->ins, "Failed to format log record, skipping");
            continue;
        }

        /* Append to output */
        output = flb_sds_cat(output, line, flb_sds_len(line));
        flb_sds_destroy(line);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    if (flb_sds_len(output) == 0) {
        flb_sds_destroy(output);
        return -1;
    }

    *formatted_data = output;
    return 0;
}

#ifdef FLB_HAVE_PARQUET
/* Placeholder for Parquet support functions */
int gcs_parquet_write_init(struct gcs_file *file)
{
    /* TODO: Initialize Parquet writer using Apache Arrow C++ library
     * This would require:
     * 1. Link against Apache Arrow C++ library
     * 2. Create Arrow schema based on log structure
     * 3. Initialize Parquet file writer
     * 4. Set up column writers for timestamp, tag, and log data
     */
    return -1; /* Not implemented */
}

int gcs_parquet_write_record(struct gcs_file *file, msgpack_object *obj)
{
    /* TODO: Write record to Parquet file
     * This would:
     * 1. Convert msgpack object to Arrow record
     * 2. Write to appropriate columns
     * 3. Handle schema evolution if needed
     */
    return -1; /* Not implemented */
}

int gcs_parquet_write_close(struct gcs_file *file)
{
    /* TODO: Finalize Parquet file
     * This would:
     * 1. Flush remaining data
     * 2. Write metadata
     * 3. Close file writer
     */
    return -1; /* Not implemented */
}
#endif