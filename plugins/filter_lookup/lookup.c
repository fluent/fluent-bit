/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_metrics.h>
#include <cfl/cfl_time.h>
#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>

#include "lookup.h"

/* Macro to increment records metrics */
#ifdef FLB_HAVE_METRICS
#define INCREMENT_SKIPPED_METRIC(ctx, ins) do { \
    if (ctx->cmt_skipped) { \
        uint64_t ts = cfl_time_now(); \
        char* labels_array[1] = {(char*)flb_filter_name(ins)}; \
        cmt_counter_add(ctx->cmt_skipped, ts, 1, 1, labels_array); \
    } \
    flb_metrics_sum(FLB_LOOKUP_METRIC_SKIPPED, 1, ins->metrics); \
} while(0)

#define INCREMENT_MATCHED_METRIC(ctx, ins) do { \
    if (ctx->cmt_matched) { \
        uint64_t ts = cfl_time_now(); \
        char* labels_array[1] = {(char*)flb_filter_name(ins)}; \
        cmt_counter_add(ctx->cmt_matched, ts, 1, 1, labels_array); \
    } \
    flb_metrics_sum(FLB_LOOKUP_METRIC_MATCHED, 1, ins->metrics); \
} while(0)

#define INCREMENT_PROCESSED_METRIC(ctx, ins) do { \
    if (ctx->cmt_processed) { \
        uint64_t ts = cfl_time_now(); \
        char* labels_array[1] = {(char*)flb_filter_name(ins)}; \
        cmt_counter_add(ctx->cmt_processed, ts, 1, 1, labels_array); \
    } \
    flb_metrics_sum(FLB_LOOKUP_METRIC_PROCESSED, 1, ins->metrics); \
} while(0)
#else
#define INCREMENT_SKIPPED_METRIC(ctx, ins) do { } while(0)
#define INCREMENT_MATCHED_METRIC(ctx, ins) do { } while(0)
#define INCREMENT_PROCESSED_METRIC(ctx, ins) do { } while(0)
#endif


struct val_node {
    struct mk_list _head;
    void *val;
};

/*
 * Trims leading/trailing whitespace and optionally normalizes to lower-case.
 */
static int normalize_and_trim(const char *input, size_t len, int ignore_case, char **output, size_t *out_len)
{
    const char *start;
    const char *end;
    size_t n;
    char *buf;
    size_t j;
    
    if (!input || len == 0) {
        *output = NULL;
        *out_len = 0;
        return 0;
    }
    /* Trim leading whitespace */
    start = input;
    n = len;
    while (n > 0 && isspace((unsigned char)*start)) {
        start++;
        n--;
    }
    /* Trim trailing whitespace */
    end = start + n;
    while (n > 0 && isspace((unsigned char)*(end - 1))) {
        end--;
        n--;
    }
    if (n == 0) {
        *output = NULL;
        *out_len = 0;
        return 0;
    }
    if (ignore_case) {
        buf = flb_malloc(n + 1);
        if (!buf) {
            *output = NULL;
            *out_len = 0;
            return -1;
        }
        for (j = 0; j < n; j++) {
            buf[j] = tolower((unsigned char)start[j]);
        }
        buf[n] = '\0';
        *output = buf;
        *out_len = n;
        return 1;
    } else {
        *output = (char *)start;
        *out_len = n;
        return 0;
    }
}

/* Dynamic buffer structure for growing strings */
struct dynamic_buffer {
    char *data;
    size_t len;
    size_t capacity;
};

/* Initialize a dynamic buffer */
static int dynbuf_init(struct dynamic_buffer *buf, size_t initial_capacity)
{
    buf->data = flb_malloc(initial_capacity);
    if (!buf->data) {
        return -1;
    }
    buf->len = 0;
    buf->capacity = initial_capacity;
    buf->data[0] = '\0';
    return 0;
}

/* Append a character to dynamic buffer, growing if necessary */
static int dynbuf_append_char(struct dynamic_buffer *buf, char c)
{
    size_t new_capacity;
    char *new_data;
    
    /* Ensure we have space for the character plus null terminator */
    if (buf->len + 1 >= buf->capacity) {
        new_capacity = buf->capacity * 2;
        new_data = flb_realloc(buf->data, new_capacity);
        if (!new_data) {
            return -1;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    buf->data[buf->len++] = c;
    buf->data[buf->len] = '\0';
    return 0;
}

/* Free dynamic buffer */
static void dynbuf_destroy(struct dynamic_buffer *buf)
{
    if (buf && buf->data) {
        flb_free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = 0;
    }
}

/* Read a line of arbitrary length from file using dynamic allocation */
static char *read_line_dynamic(FILE *fp, size_t *line_length)
{
    size_t capacity;
    size_t len;
    char *line;
    int c;
    size_t new_capacity;
    char *new_line;
    
    /* Initialize variables after declaration */
    capacity = 256;  /* Initial capacity */
    len = 0;
    
    line = flb_malloc(capacity);
    if (!line) {
        return NULL;
    }
    
    while ((c = fgetc(fp)) != EOF) {
        /* Check if we need to grow the buffer */
        if (len + 1 >= capacity) {
            new_capacity = capacity * 2;
            new_line = flb_realloc(line, new_capacity);
            if (!new_line) {
                flb_free(line);
                return NULL;
            }
            line = new_line;
            capacity = new_capacity;
        }
        
        /* Add character to buffer */
        line[len++] = c;
        
        /* Check for end of line */
        if (c == '\n') {
            break;
        }
    }
    
    /* If we read nothing and hit EOF, return NULL */
    if (len == 0 && c == EOF) {
        flb_free(line);
        return NULL;
    }
    
    /* Null terminate the string */
    if (len >= capacity) {
        new_line = flb_realloc(line, len + 1);
        if (!new_line) {
            flb_free(line);
            return NULL;
        }
        line = new_line;
    }
    line[len] = '\0';
    
    /* Remove trailing \r\n characters */
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    
    if (line_length) {
        *line_length = len;
    }
    
    return line;
}

static int load_csv(struct lookup_ctx *ctx)
{
    FILE *fp;
    int line_num = 1;
    int loaded_entries = 0;  /* Track loaded entries count */
    char *header_line;
    char *line;
    size_t line_length;
    
    fp = fopen(ctx->data_source, "r");
    if (!fp) {
        flb_plg_error(ctx->ins, "cannot open data source '%s': %s", ctx->data_source, strerror(errno));
        return -1;
    }
    /* Initialize value list if not already */
    mk_list_init(&ctx->val_list);
    
    /* Conditionally skip header row based on configuration */
    if (ctx->skip_header_row) {
        header_line = read_line_dynamic(fp, NULL);
        if (!header_line) {
            flb_plg_error(ctx->ins, "empty data source: %s", ctx->data_source);
            fclose(fp);
            return -1;
        }
        flb_free(header_line);  /* Free the header line as we don't need it */
    }
    
    while ((line = read_line_dynamic(fp, &line_length)) != NULL) {
        char *p;
        struct dynamic_buffer key_buf, val_buf;
        int in_quotes;
        int field; /* 0=key, 1=val */
        char *key_ptr;
        size_t key_len;
        int key_ptr_allocated;
        char *val_ptr;
        size_t val_len;
        int val_ptr_allocated;
        char *val_heap;
        int ret;
        struct val_node *node;
        
        if (line_length == 0) {
            flb_free(line);
            line_num++;
            continue;
        }

        /* Handle quotes in CSV files using dynamic buffers */
        p = line;
        in_quotes = 0;
        field = 0;

        /* Initialize dynamic buffers */
        if (dynbuf_init(&key_buf, 256) != 0) {
            flb_plg_debug(ctx->ins, "Failed to initialize key buffer for line %d", line_num);
            flb_free(line);
            line_num++;
            continue;
        }
        if (dynbuf_init(&val_buf, 256) != 0) {
            flb_plg_debug(ctx->ins, "Failed to initialize value buffer for line %d", line_num);
            dynbuf_destroy(&key_buf);
            flb_free(line);
            line_num++;
            continue;
        }

        /* Parse key from first column (and handle quotes) */
        while (*p && (field == 0)) {
            if (!in_quotes && *p == '"') {
                in_quotes = 1;
                p++;
                continue;
            }
            if (in_quotes) {
                if (*p == '"') {
                    if (*(p+1) == '"') {
                        /* Escaped quote */
                        if (dynbuf_append_char(&key_buf, '"') != 0) {
                            flb_plg_debug(ctx->ins, "Buffer allocation failed for line %d", line_num);
                            dynbuf_destroy(&key_buf);
                            dynbuf_destroy(&val_buf);
                            flb_free(line);
                            line_num++;
                            goto next_line;
                        }
                        p += 2;
                        continue;
                    } else {
                        in_quotes = 0;
                        p++;
                        continue;
                    }
                }
                if (dynbuf_append_char(&key_buf, *p) != 0) {
                    flb_plg_debug(ctx->ins, "Buffer allocation failed for line %d", line_num);
                    dynbuf_destroy(&key_buf);
                    dynbuf_destroy(&val_buf);
                    flb_free(line);
                    line_num++;
                    goto next_line;
                }
                p++;
                continue;
            }
            if (*p == ',') {
                field = 1;
                p++;
                break;
            }
            if (dynbuf_append_char(&key_buf, *p) != 0) {
                flb_plg_debug(ctx->ins, "Buffer allocation failed for line %d", line_num);
                dynbuf_destroy(&key_buf);
                dynbuf_destroy(&val_buf);
                flb_free(line);
                line_num++;
                goto next_line;
            }
            p++;
        }

        /* Check for unmatched quote after key parsing */
        if (in_quotes) {
            flb_plg_error(ctx->ins, "Unmatched opening quote in key at line %d, skipping malformed line", line_num);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            goto next_line;
        }

        /* Parse value from second column (handle quotes) */
        in_quotes = 0;
        while (*p && (field == 1)) {
            if (!in_quotes && *p == '"') {
                in_quotes = 1;
                p++;
                continue;
            }
            if (in_quotes) {
                if (*p == '"') {
                    if (*(p+1) == '"') {
                        /* Escaped quote */
                        if (dynbuf_append_char(&val_buf, '"') != 0) {
                            flb_plg_error(ctx->ins, "Failed to append to value buffer for line %d", line_num);
                            dynbuf_destroy(&key_buf);
                            dynbuf_destroy(&val_buf);
                            flb_free(line);
                            line_num++;
                            goto next_line;
                        }
                        p += 2;
                        continue;
                    } else {
                        in_quotes = 0;
                        p++;
                        continue;
                    }
                }
                if (dynbuf_append_char(&val_buf, *p) != 0) {
                    flb_plg_error(ctx->ins, "Failed to append to value buffer for line %d", line_num);
                    dynbuf_destroy(&key_buf);
                    dynbuf_destroy(&val_buf);
                    flb_free(line);
                    line_num++;
                    goto next_line;
                }
                p++;
                continue;
            }
            if (*p == ',') {
                /* Ignore extra fields */
                break;
            }
            if (dynbuf_append_char(&val_buf, *p) != 0) {
                flb_plg_error(ctx->ins, "Failed to append to value buffer for line %d", line_num);
                dynbuf_destroy(&key_buf);
                dynbuf_destroy(&val_buf);
                flb_free(line);
                line_num++;
                goto next_line;
            }
            p++;
        }

        /* Check for unmatched quote: if in_quotes is set, log warning and skip line */
        if (in_quotes) {
            flb_plg_warn(ctx->ins, "Unmatched quote in line %d, skipping", line_num);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }

        /* Normalize and trim key */
        key_ptr = NULL;
        key_len = 0;
        key_ptr_allocated = normalize_and_trim(key_buf.data, key_buf.len, ctx->ignore_case, &key_ptr, &key_len);
        if (key_ptr_allocated < 0) {
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }
        /* Normalize and trim value */
        val_ptr = NULL;
        val_len = 0;
        val_ptr_allocated = normalize_and_trim(val_buf.data, val_buf.len, 0, &val_ptr, &val_len);
        if (val_ptr_allocated < 0) {
            if (key_ptr_allocated) flb_free(key_ptr);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }
        if (key_len == 0 || val_len == 0) {
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }
        /* Explicitly duplicate value buffer for hash table safety, allocate +1 for null terminator */
        val_heap = flb_malloc(val_len + 1);
        if (!val_heap) {
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }
        memcpy(val_heap, val_ptr, val_len);
        val_heap[val_len] = '\0';
        
        /* Allocate and initialize val_node first to track allocated value for cleanup */
        node = flb_malloc(sizeof(struct val_node));
        if (!node) {
            flb_free(val_heap);
            flb_plg_warn(ctx->ins, "Failed to allocate val_node for value cleanup, skipping");
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }
        node->val = val_heap;
        mk_list_add(&node->_head, &ctx->val_list);
        
        /* Now add to hash table - if this fails, val_heap is still tracked in val_list */
        ret = flb_hash_table_add(ctx->ht, key_ptr, key_len, val_heap, val_len);
        if (ret < 0) {
            /* Remove from val_list and free the node since hash table add failed */
            mk_list_del(&node->_head);
            flb_free(val_heap);
            flb_free(node);
            flb_plg_warn(ctx->ins, "Failed to add key '%.*s' (duplicate or error), skipping", (int)key_len, key_ptr);
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            dynbuf_destroy(&key_buf);
            dynbuf_destroy(&val_buf);
            flb_free(line);
            line_num++;
            continue;
        }
        /* Successfully loaded entry */
        loaded_entries++;
        /* Do not free val_heap; hash table owns it now */
        if (key_ptr_allocated) flb_free(key_ptr);
        if (val_ptr_allocated) flb_free(val_ptr);
        dynbuf_destroy(&key_buf);
        dynbuf_destroy(&val_buf);
        flb_free(line);
        line_num++;
        continue;

        next_line:
        /* Label for error handling - cleanup already done in error paths */
        continue;
    }
    fclose(fp);
    return loaded_entries;  /* Return count of successfully loaded entries */
}

static int cb_lookup_init(struct flb_filter_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    int ret;
    /*
     * Allocate and initialize the filter context for this plugin instance.
     * This context will hold configuration, hash table, and state.
     */
    struct lookup_ctx *ctx;
    ctx = flb_calloc(1, sizeof(struct lookup_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

#ifdef FLB_HAVE_METRICS
    /* Initialize CMT metrics */
    {
        static char* labels_name[] = {"name"};
        ctx->cmt_processed = cmt_counter_create(ins->cmt,
                                                "fluentbit", "filter", "lookup_processed_records_total",
                                                "Total number of processed records",
                                                1, labels_name);
        if (!ctx->cmt_processed) {
            flb_plg_warn(ins, "failed to create processed_records_total counter");
        }

        ctx->cmt_matched = cmt_counter_create(ins->cmt,
                                              "fluentbit", "filter", "lookup_matched_records_total",
                                              "Total number of matched records",
                                              1, labels_name);
        if (!ctx->cmt_matched) {
            flb_plg_warn(ins, "failed to create matched_records_total counter");
        }

        ctx->cmt_skipped = cmt_counter_create(ins->cmt,
                                              "fluentbit", "filter", "lookup_skipped_records_total",
                                              "Total number of skipped records due to errors",
                                              1, labels_name);
        if (!ctx->cmt_skipped) {
            flb_plg_warn(ins, "failed to create skipped_records_total counter");
        }
    }

    /* Add to old metrics system */
    flb_metrics_add(FLB_LOOKUP_METRIC_PROCESSED, "processed_records_total", ins->metrics);
    flb_metrics_add(FLB_LOOKUP_METRIC_MATCHED, "matched_records_total", ins->metrics);
    flb_metrics_add(FLB_LOOKUP_METRIC_SKIPPED, "skipped_records_total", ins->metrics);
#endif

    /*
     * Populate context fields from config_map. This sets file, lookup_key,
     * result_key, and ignore_case from the configuration.
     */
    ret = flb_filter_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /*
     * Validate required configuration options. All three must be set for
     * the filter to operate.
     */
    if (!ctx->data_source || !ctx->lookup_key || !ctx->result_key) {
        flb_plg_error(ins, "missing required config: data_source, lookup_key, result_key");
        goto error;
    }

    /* Precompute result_key length for hot path optimization */
    ctx->result_key_len = strlen(ctx->result_key);

    /* Check file existence and readability */
#ifdef _WIN32
    if (_access(ctx->data_source, 04) != 0) {  /* 04 = R_OK on Windows */
#else
    if (access(ctx->data_source, R_OK) != 0) {
#endif
        flb_plg_error(ins, "data source '%s' does not exist or is not readable: %s", ctx->data_source, strerror(errno));
        goto error;
    }

    /*
     * Create hash table for lookups. This will store key-value pairs loaded
     * from the CSV file for fast lookup during filtering.
     */
    ctx->ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1024, -1);
    if (!ctx->ht) {
        flb_plg_error(ins, "could not create hash table");
        goto error;
    }

    /* Initialize record accessor for lookup_key */
    ctx->ra_lookup_key = flb_ra_create(ctx->lookup_key, FLB_TRUE);
    if (!ctx->ra_lookup_key) {
        flb_plg_error(ins, "invalid lookup_key pattern: %s", ctx->lookup_key);
        goto error;
    }

    /* Load CSV data into hash table. */
    ret = load_csv(ctx);
    if (ret < 0) {
        goto error;
    }
    flb_plg_info(ins, "Loaded %d entries from data source '%s'", ret, ctx->data_source);
    flb_plg_info(ins, "Lookup filter initialized: lookup_key='%s', result_key='%s', ignore_case=%s", 
                 ctx->lookup_key, ctx->result_key, ctx->ignore_case ? "true" : "false");

    /* Store context for use in filter and exit callbacks. */
    flb_filter_set_context(ins, ctx);
    return 0;

error:
    if (ctx->ra_lookup_key) {
        flb_ra_destroy(ctx->ra_lookup_key);
    }
    if (ctx->ht) {
        flb_hash_table_destroy(ctx->ht);
    }
    flb_free(ctx);
    return -1;
}

static int emit_original_record(
    struct flb_log_event_encoder *log_encoder,
    struct flb_log_event *log_event,
    struct flb_filter_instance *ins,
    struct lookup_ctx *ctx,
    int rec_num)
{
    int ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(log_encoder, &log_event->timestamp);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS && log_event->metadata) {
        ret = flb_log_event_encoder_set_metadata_from_msgpack_object(log_encoder, log_event->metadata);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_body_from_msgpack_object(log_encoder, log_event->body);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(log_encoder);
    } else {
        flb_log_event_encoder_rollback_record(log_encoder);
        flb_plg_warn(ins, "Record %d: failed to encode original record, skipping", rec_num);
        if (ctx) {
            INCREMENT_SKIPPED_METRIC(ctx, ins);
        }
    }
    return ret;
}

static int cb_lookup_filter(const void *data, size_t bytes,
                           const char *tag, int tag_len,
                           void **out_buf, size_t *out_bytes,
                           struct flb_filter_instance *ins,
                           struct flb_input_instance *in_ins,
                           void *context,
                           struct flb_config *config)
{
    /*
     * Main filter callback: processes each log event in the input batch.
     * For each record, attempts to look up a value in the hash table using
     * the configured key. If found, adds result_key to the record; otherwise,
     * emits the original record unchanged.
     */
    struct lookup_ctx *ctx = context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event log_event;
    int ret;
    int rec_num = 0;
    void *found_val = NULL;
    size_t found_len = 0;
    char *lookup_val_str = NULL;
    size_t lookup_val_len = 0;
    int lookup_val_allocated = 0;
    int any_modified = 0;  /* Track if any records were modified */

    /* Ensure context is valid */
    if (!ctx) {
        flb_plg_error(ins, "lookup filter context is NULL");
        return FLB_FILTER_NOTOUCH;
    }

    /* Initialize log event decoder for input records */
    ret = flb_log_event_decoder_init(&log_decoder, (char *)data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ins, "Log event decoder initialization error : %d", ret);
        return FLB_FILTER_NOTOUCH;
    }

    /* Initialize log event encoder for output records */
    ret = flb_log_event_encoder_init(&log_encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "Log event encoder initialization error : %d", ret);
        flb_log_event_decoder_destroy(&log_decoder);
        return FLB_FILTER_NOTOUCH;
    }

    /* Process each log event in the input batch */
    while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        char *dynamic_val_buf; /* Track dynamic buffer for numeric conversions */
        int required_size;
        int printed;
        int ht_get_ret;
        struct flb_ra_value *rval;
        
        rec_num++;
        INCREMENT_PROCESSED_METRIC(ctx, ins);
        lookup_val_str = NULL;
        lookup_val_len = 0;
        lookup_val_allocated = 0;
        dynamic_val_buf = NULL;

        /* Helper macro to clean up dynamic buffer and allocated lookup strings */
        #define CLEANUP_DYNAMIC_BUFFERS() do { \
            if (dynamic_val_buf) { \
                flb_free(dynamic_val_buf); \
                dynamic_val_buf = NULL; \
            } \
            if (lookup_val_allocated && lookup_val_str) { \
                flb_free(lookup_val_str); \
                lookup_val_str = NULL; \
            } \
        } while(0)

        /* If body is not a map, emit original record and log debug */
        if (!log_event.body || log_event.body->type != MSGPACK_OBJECT_MAP) {
            flb_plg_debug(ins, "Record %d: body is not a map (type=%d), emitting original", rec_num, log_event.body ? log_event.body->type : -1);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        /* Use record accessor to get the lookup value */
        rval = flb_ra_get_value_object(ctx->ra_lookup_key, *log_event.body);
        if (!rval) {
            /* Key not found, emit original record */
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        /* Extract string value from record accessor result */
        if (rval->type == FLB_RA_STRING) {
            lookup_val_allocated = normalize_and_trim((char *)rval->o.via.str.ptr, rval->o.via.str.size, ctx->ignore_case, &lookup_val_str, &lookup_val_len);
            if (lookup_val_allocated < 0) {
                flb_plg_warn(ins, "Record %d: malloc failed for normalize_and_trim (string), skipping", rec_num);
                INCREMENT_SKIPPED_METRIC(ctx, ins);
                lookup_val_str = NULL;
                lookup_val_len = 0;
            }
        }
        else {
            /* Non-string value: convert to string using two-pass dynamic allocation */
            required_size = 0;
            
            /* First pass: determine required buffer size */
            switch (rval->type) {
                case FLB_RA_BOOL:
                    /* Check if this boolean was converted from a MAP type */
                    if (rval->o.type == MSGPACK_OBJECT_MAP) {
                        flb_plg_debug(ins, "Record %d: MAP type from record accessor, skipping conversion", rec_num);
                        CLEANUP_DYNAMIC_BUFFERS();
                        flb_ra_key_value_destroy(rval);
                        emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                        continue;
                    }
                    required_size = snprintf(NULL, 0, "%s", rval->o.via.boolean ? "true" : "false");
                    break;
                case FLB_RA_INT:
                    required_size = snprintf(NULL, 0, "%" PRId64, rval->o.via.i64);
                    break;
                case FLB_RA_FLOAT:
                    required_size = snprintf(NULL, 0, "%.15g", rval->o.via.f64);
                    break;
                case FLB_RA_NULL:
                    required_size = snprintf(NULL, 0, "null");
                    break;
                default:
                    /* Check for ARRAY type that might not be properly handled by RA */
                    if (rval->o.type == MSGPACK_OBJECT_ARRAY) {
                        flb_plg_debug(ins, "Record %d: ARRAY type from record accessor, skipping conversion", rec_num);
                        CLEANUP_DYNAMIC_BUFFERS();
                        flb_ra_key_value_destroy(rval);
                        emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                        continue;
                    }
                    flb_plg_debug(ins, "Record %d: unsupported type %d (msgpack type %d), skipping conversion", rec_num, rval->type, rval->o.type);
                    CLEANUP_DYNAMIC_BUFFERS();
                    flb_ra_key_value_destroy(rval);
                    emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                    continue;
            }
            
            if (required_size < 0) {
                flb_plg_debug(ins, "Record %d: snprintf sizing failed for type %d, skipping conversion", rec_num, rval->type);
                CLEANUP_DYNAMIC_BUFFERS();
                flb_ra_key_value_destroy(rval);
                emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                continue;
            }
            
            /* Allocate buffer with required size plus null terminator */
            dynamic_val_buf = flb_malloc(required_size + 1);
            if (!dynamic_val_buf) {
                flb_plg_warn(ins, "Record %d: malloc failed for dynamic value buffer (size %zu), skipping", rec_num, (size_t)(required_size + 1));
                INCREMENT_SKIPPED_METRIC(ctx, ins);
                CLEANUP_DYNAMIC_BUFFERS();
                flb_ra_key_value_destroy(rval);
                emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                continue;
            }
            
            /* Second pass: write to allocated buffer */
            printed = 0;
            switch (rval->type) {
                case FLB_RA_BOOL:
                    /* Note: MAP types are converted to boolean, but we already handled them in first pass */
                    printed = snprintf(dynamic_val_buf, required_size + 1, "%s", rval->o.via.boolean ? "true" : "false");
                    break;
                case FLB_RA_INT:
                    printed = snprintf(dynamic_val_buf, required_size + 1, "%" PRId64, rval->o.via.i64);
                    break;
                case FLB_RA_FLOAT:
                    printed = snprintf(dynamic_val_buf, required_size + 1, "%.15g", rval->o.via.f64);
                    break;
                case FLB_RA_NULL:
                    printed = snprintf(dynamic_val_buf, required_size + 1, "null");
                    break;
            }
            
            if (printed < 0 || printed != required_size) {
                flb_plg_debug(ins, "Record %d: snprintf formatting failed (expected %d, got %d), skipping conversion", rec_num, required_size, printed);
                CLEANUP_DYNAMIC_BUFFERS();
                flb_ra_key_value_destroy(rval);
                emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                continue;
            }
            
            /* Use the dynamically allocated buffer for normalization */
            lookup_val_allocated = normalize_and_trim(dynamic_val_buf, printed, ctx->ignore_case, &lookup_val_str, &lookup_val_len);
            if (lookup_val_allocated < 0) {
                flb_plg_warn(ins, "Record %d: malloc failed for normalize_and_trim (non-string), skipping", rec_num);
                INCREMENT_SKIPPED_METRIC(ctx, ins);
                CLEANUP_DYNAMIC_BUFFERS();
                flb_ra_key_value_destroy(rval);
                emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                continue;
            }
            
            flb_plg_debug(ins, "Record %d: lookup value for key '%s' is non-string, converted to '%s'", rec_num, ctx->lookup_key, lookup_val_str ? lookup_val_str : "NULL");
            
            /* 
             * If normalize_and_trim allocated a new buffer (lookup_val_allocated > 0), 
             * we can free the dynamic buffer now. Otherwise, lookup_val_str points
             * into dynamic_val_buf and we must delay freeing it.
             */
            if (lookup_val_allocated > 0) {
                flb_free(dynamic_val_buf);
                dynamic_val_buf = NULL;
            }
            /* Note: dynamic_val_buf will be freed later if still allocated */
        }

        /* If lookup value is missing or empty, emit the original record unchanged. */
        if (!lookup_val_str || lookup_val_len == 0) {
            CLEANUP_DYNAMIC_BUFFERS();
            flb_ra_key_value_destroy(rval);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        /*
         * Attempt to find the lookup value in the hash table.
         * If not found, emit the original record unchanged.
         */
        ht_get_ret = flb_hash_table_get(ctx->ht, lookup_val_str, lookup_val_len, &found_val, &found_len);
        
        if (ht_get_ret < 0 || !found_val || found_len == 0) {
            /* Not found, emit original record */
            CLEANUP_DYNAMIC_BUFFERS();
            flb_ra_key_value_destroy(rval);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        /* Match found - increment counter */
        INCREMENT_MATCHED_METRIC(ctx, ins);
        any_modified = 1;  /* Mark that we have modified records */
        
        flb_plg_trace(ins, "Record %d: Found match for '%.*s' -> '%.*s'", 
                     rec_num, (int)lookup_val_len, lookup_val_str, (int)found_len, (char*)found_val);
        
        /* Free normalization buffer if allocated (after using it in trace) */
        CLEANUP_DYNAMIC_BUFFERS();
        flb_ra_key_value_destroy(rval);

        /* Begin new record */
        ret = flb_log_event_encoder_begin_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to begin new record, emitting original", rec_num);
            INCREMENT_SKIPPED_METRIC(ctx, ins);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        ret = flb_log_event_encoder_set_timestamp(&log_encoder, &log_event.timestamp);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to set timestamp, emitting original", rec_num);
            INCREMENT_SKIPPED_METRIC(ctx, ins);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        if (log_event.metadata) {
            ret = flb_log_event_encoder_set_metadata_from_msgpack_object(&log_encoder, log_event.metadata);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_warn(ins, "Record %d: failed to set metadata, emitting original", rec_num);
                INCREMENT_SKIPPED_METRIC(ctx, ins);
                flb_log_event_encoder_rollback_record(&log_encoder);
                emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                continue;
            }
        }

        /* Copy all keys except result_key (to avoid collision) */
        if (log_event.body && log_event.body->type == MSGPACK_OBJECT_MAP) {
            int i;
            for (i = 0; i < log_event.body->via.map.size; i++) {
                msgpack_object_kv *kv = &log_event.body->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    kv->key.via.str.size == ctx->result_key_len &&
                    memcmp(kv->key.via.str.ptr, ctx->result_key, ctx->result_key_len) == 0) {
                    continue;
                }
                ret = flb_log_event_encoder_append_body_values(&log_encoder, 
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv->key), 
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv->val));
                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    flb_plg_warn(ins, "Record %d: failed to append key/value, emitting original", rec_num);
                    INCREMENT_SKIPPED_METRIC(ctx, ins);
                    flb_log_event_encoder_rollback_record(&log_encoder);
                    emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
                    continue;
                }
            }
        }

        /* Add result_key */
        ret = flb_log_event_encoder_append_body_string(&log_encoder, ctx->result_key, strlen(ctx->result_key));
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to append result_key, emitting original", rec_num);
            INCREMENT_SKIPPED_METRIC(ctx, ins);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        ret = flb_log_event_encoder_append_body_string(&log_encoder, (char *)found_val, found_len);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to append found_val, emitting original", rec_num);
            INCREMENT_SKIPPED_METRIC(ctx, ins);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }

        ret = flb_log_event_encoder_commit_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to commit record, emitting original", rec_num);
            INCREMENT_SKIPPED_METRIC(ctx, ins);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, ctx, rec_num);
            continue;
        }
    }

    #undef CLEANUP_DYNAMIC_BUFFERS

    /*
     * If any records were modified, return the new buffer.
     * Otherwise, indicate no change to avoid unnecessary buffer copy.
     */
    if (any_modified) {
        *out_buf = log_encoder.output_buffer;
        *out_bytes = log_encoder.output_length;
        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
        ret = FLB_FILTER_MODIFIED;
    } else {
        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);
    return ret;
}

static int cb_lookup_exit(void *data, struct flb_config *config)
{
    struct lookup_ctx *ctx = data;
    if (!ctx) return 0;
    
    /* Free all allocated values tracked in val_list */
    struct mk_list *tmp;
    struct mk_list *head;
    struct val_node *node;
    mk_list_foreach_safe(head, tmp, &ctx->val_list) {
        node = mk_list_entry(head, struct val_node, _head);
        flb_free(node->val);
        mk_list_del(head);
        flb_free(node);
    }
    if (ctx->ra_lookup_key) flb_ra_destroy(ctx->ra_lookup_key);
    if (ctx->ht) flb_hash_table_destroy(ctx->ht);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    { FLB_CONFIG_MAP_STR, "data_source", NULL, 0, FLB_TRUE, offsetof(struct lookup_ctx, data_source), "Data source for lookup values (file path to CSV)." },
    { FLB_CONFIG_MAP_STR, "lookup_key", NULL, 0, FLB_TRUE, offsetof(struct lookup_ctx, lookup_key), "Name of the key to lookup in input record." },
    { FLB_CONFIG_MAP_STR, "result_key", NULL, 0, FLB_TRUE, offsetof(struct lookup_ctx, result_key), "Name of the key to add to output record if found." },
    { FLB_CONFIG_MAP_BOOL, "ignore_case", "false", 0, FLB_TRUE, offsetof(struct lookup_ctx, ignore_case), "Ignore case when matching lookup values (default: false)." },
    { FLB_CONFIG_MAP_BOOL, "skip_header_row", "false", 0, FLB_TRUE, offsetof(struct lookup_ctx, skip_header_row), "Skip first row of CSV file as header (default: false)." },
    {0}
};

struct flb_filter_plugin filter_lookup_plugin = {
    .name         = "lookup",
    .description  = "Lookup values from CSV file and add to records",
    .cb_init      = cb_lookup_init,
    .cb_filter    = cb_lookup_filter,
    .cb_exit      = cb_lookup_exit,
    .config_map   = config_map,
    .flags        = 0
};
