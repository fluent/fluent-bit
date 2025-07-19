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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>

#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_record_accessor.h>
#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>


struct val_node {
    struct mk_list _head;
    void *val;
};

struct lookup_ctx {
    struct flb_filter_instance *ins;
    char *file;
    char *lookup_key;
    char *result_key;
    struct flb_hash_table *ht;
    struct flb_record_accessor *ra_lookup_key;
    int ignore_case;
    struct mk_list val_list;
};

/*
 * Trims leading/trailing whitespace and optionally normalizes to lower-case.
 * Allocates output buffer (caller must free if output != input).
 */
static int normalize_and_trim(const char *input, size_t len, int ignore_case, char **output, size_t *out_len)
{
    if (!input || len == 0) {
        *output = NULL;
        *out_len = 0;
        return 0;
    }
    /* Trim leading whitespace */
    const char *start = input;
    size_t n = len;
    while (n > 0 && isspace((unsigned char)*start)) {
        start++;
        n--;
    }
    /* Trim trailing whitespace */
    const char *end = start + n;
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
        char *buf = flb_malloc(n + 1);
        if (!buf) {
            *output = NULL;
            *out_len = 0;
            return -1;
        }
        for (size_t j = 0; j < n; j++) {
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

static int load_csv(struct lookup_ctx *ctx)
{
    FILE *fp;
    char line[4096];
    int line_num = 1;
    fp = fopen(ctx->file, "r");
    if (!fp) {
        flb_plg_error(ctx->ins, "cannot open CSV file: %s", ctx->file);
        return -1;
    }
    /* Initialize value list if not already */
    mk_list_init(&ctx->val_list);
    /* Skip header */
    if (!fgets(line, sizeof(line), fp)) {
        flb_plg_error(ctx->ins, "empty CSV file: %s", ctx->file);
        fclose(fp);
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) {
            line_num++;
            continue;
        }

        /* Handle quotes in CSV files */
        char *p = line;
        char key[2048];
        char val[2048];
        size_t key_len = 0, val_len = 0;
        key[0] = '\0';
        val[0] = '\0';
    int in_quotes = 0;
        int field = 0; /* 0=key, 1=val */

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
                        if (key_len < sizeof(key)-1) key[key_len++] = '"';
                        p += 2;
                        continue;
                    } else {
                        in_quotes = 0;
                        p++;
                        continue;
                    }
                }
                if (key_len < sizeof(key)-1) key[key_len++] = *p;
                p++;
                continue;
            }
            if (*p == ',') {
                field = 1;
                p++;
                break;
            }
            if (key_len < sizeof(key)-1) key[key_len++] = *p;
            p++;
        }
        key[key_len] = '\0';

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
                        // Escaped quote
                        if (val_len < sizeof(val)-1) val[val_len++] = '"';
                        p += 2;
                        continue;
                    } else {
                        in_quotes = 0;
                        p++;
                        continue;
                    }
                }
                if (val_len < sizeof(val)-1) val[val_len++] = *p;
                p++;
                continue;
            }
            if (*p == ',') {
                /* Ignore extra fields */
                break;
            }
            if (val_len < sizeof(val)-1) val[val_len++] = *p;
            p++;
        }

        val[val_len] = '\0';

        /* Check for unmatched quote: if in_quotes is set, log warning and skip line */
        if (in_quotes) {
            flb_plg_warn(ctx->ins, "Unmatched quote in line %d, skipping", line_num);
            line_num++;
            continue;
        }

        /* Normalize and trim key */
        char *key_ptr = NULL;
        int key_ptr_allocated = normalize_and_trim(key, strlen(key), ctx->ignore_case, &key_ptr, &key_len);
        if (key_ptr_allocated < 0) {
            line_num++;
            continue;
        }
        /* Normalize and trim value */
        char *val_ptr = NULL;
        int val_ptr_allocated = normalize_and_trim(val, strlen(val), 0, &val_ptr, &val_len);
        if (val_ptr_allocated < 0) {
            if (key_ptr_allocated) flb_free(key_ptr);
            line_num++;
            continue;
        }
        if (key_len == 0 || val_len == 0 || key_len > sizeof(key) || val_len > sizeof(val)) {
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            line_num++;
            continue;
        }
        /* Explicitly duplicate value buffer for hash table safety, allocate +1 for null terminator */
        char *val_heap = flb_malloc(val_len + 1);
        if (!val_heap) {
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            line_num++;
            continue;
        }
        memcpy(val_heap, val_ptr, val_len);
        val_heap[val_len] = '\0';
        int ret = flb_hash_table_add(ctx->ht, key_ptr, key_len, val_heap, val_len);
        if (ret < 0) {
            flb_free(val_heap);
            flb_plg_warn(ctx->ins, "Failed to add key '%.*s' (duplicate or error), skipping", (int)key_len, key_ptr);
            if (key_ptr_allocated) flb_free(key_ptr);
            if (val_ptr_allocated) flb_free(val_ptr);
            line_num++;
            continue;
        }
        /* Track allocated value for later cleanup */
        struct val_node *node = flb_malloc(sizeof(struct val_node));
        if (node) {
            node->val = val_heap;
            mk_list_add(&node->_head, &ctx->val_list);
        } else {
            /* If malloc fails, value will leak, but plugin will still function */
            flb_plg_warn(ctx->ins, "Failed to allocate val_node for value cleanup, value will leak");
        }
        /* Do not free val_heap; hash table owns it now */
        if (key_ptr_allocated) flb_free(key_ptr);
        if (val_ptr_allocated) flb_free(val_ptr);
        line_num++;
    }
    fclose(fp);
    return 0;
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
    if (!ctx->file || !ctx->lookup_key || !ctx->result_key) {
        flb_plg_error(ins, "missing required config: file, lookup_key, result_key");
        if (ctx->file) flb_free(ctx->file);
        if (ctx->lookup_key) flb_free(ctx->lookup_key);
        if (ctx->result_key) flb_free(ctx->result_key);
        flb_free(ctx);
        return -1;
    }

    /* Check file existence and readability */
    if (access(ctx->file, R_OK) != 0) {
        flb_plg_error(ins, "CSV file '%s' does not exist or is not readable", ctx->file);
        if (ctx->file) flb_free(ctx->file);
        if (ctx->lookup_key) flb_free(ctx->lookup_key);
        if (ctx->result_key) flb_free(ctx->result_key);
        flb_free(ctx);
        return -1;
    }

    /*
     * Create hash table for lookups. This will store key-value pairs loaded
     * from the CSV file for fast lookup during filtering.
     */
    ctx->ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1024, -1);
    if (!ctx->ht) {
        flb_plg_error(ins, "could not create hash table");
        if (ctx->file) flb_free(ctx->file);
        if (ctx->lookup_key) flb_free(ctx->lookup_key);
        if (ctx->result_key) flb_free(ctx->result_key);
        flb_free(ctx);
        return -1;
    }

    /* Initialize record accessor for lookup_key */
    ctx->ra_lookup_key = flb_ra_create(ctx->lookup_key, FLB_TRUE);
    if (!ctx->ra_lookup_key) {
        flb_plg_error(ins, "invalid lookup_key pattern: %s", ctx->lookup_key);
        flb_hash_table_destroy(ctx->ht);
        if (ctx->file) flb_free(ctx->file);
        if (ctx->lookup_key) flb_free(ctx->lookup_key);
        if (ctx->result_key) flb_free(ctx->result_key);
        flb_free(ctx);
        return -1;
    }

    /* Load CSV data into hash table. */
    ret = load_csv(ctx);
    if (ret < 0) {
        flb_ra_destroy(ctx->ra_lookup_key);
        flb_hash_table_destroy(ctx->ht);
        if (ctx->file) flb_free(ctx->file);
        if (ctx->lookup_key) flb_free(ctx->lookup_key);
        if (ctx->result_key) flb_free(ctx->result_key);
        flb_free(ctx);
        return -1;
    }
    flb_plg_info(ins, "Loaded %d entries from CSV", (int)ctx->ht->total_count);

    /* Store context for use in filter and exit callbacks. */
    flb_filter_set_context(ins, ctx);
    return 0;
}

static int emit_original_record(
    struct flb_log_event_encoder *log_encoder,
    struct flb_log_event *log_event,
    struct flb_filter_instance *ins,
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

    /* Defensive: ensure context is valid */
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
        rec_num++;
        lookup_val_str = NULL;
        lookup_val_len = 0;
        lookup_val_allocated = 0;

        /* Defensive: if body is not a map, emit original record and log debug */
        if (!log_event.body || log_event.body->type != MSGPACK_OBJECT_MAP) {
            flb_plg_debug(ins, "Record %d: body is not a map (type=%d), emitting original", rec_num, log_event.body ? log_event.body->type : -1);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        /*
         * Pre-scan for lookup_key to check for non-string types (array/map)
         * that the record accessor cannot handle, to prevent 'cannot process key value'
         * errors from flooding logs.
         *
         * This is a simple check for top-level keys and will not handle nested
         * record accessor patterns. A more robust solution would require parsing
         * the accessor pattern, which is beyond the scope of this simple fix.
         */
        char *key_to_find = ctx->lookup_key;
        size_t key_len = strlen(key_to_find);
        if (key_to_find[0] == '$') {
            key_to_find++;
            key_len--;
        }

        int key_found = 0;
        int key_type = -1;
        msgpack_object_map *map = &log_event.body->via.map;
        for (int i = 0; i < map->size; i++) {
            msgpack_object_kv *kv = &map->ptr[i];
            if (kv->key.type == MSGPACK_OBJECT_STR &&
                kv->key.via.str.size == key_len &&
                strncmp(kv->key.via.str.ptr, key_to_find, key_len) == 0) {
                key_found = 1;
                key_type = kv->val.type;
                break;
            }
        }

        if (key_found && (key_type == MSGPACK_OBJECT_ARRAY || key_type == MSGPACK_OBJECT_MAP)) {
            flb_plg_debug(ins, "Record %d: lookup_key '%s' has type array/map, skipping to avoid ra error", rec_num, ctx->lookup_key);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        /* Use record accessor to get the lookup value */
        struct flb_ra_value *rval = flb_ra_get_value_object(ctx->ra_lookup_key, *log_event.body);
        if (!rval) {
            /* Key not found, emit original record */
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        /* Extract string value from record accessor result */
        if (rval->type == FLB_RA_STRING) {
            lookup_val_allocated = normalize_and_trim((char *)rval->o.via.str.ptr, rval->o.via.str.size, ctx->ignore_case, &lookup_val_str, &lookup_val_len);
            if (lookup_val_allocated < 0) {
                flb_plg_warn(ins, "Record %d: malloc failed for normalize_and_trim (string), skipping", rec_num);
                lookup_val_str = NULL;
                lookup_val_len = 0;
            }
        }
        else {
            /* Non-string value: convert to string using direct formatting */
            char val_buf[64];
            int printed = 0;
            switch (rval->type) {
                case FLB_RA_BOOL:
                    printed = snprintf(val_buf, sizeof(val_buf), "%s", rval->o.via.boolean ? "true" : "false");
                    break;
                case FLB_RA_INT:
                    printed = snprintf(val_buf, sizeof(val_buf), "%" PRId64, rval->o.via.i64);
                    break;
                case FLB_RA_FLOAT:
                    printed = snprintf(val_buf, sizeof(val_buf), "%f", rval->o.via.f64);
                    break;
                case FLB_RA_NULL:
                    printed = snprintf(val_buf, sizeof(val_buf), "null");
                    break;
                case 5: /* ARRAY */
                case 6: /* MAP */
                    flb_plg_debug(ins, "Record %d: complex type (ARRAY/MAP) from record accessor, skipping conversion", rec_num);
                    flb_ra_key_value_destroy(rval);
                    emit_original_record(&log_encoder, &log_event, ins, rec_num);
                    continue;
                default:
                    flb_plg_debug(ins, "Record %d: unsupported type %d, skipping conversion", rec_num, rval->type);
                    flb_ra_key_value_destroy(rval);
                    emit_original_record(&log_encoder, &log_event, ins, rec_num);
                    continue;
            }
            if (printed > 0 && printed < (int)sizeof(val_buf)) {
                char *val_ptr = val_buf;
                size_t val_len = printed;
                lookup_val_allocated = normalize_and_trim(val_ptr, val_len, ctx->ignore_case, &lookup_val_str, &lookup_val_len);
                if (lookup_val_allocated < 0) {
                    flb_plg_warn(ins, "Record %d: malloc failed for normalize_and_trim (non-string), skipping", rec_num);
                    lookup_val_str = NULL;
                    lookup_val_len = 0;
                }
                flb_plg_debug(ins, "Record %d: lookup value for key '%s' is non-string, converted to '%s'", rec_num, ctx->lookup_key, lookup_val_str);
            } else {
                flb_plg_debug(ins, "Record %d: lookup value for key '%s' is non-string and could not be converted, emitting original", rec_num, ctx->lookup_key);
                flb_ra_key_value_destroy(rval);
                emit_original_record(&log_encoder, &log_event, ins, rec_num);
                continue;
            }
        }

        /*
         * If lookup value is missing or empty, emit the original record unchanged.
         */
        if (!lookup_val_str || lookup_val_len == 0) {
            if (lookup_val_allocated) {
                flb_free(lookup_val_str);
            }
            flb_ra_key_value_destroy(rval);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        /*
         * Attempt to find the lookup value in the hash table.
         * If not found, emit the original record unchanged.
         */
        int ht_get_ret = flb_hash_table_get(ctx->ht, lookup_val_str, lookup_val_len, &found_val, &found_len);
        /* Free normalization buffer if allocated */
        if (lookup_val_allocated) {
            flb_free(lookup_val_str);
            lookup_val_str = NULL;
        }
        flb_ra_key_value_destroy(rval);
        
        if (ht_get_ret < 0 || !found_val || found_len == 0) {
            /* Not found, emit original record */
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        /* Begin new record */
        ret = flb_log_event_encoder_begin_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to begin new record, emitting original", rec_num);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        ret = flb_log_event_encoder_set_timestamp(&log_encoder, &log_event.timestamp);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to set timestamp, emitting original", rec_num);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        if (log_event.metadata) {
            ret = flb_log_event_encoder_set_metadata_from_msgpack_object(&log_encoder, log_event.metadata);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_warn(ins, "Record %d: failed to set metadata, emitting original", rec_num);
                flb_log_event_encoder_rollback_record(&log_encoder);
                emit_original_record(&log_encoder, &log_event, ins, rec_num);
                continue;
            }
        }

        /* Copy all keys except result_key (to avoid collision) */
        if (log_event.body && log_event.body->type == MSGPACK_OBJECT_MAP) {
            int i;
            for (i = 0; i < log_event.body->via.map.size; i++) {
                msgpack_object_kv *kv = &log_event.body->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    kv->key.via.str.size == strlen(ctx->result_key) &&
                    strncmp(kv->key.via.str.ptr, ctx->result_key, kv->key.via.str.size) == 0) {
                    continue;
                }
                ret = flb_log_event_encoder_append_body_values(&log_encoder, 
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv->key), 
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv->val));
                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    flb_plg_warn(ins, "Record %d: failed to append key/value, emitting original", rec_num);
                    flb_log_event_encoder_rollback_record(&log_encoder);
                    emit_original_record(&log_encoder, &log_event, ins, rec_num);
                    continue;
                }
            }
        }

        /* Add result_key */
        ret = flb_log_event_encoder_append_body_string(&log_encoder, ctx->result_key, strlen(ctx->result_key));
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to append result_key, emitting original", rec_num);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        ret = flb_log_event_encoder_append_body_string(&log_encoder, (char *)found_val, found_len);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to append found_val, emitting original", rec_num);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }

        ret = flb_log_event_encoder_commit_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_warn(ins, "Record %d: failed to commit record, emitting original", rec_num);
            flb_log_event_encoder_rollback_record(&log_encoder);
            emit_original_record(&log_encoder, &log_event, ins, rec_num);
            continue;
        }
    }

    /*
     * If any records were modified, return the new buffer.
     * Otherwise, indicate no change.
     */
    if (log_encoder.output_length > 0) {
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
    if (ctx->file) flb_free(ctx->file);
    if (ctx->lookup_key) flb_free(ctx->lookup_key);
    if (ctx->result_key) flb_free(ctx->result_key);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    { FLB_CONFIG_MAP_STR, "file", NULL, 0, FLB_TRUE, offsetof(struct lookup_ctx, file), "CSV file to lookup values from." },
    { FLB_CONFIG_MAP_STR, "lookup_key", NULL, 0, FLB_TRUE, offsetof(struct lookup_ctx, lookup_key), "Name of the key to lookup in input record." },
    { FLB_CONFIG_MAP_STR, "result_key", NULL, 0, FLB_TRUE, offsetof(struct lookup_ctx, result_key), "Name of the key to add to output record if found." },
    { FLB_CONFIG_MAP_BOOL, "ignore_case", "false", 0, FLB_TRUE, offsetof(struct lookup_ctx, ignore_case), "Ignore case when matching lookup values (default: false)." },
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
