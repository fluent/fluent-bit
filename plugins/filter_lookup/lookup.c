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
#include <msgpack.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

struct lookup_ctx {
    struct flb_filter_instance *ins;
    char *file;
    char *lookup_key;
    char *result_key;
    struct flb_hash_table *ht;
    int ignore_case;
};

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
        int in_quotes = 0, escape = 0;
        int field = 0; /* 0=key, 1=val */

        /* Parse key from first column (handle quotes and escaped quotes) */
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

        /* Parse value from second column (handle quotes and escaped quotes) */
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

        /* Trim leading/trailing whitespace for both fields */
        char *key_ptr = key;
        while (*key_ptr && isspace((unsigned char)*key_ptr)) key_ptr++;
        char *key_end = key_ptr + strlen(key_ptr);
        while (key_end > key_ptr && isspace((unsigned char)*(key_end - 1))) key_end--;
        key_len = key_end - key_ptr;

        char *val_ptr = val;
        while (*val_ptr && isspace((unsigned char)*val_ptr)) val_ptr++;
        char *val_end = val_ptr + strlen(val_ptr);
        while (val_end > val_ptr && isspace((unsigned char)*(val_end - 1))) val_end--;
        val_len = val_end - val_ptr;

        if (key_len == 0 || val_len == 0 || key_len > sizeof(key) || val_len > sizeof(val)) {
            line_num++;
            continue;
        }

        /* If ignore_case, normalize key to lower-case */
        char key_norm[2048];
        if (ctx->ignore_case) {
            size_t j;
            for (j = 0; j < key_len && j < sizeof(key_norm)-1; j++) {
                key_norm[j] = tolower((unsigned char)key_ptr[j]);
            }
            key_norm[j] = '\0';
            key_ptr = key_norm;
            key_len = j;
        }

        /* Explicitly duplicate value buffer for hash table safety, allocate +1 for null terminator */
        char *val_heap = flb_malloc(val_len + 1);
        if (!val_heap) {
            /* Allocation failure, skip line */
            line_num++;
            continue;
        }
        memcpy(val_heap, val_ptr, val_len);
        val_heap[val_len] = '\0'; /* Ensure null-terminated for safety */
        int ht_ret = flb_hash_table_add(ctx->ht, key_ptr, key_len, val_heap, val_len);
        /* Do not free val_heap; hash table owns it now */
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

    /*
     * Load CSV data into hash table. Each line is parsed and added as a key-value
     * entry. If ignore_case is enabled, keys are normalized to lower-case.
     */

    ret = load_csv(ctx);
    if (ret < 0) {
        flb_hash_table_destroy(ctx->ht);
        if (ctx->file) flb_free(ctx->file);
        if (ctx->lookup_key) flb_free(ctx->lookup_key);
        if (ctx->result_key) flb_free(ctx->result_key);
        flb_free(ctx);
        return -1;
    }
    flb_plg_info(ins, "Loaded %zu entries from CSV", ctx->ht->total_count);

    /* Store context for use in filter and exit callbacks. */
    flb_filter_set_context(ins, ctx);
    return 0;
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

        /* Defensive: if body is not a map, emit original record and log debug */
        if (!log_event.body || log_event.body->type != MSGPACK_OBJECT_MAP) {
            flb_plg_debug(ins, "Record %d: body is not a map (type=%d), emitting original", rec_num, log_event.body ? log_event.body->type : -1);
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }

        /* Find lookup_key in record body */
        int i;
        for (i = 0; i < log_event.body->via.map.size; i++) {
            msgpack_object_kv *kv = &log_event.body->via.map.ptr[i];
            if (kv->key.type == MSGPACK_OBJECT_STR &&
                kv->key.via.str.size == strlen(ctx->lookup_key) &&
                strncmp(kv->key.via.str.ptr, ctx->lookup_key, kv->key.via.str.size) == 0) {
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    /* Trim leading/trailing whitespace from lookup value */
                    char *val_ptr = (char *)kv->val.via.str.ptr;
                    size_t val_len = kv->val.via.str.size;
                    /* Trim leading */
                    while (val_len > 0 && isspace((unsigned char)*val_ptr)) {
                        val_ptr++;
                        val_len--;
                    }
                    /* Trim trailing */
                    char *val_end = val_ptr + val_len;
                    while (val_len > 0 && isspace((unsigned char)*(val_end - 1))) {
                        val_end--;
                        val_len--;
                    }
                    /* If ignore_case, normalize lookup value to lower-case */
                    /* Defensive: check for excessive value length */
                    if (val_len > 4095) {
                        flb_plg_warn(ins, "Record %d: lookup value length %zu exceeds max allowed, skipping", rec_num, val_len);
                        lookup_val_str = NULL;
                        lookup_val_len = 0;
                    } else if (ctx->ignore_case) {
                        static char lookup_norm[4096];
                        size_t j;
                        for (j = 0; j < val_len && j < sizeof(lookup_norm)-1; j++) {
                            lookup_norm[j] = tolower((unsigned char)val_ptr[j]);
                        }
                        lookup_norm[j] = '\0';
                        lookup_val_str = lookup_norm;
                        lookup_val_len = j;
                    } else {
                        lookup_val_str = val_ptr;
                        lookup_val_len = val_len;
                    }
                }
                else {
                    /* Non-string value: convert to string using MsgPack print */
                    char val_buf[4096];
                    int printed = 0;
                    /* Use msgpack_object_print to convert value to string */
                    FILE *tmp_fp = fmemopen(val_buf, sizeof(val_buf)-1, "w");
                    if (tmp_fp) {
                        msgpack_object_print(tmp_fp, kv->val);
                        fflush(tmp_fp);
                        printed = ftell(tmp_fp);
                        fclose(tmp_fp);
                    }
                    if (printed > 0 && printed < sizeof(val_buf)) {
                        val_buf[printed] = '\0';
                        lookup_val_str = val_buf;
                        lookup_val_len = printed;
                        flb_plg_debug(ins, "Record %d: lookup value for key '%s' is non-string, converted to '%s'", rec_num, ctx->lookup_key, val_buf);
                    } else {
                        flb_plg_debug(ins, "Record %d: lookup value for key '%s' is non-string and could not be converted, emitting original", rec_num, ctx->lookup_key);
                        lookup_val_str = NULL;
                        lookup_val_len = 0;
                    }
                }
                break;
            }
        }

        /*
         * If lookup value is missing or empty, emit the original record unchanged.
         */
        if (!lookup_val_str || lookup_val_len == 0) {
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }

        /*
         * Attempt to find the lookup value in the hash table.
         * If not found, emit the original record unchanged.
         */
        int ht_get_ret = flb_hash_table_get(ctx->ht, lookup_val_str, lookup_val_len, &found_val, &found_len);
        if (ht_get_ret < 0 || !found_val || found_len == 0 || found_len > 4096) {
        /* Not found, emit original record */
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }

        /* Begin new record */
        ret = flb_log_event_encoder_begin_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }
        ret = flb_log_event_encoder_set_timestamp(&log_encoder, &log_event.timestamp);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }
        if (log_event.metadata) {
            ret = flb_log_event_encoder_set_metadata_from_msgpack_object(&log_encoder, log_event.metadata);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(&log_encoder);
                flb_log_event_encoder_emit_record(&log_encoder);
                continue;
            }
        }

        /* Copy all keys except result_key (to avoid collision) */
        if (log_event.body && log_event.body->type == MSGPACK_OBJECT_MAP) {
            int i;
            for (i = 0; i < log_event.body->via.map.size; i++) {
                msgpack_object_kv *kv = &log_event.body->via.map.ptr[i];
                /* Don't duplicate result_key */
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    kv->key.via.str.size == strlen(ctx->result_key) &&
                    strncmp(kv->key.via.str.ptr, ctx->result_key, kv->key.via.str.size) == 0) {
                    continue;
                }
                ret = flb_log_event_encoder_append_body_values(&log_encoder, FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv->key), FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv->val));
                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    flb_log_event_encoder_rollback_record(&log_encoder);
                    flb_log_event_encoder_emit_record(&log_encoder);
                    break;
                }
            }
        }

        /* Add result_key */
        ret = flb_log_event_encoder_append_body_string(&log_encoder, ctx->result_key, strlen(ctx->result_key));
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }
        ret = flb_log_event_encoder_append_body_string(&log_encoder, (char *)found_val, found_len);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            flb_log_event_encoder_emit_record(&log_encoder);
            continue;
        }

        ret = flb_log_event_encoder_commit_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            flb_log_event_encoder_emit_record(&log_encoder);
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
