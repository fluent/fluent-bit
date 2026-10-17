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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream_node.h>
#include <fluent-bit/flb_search_bulk.h>
#include <msgpack.h>

#include <time.h>

#include "es.h"
#include "es_conf.h"
#include "es_conf_prop.h"
#include "es_bulk.h"
#include "murmur3.h"

#define FLB_ES_TRACE_CHUNK_SIZE 3000
#define FLB_ES_RESPONSE_PREVIEW_SIZE 512

struct flb_output_plugin out_es_plugin;

static int es_pack_array_content(msgpack_packer *tmp_pck,
                                 msgpack_object array,
                                 int replace_dots);

static void log_payload_chunks(struct flb_elasticsearch *ctx,
                               const char *label,
                               const char *payload, size_t payload_size,
                               int log_level)
{
    size_t offset;
    size_t part;
    size_t part_count;
    size_t part_size;

    part_count = (payload_size + FLB_ES_TRACE_CHUNK_SIZE - 1) /
                 FLB_ES_TRACE_CHUNK_SIZE;
    for (offset = 0, part = 1; offset < payload_size; part++) {
        part_size = payload_size - offset;
        if (part_size > FLB_ES_TRACE_CHUNK_SIZE) {
            part_size = FLB_ES_TRACE_CHUNK_SIZE;
        }

        switch (log_level) {
        case FLB_LOG_ERROR:
            flb_plg_error(ctx->ins, "%s part %zu/%zu: %.*s",
                          label, part, part_count, (int) part_size,
                          payload + offset);
            break;
        case FLB_LOG_WARN:
            flb_plg_warn(ctx->ins, "%s part %zu/%zu: %.*s",
                         label, part, part_count, (int) part_size,
                         payload + offset);
            break;
        case FLB_LOG_INFO:
            flb_plg_info(ctx->ins, "%s part %zu/%zu: %.*s",
                         label, part, part_count, (int) part_size,
                         payload + offset);
            break;
        case FLB_LOG_DEBUG:
            flb_plg_debug(ctx->ins, "%s part %zu/%zu: %.*s",
                          label, part, part_count, (int) part_size,
                          payload + offset);
            break;
        case FLB_LOG_TRACE:
            flb_plg_trace(ctx->ins, "%s part %zu/%zu: %.*s",
                          label, part, part_count, (int) part_size,
                          payload + offset);
            break;
        case FLB_LOG_OFF:
        default:
            break;
        }
        offset += part_size;
    }
}

static void log_invalid_bulk_response(struct flb_elasticsearch *ctx,
                                      const char *payload,
                                      size_t payload_size)
{
    char character;
    char preview[(FLB_ES_RESPONSE_PREVIEW_SIZE * 2) + 1];
    size_t input_index;
    size_t input_size;
    size_t output_index;

    input_size = payload_size;
    if (input_size > FLB_ES_RESPONSE_PREVIEW_SIZE) {
        input_size = FLB_ES_RESPONSE_PREVIEW_SIZE;
    }

    output_index = 0;
    for (input_index = 0; input_index < input_size; input_index++) {
        character = payload[input_index];
        if (character == '\n' || character == '\r' || character == '\t') {
            preview[output_index++] = '\\';
            if (character == '\n') {
                preview[output_index++] = 'n';
            }
            else if (character == '\r') {
                preview[output_index++] = 'r';
            }
            else {
                preview[output_index++] = 't';
            }
        }
        else if ((unsigned char) character < 0x20 || character == 0x7f) {
            preview[output_index++] = '.';
        }
        else {
            preview[output_index++] = character;
        }
    }
    preview[output_index] = '\0';

    flb_plg_error(ctx->ins,
                  "invalid Elasticsearch bulk response (first %zu/%zu bytes): %s",
                  input_size, payload_size, preview);
}

static void log_bulk_failure_summary(struct flb_elasticsearch *ctx,
                                     struct flb_search_bulk_stats *stats,
                                     size_t retry_records,
                                     size_t dropped_records)
{
    if (dropped_records > 0) {
        flb_plg_error(ctx->ins,
                      "bulk response reported errors: %zu/%zu items failed, "
                      "first error: status=%d type='%s' reason='%s'; "
                      "retrying %zu record(s), dropped %zu unrecoverable record(s)",
                      stats->failed_items, stats->total_items,
                      stats->first_error_status, stats->first_error_type,
                      stats->first_error_reason, retry_records,
                      dropped_records);
    }
    else {
        flb_plg_error(ctx->ins,
                      "bulk response reported errors: %zu/%zu items failed, "
                      "first error: status=%d type='%s' reason='%s'; "
                      "retrying %zu record(s)",
                      stats->failed_items, stats->total_items,
                      stats->first_error_status, stats->first_error_type,
                      stats->first_error_reason, retry_records);
    }
}

#ifdef FLB_HAVE_AWS
static flb_sds_t add_aws_auth(struct flb_http_client *c,
                              struct flb_elasticsearch *ctx,
                              struct flb_elasticsearch_config *ec)
{
    flb_sds_t signature = NULL;
    int ret;

    flb_plg_debug(ctx->ins, "Signing request with AWS Sigv4");

    /* Amazon OpenSearch Sigv4 does not allow the host header to include the port */
    ret = flb_http_strip_port_from_host(c);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not strip port from host for sigv4");
        return NULL;
    }

    /* AWS Fluent Bit user agent */
    flb_http_add_header(c, "User-Agent", 10, "aws-fluent-bit-plugin", 21);

    signature = flb_signv4_do(c, FLB_TRUE, FLB_TRUE, time(NULL),
                              ec->aws_region, ec->aws_service_name,
                              S3_MODE_SIGNED_PAYLOAD,
                              ec->aws_unsigned_headers.value,
                              ec->aws_provider.value);
    if (!signature) {
        flb_plg_error(ctx->ins, "could not sign request with sigv4");
        return NULL;
    }
    return signature;
}
#endif /* FLB_HAVE_AWS */

static int es_pack_map_content(msgpack_packer *tmp_pck,
                               msgpack_object map,
                               int replace_dots)
{
    int i;
    char *ptr_key = NULL;
    char buf_key[256];
    msgpack_object *k;
    msgpack_object *v;

    for (i = 0; i < map.via.map.size; i++) {
        k = &map.via.map.ptr[i].key;
        v = &map.via.map.ptr[i].val;
        ptr_key = NULL;

        /* Store key */
        const char *key_ptr = NULL;
        size_t key_size = 0;

        if (k->type == MSGPACK_OBJECT_BIN) {
            key_ptr  = k->via.bin.ptr;
            key_size = k->via.bin.size;
        }
        else if (k->type == MSGPACK_OBJECT_STR) {
            key_ptr  = k->via.str.ptr;
            key_size = k->via.str.size;
        }

        if (key_size < (sizeof(buf_key) - 1)) {
            memcpy(buf_key, key_ptr, key_size);
            buf_key[key_size] = '\0';
            ptr_key = buf_key;
        }
        else {
            /* Long map keys have a performance penalty */
            ptr_key = flb_malloc(key_size + 1);
            if (!ptr_key) {
                flb_errno();
                return -1;
            }

            memcpy(ptr_key, key_ptr, key_size);
            ptr_key[key_size] = '\0';
        }

        /*
         * Sanitize key name, Elastic Search 2.x don't allow dots
         * in field names:
         *
         *   https://goo.gl/R5NMTr
         */
        if (replace_dots == FLB_TRUE) {
            char *p   = ptr_key;
            char *end = ptr_key + key_size;
            while (p != end) {
                if (*p == '.') *p = '_';
                p++;
            }
        }

        /* Append the key */
        msgpack_pack_str(tmp_pck, key_size);
        msgpack_pack_str_body(tmp_pck, ptr_key, key_size);

        /* Release temporary key if was allocated */
        if (ptr_key && ptr_key != buf_key) {
            flb_free(ptr_key);
        }
        ptr_key = NULL;

        /*
         * The value can be any data type, if it's a map we need to
         * sanitize to avoid dots.
         */
        if (v->type == MSGPACK_OBJECT_MAP) {
            msgpack_pack_map(tmp_pck, v->via.map.size);
            es_pack_map_content(tmp_pck, *v, replace_dots);
        }
        /*
         * The value can be any data type, if it's an array we need to
         * pass it to es_pack_array_content.
         */
        else if (v->type == MSGPACK_OBJECT_ARRAY) {
          msgpack_pack_array(tmp_pck, v->via.array.size);
          es_pack_array_content(tmp_pck, *v, replace_dots);
        }
        else {
            msgpack_pack_object(tmp_pck, *v);
        }
    }
    return 0;
}

/*
  * Iterate through the array and sanitize elements.
  * Mutual recursion with es_pack_map_content.
  */
static int es_pack_array_content(msgpack_packer *tmp_pck,
                                 msgpack_object array,
                                 int replace_dots)
{
    int i;
    msgpack_object *e;

    for (i = 0; i < array.via.array.size; i++) {
        e = &array.via.array.ptr[i];
        if (e->type == MSGPACK_OBJECT_MAP)
        {
            msgpack_pack_map(tmp_pck, e->via.map.size);
            es_pack_map_content(tmp_pck, *e, replace_dots);
        }
        else if (e->type == MSGPACK_OBJECT_ARRAY)
        {
            msgpack_pack_array(tmp_pck, e->via.array.size);
            es_pack_array_content(tmp_pck, *e, replace_dots);
        }
        else
        {
            msgpack_pack_object(tmp_pck, *e);
        }
    }
    return 0;
}

/*
 * Get _id value from incoming record.
 * If it successed, return the value as flb_sds_t.
 * If it failed, return NULL.
*/
static flb_sds_t es_get_id_value(struct flb_elasticsearch *ctx,
                                 struct flb_elasticsearch_config *ec,
                                 msgpack_object *map)
{
    struct flb_ra_value *rval = NULL;
    flb_sds_t tmp_str;
    rval = flb_ra_get_value_object(ec->ra_id_key.value, *map);
    if (rval == NULL) {
        flb_plg_warn(ctx->ins, "the value of %s is missing",
                     ec->id_key.value);
        return NULL;
    }
    else if(rval->o.type != MSGPACK_OBJECT_STR) {
        flb_plg_warn(ctx->ins, "the value of %s is not string",
                     ec->id_key.value);
        flb_ra_key_value_destroy(rval);
        return NULL;
    }

    tmp_str = flb_sds_create_len(rval->o.via.str.ptr,
                                 rval->o.via.str.size);
    if (tmp_str == NULL) {
        flb_plg_warn(ctx->ins, "cannot create ID string from record");
        flb_ra_key_value_destroy(rval);
        return NULL;
    }
    flb_ra_key_value_destroy(rval);
    return tmp_str;
}

static int es_action_line_value_is_safe(const char *value, size_t len)
{
    size_t i;
    unsigned char c;

    for (i = 0; i < len; i++) {
        c = (unsigned char) value[i];
        if (c == '\n' || c == '\r' || c == '"' || c == '\\' || c < 0x20) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int compose_index_header(struct flb_elasticsearch_config *ec,
                                int es_index_custom_len,
                                char *logstash_index, size_t logstash_index_size,
                                char *separator,
                                struct tm *tm)
{
    int ret;
    int len;
    char *p;
    size_t s;
    size_t separator_len;

    /* Compose Index header */
    if (es_index_custom_len > 0) {
        p = logstash_index + es_index_custom_len;
    } else {
        p = logstash_index + flb_sds_len(ec->logstash_prefix.value);
    }
    len = p - logstash_index;
    ret = snprintf(p, logstash_index_size - len, "%s", separator);
    if (ret > logstash_index_size - len) {
        /* exceed limit */
        return -1;
    }
    separator_len = strlen(separator);
    p += separator_len;
    len += separator_len;

    s = strftime(p, logstash_index_size - len,
                 ec->logstash_dateformat.value, tm);
    if (s==0) {
        /* exceed limit */
        return -1;
    }
    p += s;
    *p++ = '\0';

    return 0;
}

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Elasticsearch.
 *
 * 'Sadly' this process involves to convert from Msgpack to JSON.
 */
static int elasticsearch_format(struct flb_config *config,
                                struct flb_input_instance *ins,
                                void *plugin_context,
                                void *flush_ctx,
                                int event_type,
                                const char *tag, int tag_len,
                                const void *data, size_t bytes,
                                void **out_data, size_t *out_size)
{
    int ret;
    int len;
    int map_size;
    int index_len = 0;
    int write_op_update = FLB_FALSE;
    int write_op_upsert = FLB_FALSE;
    int id_key_required = FLB_FALSE;
    int id_key_safe;
    size_t s = 0;
    size_t off = 0;
    size_t off_prev = 0;
    char *es_index;
    char logstash_index[256];
    char time_formatted[256];
    char index_formatted[256];
    char es_uuid[37];
    flb_sds_t out_buf;
    size_t out_buf_len = 0;
    flb_sds_t tmp_buf;
    flb_sds_t id_key_str = NULL;
    // msgpack_unpacked result;
    // msgpack_object root;
    msgpack_object map;
    // msgpack_object *obj;
    flb_sds_t j_index;
    struct es_bulk *bulk;
    struct tm tm;
    struct flb_time tms;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    uint16_t hash[8];
    int es_index_custom_len;
    struct flb_elasticsearch *ctx = plugin_context;
    struct flb_elasticsearch_config *ec = flush_ctx;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    j_index = flb_sds_create_size(ES_BULK_HEADER);
    if (j_index == NULL) {
        flb_errno();
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);
        flb_sds_destroy(j_index);

        return -1;
    }

    /* Create the bulk composer */
    bulk = es_bulk_create(bytes);
    if (!bulk) {
        flb_log_event_decoder_destroy(&log_decoder);
        flb_sds_destroy(j_index);
        return -1;
    }

    if (strcasecmp(ec->write_operation.value, FLB_ES_WRITE_OP_UPDATE) == 0) {
        write_op_update = FLB_TRUE;
    }
    else if (strcasecmp(ec->write_operation.value, FLB_ES_WRITE_OP_UPSERT) == 0) {
        write_op_upsert = FLB_TRUE;
    }

    if (ec->ra_id_key.value && ec->generate_id == FLB_FALSE &&
        (write_op_update == FLB_TRUE || write_op_upsert == FLB_TRUE)) {
        id_key_required = FLB_TRUE;
    }

    /*
     * If logstash format and id generation are disabled, pre-generate
     * the index line for all records.
     *
     * The header stored in 'j_index' will be used for the all records on
     * this payload.
     */
    if (ec->logstash_format == FLB_FALSE && ec->generate_id == FLB_FALSE) {
        flb_time_get(&tms);
        gmtime_r(&tms.tm.tv_sec, &tm);
        strftime(index_formatted, sizeof(index_formatted) - 1,
                 ec->index.value, &tm);
        es_index = index_formatted;
        if (ec->suppress_type_name) {
            index_len = flb_sds_snprintf(&j_index,
                                         flb_sds_alloc(j_index),
                                         ES_BULK_INDEX_FMT_WITHOUT_TYPE,
                                         ec->es_action,
                                         es_index);
        }
        else {
            index_len = flb_sds_snprintf(&j_index,
                                         flb_sds_alloc(j_index),
                                         ES_BULK_INDEX_FMT,
                                         ec->es_action,
                                         es_index, ec->type.value);
        }
    }

    /*
     * Some broken clients may have time drift up to year 1970
     * this will generate corresponding index in Elasticsearch
     * in order to prevent generating millions of indexes
     * we can set to always use current time for index generation
     */
    if (ec->current_time_index == FLB_TRUE) {
        flb_time_get(&tms);
    }

    /* Iterate each record and do further formatting */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        /* Only pop time from record if current_time_index is disabled */
        if (ec->current_time_index == FLB_FALSE) {
            flb_time_copy(&tms, &log_event.timestamp);
        }

        map   = *log_event.body;
        map_size = map.via.map.size;

        /* Copy logstash prefix for the per-record fallback path. */
        if (ec->logstash_format == FLB_TRUE) {
            strncpy(logstash_index, ec->logstash_prefix.value, sizeof(logstash_index));
            logstash_index[sizeof(logstash_index) - 1] = '\0';
        }

        es_index_custom_len = 0;
        if (ec->logstash_prefix_key.value) {
            flb_sds_t v = flb_ra_translate(ec->ra_prefix_key.value,
                                           (char *) tag, tag_len,
                                           map, NULL);
            if (v) {
                len = flb_sds_len(v);
                if (es_action_line_value_is_safe(v, len) == FLB_TRUE) {
                    if (len > 128) {
                        len = 128;
                        memcpy(logstash_index, v, 128);
                    }
                    else {
                        memcpy(logstash_index, v, len);
                    }
                    es_index_custom_len = len;
                }
                flb_sds_destroy(v);
            }
        }

        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        if (ec->include_tag_key == FLB_TRUE) {
            map_size++;
        }

        /* Set the new map size */
        msgpack_pack_map(&tmp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&tmp_pck, flb_sds_len(ec->time_key.value));
        msgpack_pack_str_body(&tmp_pck, ec->time_key.value,
                              flb_sds_len(ec->time_key.value));

        /* Format the time */
        gmtime_r(&tms.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                     ec->time_key_format.value, &tm);
        if (ec->time_key_nanos) {
            len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                           ".%09" PRIu64 "Z", (uint64_t) tms.tm.tv_nsec);
        } else {
            len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                           ".%03" PRIu64 "Z",
                           (uint64_t) tms.tm.tv_nsec / 1000000);
        }

        s += len;
        msgpack_pack_str(&tmp_pck, s);
        msgpack_pack_str_body(&tmp_pck, time_formatted, s);

        es_index = ec->index.value;
        if (ec->logstash_format == FLB_TRUE) {
            ret = compose_index_header(ec, es_index_custom_len,
                                       &logstash_index[0], sizeof(logstash_index),
                                       ec->logstash_prefix_separator.value, &tm);
            if (ret < 0) {
                /* retry with default separator */
                compose_index_header(ec, es_index_custom_len,
                                     &logstash_index[0], sizeof(logstash_index),
                                     "-", &tm);
            }

            es_index = logstash_index;
            if (ec->generate_id == FLB_FALSE) {
                if (ec->suppress_type_name) {
                    index_len = flb_sds_snprintf(&j_index,
                                                 flb_sds_alloc(j_index),
                                                 ES_BULK_INDEX_FMT_WITHOUT_TYPE,
                                                 ec->es_action,
                                                 es_index);
                }
                else {
                    index_len = flb_sds_snprintf(&j_index,
                                                 flb_sds_alloc(j_index),
                                                 ES_BULK_INDEX_FMT,
                                                 ec->es_action,
                                                 es_index, ec->type.value);
                }
            }
        }
        else if (ec->current_time_index == FLB_TRUE) {
            /* Make sure we handle index time format for index */
            strftime(index_formatted, sizeof(index_formatted) - 1,
                     ec->index.value, &tm);
            es_index = index_formatted;
        }

        /* Tag Key */
        if (ec->include_tag_key == FLB_TRUE) {
            msgpack_pack_str(&tmp_pck, flb_sds_len(ec->tag_key.value));
            msgpack_pack_str_body(&tmp_pck, ec->tag_key.value,
                                  flb_sds_len(ec->tag_key.value));
            msgpack_pack_str(&tmp_pck, tag_len);
            msgpack_pack_str_body(&tmp_pck, tag, tag_len);
        }

        /*
         * The map_content routine iterate over each Key/Value pair found in
         * the map and do some sanitization for the key names.
         *
         * Elasticsearch have a restriction that key names cannot contain
         * a dot; if some dot is found, it's replaced with an underscore.
         */
        ret = es_pack_map_content(&tmp_pck, map, ec->replace_dots);
        if (ret == -1) {
            flb_log_event_decoder_destroy(&log_decoder);
            msgpack_sbuffer_destroy(&tmp_sbuf);
            es_bulk_destroy(bulk);
            flb_sds_destroy(j_index);
            return -1;
        }

        if (ec->generate_id == FLB_TRUE) {
            MurmurHash3_x64_128(tmp_sbuf.data, tmp_sbuf.size, 42, hash);
            snprintf(es_uuid, sizeof(es_uuid),
                     "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
                     hash[0], hash[1], hash[2], hash[3],
                     hash[4], hash[5], hash[6], hash[7]);
            if (ec->suppress_type_name) {
                index_len = flb_sds_snprintf(&j_index,
                                             flb_sds_alloc(j_index),
                                             ES_BULK_INDEX_FMT_ID_WITHOUT_TYPE,
                                             ec->es_action,
                                             es_index,  es_uuid);
            }
            else {
                index_len = flb_sds_snprintf(&j_index,
                                             flb_sds_alloc(j_index),
                                             ES_BULK_INDEX_FMT_ID,
                                             ec->es_action,
                                             es_index, ec->type.value, es_uuid);
            }
        }
        if (ec->ra_id_key.value) {
            id_key_str = es_get_id_value(ctx, ec, &map);
            id_key_safe = FLB_FALSE;

            if (id_key_str &&
                es_action_line_value_is_safe(id_key_str,
                                             flb_sds_len(id_key_str)) == FLB_TRUE) {
                id_key_safe = FLB_TRUE;
            }

            if (id_key_safe == FLB_TRUE) {
                if (ec->suppress_type_name) {
                    index_len = flb_sds_snprintf(&j_index,
                                                 flb_sds_alloc(j_index),
                                                 ES_BULK_INDEX_FMT_ID_WITHOUT_TYPE,
                                                 ec->es_action,
                                                 es_index,  id_key_str);
                }
                else {
                    index_len = flb_sds_snprintf(&j_index,
                                                 flb_sds_alloc(j_index),
                                                 ES_BULK_INDEX_FMT_ID,
                                                 ec->es_action,
                                                 es_index, ec->type.value,
                                                 id_key_str);
                }
            }
            else if (id_key_required == FLB_TRUE) {
                flb_plg_warn(ctx->ins,
                             "skipping record with missing or unsafe Id_Key value");
                if (id_key_str) {
                    flb_sds_destroy(id_key_str);
                    id_key_str = NULL;
                }
                msgpack_sbuffer_destroy(&tmp_sbuf);
                continue;
            }
            else if (ec->generate_id == FLB_FALSE && id_key_str) {
                if (ec->suppress_type_name) {
                    index_len = flb_sds_snprintf(&j_index,
                                                 flb_sds_alloc(j_index),
                                                 ES_BULK_INDEX_FMT_WITHOUT_TYPE,
                                                 ec->es_action,
                                                 es_index);
                }
                else {
                    index_len = flb_sds_snprintf(&j_index,
                                                 flb_sds_alloc(j_index),
                                                 ES_BULK_INDEX_FMT,
                                                 ec->es_action,
                                                 es_index, ec->type.value);
                }
            }

            if (id_key_str) {
                flb_sds_destroy(id_key_str);
                id_key_str = NULL;
            }
        }

        /* Convert msgpack to JSON */
        out_buf = flb_msgpack_raw_to_json_sds(tmp_sbuf.data, tmp_sbuf.size,
                                              config->json_escape_unicode);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        if (!out_buf) {
            flb_log_event_decoder_destroy(&log_decoder);
            es_bulk_destroy(bulk);
            flb_sds_destroy(j_index);
            return -1;
        }

        out_buf_len = flb_sds_len(out_buf);
        if (write_op_update == FLB_TRUE) {
            tmp_buf = out_buf;
            out_buf = flb_sds_create_len(NULL, out_buf_len = out_buf_len + sizeof(ES_BULK_UPDATE_OP_BODY) - 2);
            out_buf_len = snprintf(out_buf, out_buf_len, ES_BULK_UPDATE_OP_BODY, tmp_buf);
            flb_sds_destroy(tmp_buf);
        }
        else if (write_op_upsert == FLB_TRUE) {
            tmp_buf = out_buf;
            out_buf = flb_sds_create_len(NULL, out_buf_len = out_buf_len + sizeof(ES_BULK_UPSERT_OP_BODY) - 2);
            out_buf_len = snprintf(out_buf, out_buf_len, ES_BULK_UPSERT_OP_BODY, tmp_buf);
            flb_sds_destroy(tmp_buf);
        }

        ret = es_bulk_append(bulk, j_index, index_len,
                             out_buf, out_buf_len,
                             bytes, off_prev);
        flb_sds_destroy(out_buf);

        off_prev = off;
        if (ret == -1) {
            /* We likely ran out of memory, abort here */
            flb_log_event_decoder_destroy(&log_decoder);
            *out_size = 0;
            es_bulk_destroy(bulk);
            flb_sds_destroy(j_index);
            return -1;
        }
    }
    flb_log_event_decoder_destroy(&log_decoder);

    /* Set outgoing data */
    *out_data = bulk->ptr;
    *out_size = bulk->len;

    /*
     * Note: we don't destroy the bulk as we need to keep the allocated
     * buffer with the data. Instead we just release the bulk context and
     * return the bulk->ptr buffer
     */
    flb_free(bulk);
    if (ec->trace_output) {
        fwrite(*out_data, 1, *out_size, stdout);
        fflush(stdout);
    }
    flb_sds_destroy(j_index);
    return 0;
}

static int cb_es_init(struct flb_output_instance *ins,
                      struct flb_config *config,
                      void *data)
{
    struct flb_elasticsearch *ctx;
    (void) data;

    ctx = flb_es_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize plugin");
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

struct flb_elasticsearch_config *flb_elasticsearch_target(
        struct flb_elasticsearch *ctx, struct flb_upstream_node **node)
{
    struct flb_elasticsearch_config *ec;
    struct flb_upstream_node *target_node;

    if (ctx->ha_mode == FLB_FALSE) {
        ec = flb_es_upstream_conf(ctx, NULL);
        *node = NULL;
        return ec;
    }

    target_node = flb_upstream_ha_node_get(ctx->ha);
    if (!target_node) {
        *node = NULL;
        return NULL;
    }

    ec = flb_es_upstream_conf(ctx, target_node);
    *node = target_node;

    return ec;
}

static int elasticsearch_error_check(struct flb_elasticsearch *ctx,
                                     struct flb_http_client *c)
{
    int i, j, k;
    int ret;
    int check = 0;
    int root_type;
    char *out_buf;
    size_t off = 0;
    size_t out_size;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;
    msgpack_object item;
    msgpack_object item_key;
    msgpack_object item_val;

    /*
     * Check if our payload is complete: there is such situations where
     * the Elasticsearch HTTP response body is bigger than the HTTP client
     * buffer so payload can be incomplete.
     */
    /* Convert JSON payload to msgpack */
    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &out_buf, &out_size, &root_type, NULL);
    if (ret == -1) {
        /* Is this an incomplete HTTP Request ? */
        if (c->resp.payload_size <= 0) {
            check |= FLB_ES_STATUS_IMCOMPLETE;
            return check;
        }

        /* Lookup error field */
        if (strstr(c->resp.payload, "\"errors\":false,\"items\":[")) {
            check |= FLB_ES_STATUS_SUCCESS;
            return check;
        }

        flb_plg_error(ctx->ins, "could not pack/validate JSON response\n%s",
                      c->resp.payload);
        check |= FLB_ES_STATUS_BAD_RESPONSE;
        return check;
    }

    /* Lookup error field */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack response to find error\n%s",
                      c->resp.payload);
        check |= FLB_ES_STATUS_ERROR_UNPACK;
        return check;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected payload type=%i",
                      root.type);
        check |= FLB_ES_STATUS_BAD_TYPE;
        goto done;
    }

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "unexpected key type=%i",
                          key.type);
            check |= FLB_ES_STATUS_INVAILD_ARGUMENT;
            goto done;
        }

        if (key.via.str.size == 6 && strncmp(key.via.str.ptr, "errors", 6) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_BOOLEAN) {
                flb_plg_error(ctx->ins, "unexpected 'error' value type=%i",
                              val.type);
                check |= FLB_ES_STATUS_BAD_TYPE;
                goto done;
            }

            /* If error == false, we are OK (no errors = FLB_FALSE) */
            if (!val.via.boolean) {
                /* no errors */
                check |= FLB_ES_STATUS_SUCCESS;
                goto done;
            }
        }
        else if (key.via.str.size == 5 && strncmp(key.via.str.ptr, "items", 5) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_ARRAY) {
                flb_plg_error(ctx->ins, "unexpected 'items' value type=%i",
                              val.type);
                check |= FLB_ES_STATUS_BAD_TYPE;
                goto done;
            }

            for (j = 0; j < val.via.array.size; j++) {
                item = val.via.array.ptr[j];
                if (item.type != MSGPACK_OBJECT_MAP) {
                    flb_plg_error(ctx->ins, "unexpected 'item' outer value type=%i",
                                  item.type);
                    check |= FLB_ES_STATUS_BAD_TYPE;
                    goto done;
                }

                if (item.via.map.size != 1) {
                    flb_plg_error(ctx->ins, "unexpected 'item' size=%i",
                                  item.via.map.size);
                    check |= FLB_ES_STATUS_INVAILD_ARGUMENT;
                    goto done;
                }

                item = item.via.map.ptr[0].val;
                if (item.type != MSGPACK_OBJECT_MAP) {
                    flb_plg_error(ctx->ins, "unexpected 'item' inner value type=%i",
                                  item.type);
                    check |= FLB_ES_STATUS_BAD_TYPE;
                    goto done;
                }

                for (k = 0; k < item.via.map.size; k++) {
                    item_key = item.via.map.ptr[k].key;
                    if (item_key.type != MSGPACK_OBJECT_STR) {
                        flb_plg_error(ctx->ins, "unexpected key type=%i",
                                      item_key.type);
                        check |= FLB_ES_STATUS_BAD_TYPE;
                        goto done;
                    }

                    if (item_key.via.str.size == 6 && strncmp(item_key.via.str.ptr, "status", 6) == 0) {
                        item_val = item.via.map.ptr[k].val;

                        if (item_val.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            flb_plg_error(ctx->ins, "unexpected 'status' value type=%i",
                                          item_val.type);
                            check |= FLB_ES_STATUS_BAD_TYPE;
                            goto done;
                        }
                        /* Check for success responses */
                        if (item_val.via.i64 == 200 || item_val.via.i64 == 201) {
                            check |= FLB_ES_STATUS_SUCCESS;
                        }
                        /* Check for errors other than version conflict (document already exists) */
                        if (item_val.via.i64 != 409) {
                            check |= FLB_ES_STATUS_ERROR;
                        }
                    }
                }
            }
        }
    }

 done:
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
    return check;
}

static void cb_es_flush(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *ins, void *out_context,
                        struct flb_config *config)
{
    int ret;
    size_t pack_size;
    char *pack;
    void *out_buf;
    size_t out_size;
    size_t b_sent;
    struct flb_elasticsearch *ctx = out_context;
    struct flb_elasticsearch_config *ec;
    struct flb_connection *u_conn;
    struct flb_upstream_node *node;
    struct flb_http_client *c;
    flb_sds_t signature = NULL;
    int compressed = FLB_FALSE;
    void *final_payload_buf;
    size_t final_payload_size;
    struct flb_search_bulk_retry *retry_payload;
    struct flb_search_bulk_retry *next_retry_payload;
    flb_sds_t header_line = NULL;
    struct flb_search_bulk_stats bulk_stats;
    size_t retry_records;
    size_t dropped_records;
    size_t dropped_bytes;
    size_t successful_bytes;
    int successful_records;
    int retry_context_result;

    pack = NULL;
    out_buf = NULL;
    final_payload_buf = NULL;
    final_payload_size = 0;
    next_retry_payload = NULL;

    ec = flb_elasticsearch_target(ctx, &node);
    if (!ec) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get upstream connection */
    if (ctx->ha_mode == FLB_TRUE) {
        u_conn = flb_upstream_conn_get(node->u);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "no upstream connections available for %s node",
                          node->name);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
    else {
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "no upstream connections available");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    retry_payload = flb_output_get_retry_context(out_flush, NULL, NULL);
    if (retry_payload != NULL) {
        out_buf = flb_malloc(retry_payload->size);
        if (out_buf == NULL) {
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        memcpy(out_buf, retry_payload->payload, retry_payload->size);
        out_size = retry_payload->size;
    }
    else {
        /* Convert format */
        ret = elasticsearch_format(config, ins,
                                   ctx, ec,
                                   event_chunk->type,
                                   event_chunk->tag, flb_sds_len(event_chunk->tag),
                                   event_chunk->data, event_chunk->size,
                                   &out_buf, &out_size);
        if (ret != 0) {
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    if (out_size == 0) {
        flb_free(out_buf);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    pack = (char *) out_buf;
    pack_size = out_size;
    final_payload_buf = pack;
    final_payload_size = pack_size;

    /* Should we compress the payload ? */
    if (ec->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) pack, pack_size,
                                &out_buf, &out_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        }
        else {
            compressed = FLB_TRUE;
            final_payload_buf = out_buf;
            final_payload_size = out_size;
        }
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ec->uri,
                        final_payload_buf, final_payload_size,
                        NULL, 0, NULL, 0);
    if (c == NULL) {
        goto retry;
    }

    flb_http_buffer_size(c, ec->buffer_size);

#ifndef FLB_HAVE_AWS
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
#endif

    flb_http_add_header(c, "Content-Type", 12, "application/x-ndjson", 20);

    if (ec->http_user && ec->http_passwd) {
        flb_http_basic_auth(c, ec->http_user, ec->http_passwd);
    }
    else if (ec->cloud_user.value && ec->cloud_passwd.value) {
        flb_http_basic_auth(c, ec->cloud_user.value, ec->cloud_passwd.value);
    }
    else if (ec->http_api_key) {
        /* 7 for ApiKey + space */
        header_line = flb_sds_create_size(strlen(ec->http_api_key)+7);
        if (header_line == NULL) {
            flb_plg_error(ctx->ins, "failed to format API key auth header");
            goto retry;
        }
        header_line = flb_sds_printf(&header_line, "ApiKey %s", ec->http_api_key);

        if (flb_http_add_header(c,
                                FLB_HTTP_HEADER_AUTH, strlen(FLB_HTTP_HEADER_AUTH),
                                header_line, flb_sds_len(header_line)) != 0) {
            flb_plg_error(ctx->ins, "failed to add API key auth header");
            flb_sds_destroy(header_line);
            goto retry;
        }

        flb_sds_destroy(header_line);
    }

#ifdef FLB_HAVE_AWS
    if (ec->has_aws_auth == FLB_TRUE) {
        signature = add_aws_auth(c, ctx, ec);
        if (!signature) {
            goto retry;
        }
    }
    else {
        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    }
#endif

    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Map debug callbacks */
    flb_http_client_debug(c, ctx->ins->callback);

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i URI=%s", ret, ec->uri);
        goto retry;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i URI=%s", c->resp.status, ec->uri);
        if (c->resp.status != 200 && c->resp.status != 201) {
            if (c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "HTTP status=%i URI=%s, response:\n%s\n",
                              c->resp.status, ec->uri, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "HTTP status=%i URI=%s",
                              c->resp.status, ec->uri);
            }
            goto retry;
        }

        if (c->resp.payload_size > 0) {
            /* Only create conflicts confirm that the document already exists. */
            ret = flb_search_bulk_process_response(c->resp.payload,
                                                   c->resp.payload_size,
                                                   pack, pack_size,
                                                   FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                                   ec->drop_unrecoverable_records,
                                                   &bulk_stats,
                                                   &next_retry_payload);
            retry_records = 0;
            if (next_retry_payload != NULL) {
                retry_records = next_retry_payload->records;
            }
            dropped_records = 0;
            dropped_bytes = 0;

            if (ret == FLB_SEARCH_BULK_RETRY) {
                retry_context_result = flb_output_set_retry_context(
                                           out_flush, next_retry_payload,
                                           flb_search_bulk_retry_destroy,
                                           next_retry_payload->records,
                                           next_retry_payload->size);
                if (retry_context_result != 0) {
                    flb_search_bulk_retry_destroy(next_retry_payload);
                    next_retry_payload = NULL;
                    retry_records = bulk_stats.total_items;
                    flb_plg_error(ctx->ins,
                                  "could not preserve filtered bulk retry payload; "
                                  "retrying the full batch");
                }
                else {
                    next_retry_payload = NULL;
                    if (ec->drop_unrecoverable_records == FLB_TRUE) {
                        dropped_records = bulk_stats.unrecoverable_items;
                        dropped_bytes = bulk_stats.unrecoverable_bytes;
                    }
                }
            }
            else if (ret == FLB_SEARCH_BULK_COMPLETE &&
                     ec->drop_unrecoverable_records == FLB_TRUE) {
                dropped_records = bulk_stats.unrecoverable_items;
                dropped_bytes = bulk_stats.unrecoverable_bytes;
            }

            if ((ret == FLB_SEARCH_BULK_COMPLETE ||
                 ret == FLB_SEARCH_BULK_RETRY) &&
                bulk_stats.failed_items > 0) {
                log_bulk_failure_summary(ctx, &bulk_stats, retry_records,
                                         dropped_records);
#ifdef FLB_HAVE_METRICS
                if (dropped_records > 0) {
                    cmt_counter_add(ctx->ins->cmt_dropped_records,
                                    cfl_time_now(),
                                    dropped_records,
                                    1, (char *[]) {
                                        (char *) flb_output_name(ctx->ins)
                                    });

                    if (out_flush->config->router != NULL &&
                        event_chunk->type == FLB_EVENT_TYPE_LOGS) {
                        cmt_counter_add(out_flush->config->router->logs_drop_records_total,
                                        cfl_time_now(), dropped_records,
                                        2, (char *[]) {
                                            (char *) flb_input_name(out_flush->task->i_ins),
                                            (char *) flb_output_name(ctx->ins)
                                        });
                        cmt_counter_add(out_flush->config->router->logs_drop_bytes_total,
                                        cfl_time_now(), dropped_bytes,
                                        2, (char *[]) {
                                            (char *) flb_input_name(out_flush->task->i_ins),
                                            (char *) flb_output_name(ctx->ins)
                                        });
                    }
                }
#endif
            }

            if (ec->trace_error == FLB_TRUE &&
                (ret != FLB_SEARCH_BULK_COMPLETE || bulk_stats.failed_items > 0)) {
                log_payload_chunks(ctx, "error caused by: Input", pack, pack_size,
                                   FLB_LOG_DEBUG);
                log_payload_chunks(ctx, "error: Output", c->resp.payload,
                                   c->resp.payload_size, FLB_LOG_ERROR);
            }

            if (ret == FLB_SEARCH_BULK_COMPLETE) {
                if (bulk_stats.total_items > 0 &&
                    (dropped_records > 0 || retry_payload != NULL)) {
                    successful_records = (int) bulk_stats.successful_items;
                    successful_bytes = bulk_stats.successful_bytes;
                    flb_output_set_successful_route_data(out_flush,
                                                         successful_records,
                                                         successful_bytes);
                }
                else if (retry_payload != NULL) {
                    flb_output_set_successful_route_data(out_flush,
                                                         retry_payload->records,
                                                         retry_payload->size);
                }
                flb_output_clear_retry_context(out_flush);
                flb_plg_debug(ctx->ins, "Elasticsearch response\n%s",
                              c->resp.payload);
            }
            else {
                if (ret != FLB_SEARCH_BULK_RETRY) {
                    log_invalid_bulk_response(ctx, c->resp.payload,
                                              c->resp.payload_size);
                }
                goto retry;
            }
        }
        else {
            goto retry;
        }
    }

    /* Cleanup */
    if (c != NULL) {
        flb_http_client_destroy(c);
    }
    flb_free(pack);
    if (final_payload_buf != pack) {
        flb_free(final_payload_buf);
    }
    flb_upstream_conn_release(u_conn);
    if (signature) {
        flb_sds_destroy(signature);
    }
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    if (c != NULL) {
        flb_http_client_destroy(c);
    }
    flb_free(pack);
    if (signature != NULL) {
        flb_sds_destroy(signature);
    }
    if (final_payload_buf != pack) {
        flb_free(final_payload_buf);
    }

    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int elasticsearch_response_test(struct flb_config *config,
                                       void *plugin_context,
                                       int status,
                                       const void *data, size_t bytes,
                                       void **out_data, size_t *out_size)
{
    int ret = 0;
    struct flb_elasticsearch *ctx = plugin_context;
    struct flb_elasticsearch_config *ec;
    struct flb_upstream_node *node;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    size_t b_sent;

    ec = flb_elasticsearch_target(ctx, &node);
    if (!ec) {
      flb_plg_warn(ctx->ins, "failed to get target configuration");
      return -2;
    }

    /* Not retrieve upstream connection */
    u_conn = NULL;

    /* Compose HTTP Client request (dummy client) */
    c = flb_http_dummy_client(u_conn, FLB_HTTP_POST, ec->uri,
                              NULL, 0, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, ec->buffer_size);

    /* Just stubbing the HTTP responses */
    flb_http_set_response_test(c, "response", data, bytes, status, NULL, NULL);

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i URI=%s", ret, ec->uri);
        goto error;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i URI=%s", c->resp.status, ec->uri);
        if (c->resp.status != 200 && c->resp.status != 201) {
            if (c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "HTTP status=%i URI=%s, response:\n%s\n",
                              c->resp.status, ec->uri, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "HTTP status=%i URI=%s",
                              c->resp.status, ec->uri);
            }
            goto error;
        }

        if (c->resp.payload_size > 0) {
            /*
             * Elasticsearch payload should be JSON, we convert it to msgpack
             * and lookup the 'error' field.
             */
            ret = elasticsearch_error_check(ctx, c);
        }
        else {
            goto error;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);

    return ret;

error:
    /* Cleanup */
    flb_http_client_destroy(c);

    return -2;
}

static int cb_es_exit(void *data, struct flb_config *config)
{
    struct flb_elasticsearch *ctx = data;

    flb_es_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_INDEX, FLB_ES_DEFAULT_INDEX,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, index) +
         offsetof(struct flb_es_str, value),
     "Set an index name"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_TYPE, FLB_ES_DEFAULT_TYPE,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, type) +
         offsetof(struct flb_es_str, value),
     "Set the document type property"
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_SUPPRESS_TYPE_NAME, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, suppress_type_name),
     "If true, mapping types is removed. (for v7.0.0 or later)"
    },

    /* HTTP Authentication */
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_HTTP_USER, NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, http_user),
     "Optional username credential for Elastic X-Pack access"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_HTTP_PASSWD, "",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, http_passwd),
     "Password for user defined in HTTP_User"
    },
    {
    FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_HTTP_API_KEY, NULL,
    0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, http_api_key),
    "Base-64 encoded API key credential for Elasticsearch"
    },

    /* HTTP Compression */
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_COMPRESS, NULL,
     0, FLB_FALSE, 0,
     "Set payload compression mechanism. Option available is 'gzip'"
    },

    /* Cloud Authentication */
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_CLOUD_ID, NULL,
     0, FLB_FALSE, 0,
     "Elastic cloud ID of the cluster to connect to"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_CLOUD_AUTH, NULL,
     0, FLB_FALSE, 0,
     "Elastic cloud authentication credentials"
    },

    /* AWS Authentication */
#ifdef FLB_HAVE_AWS
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_AWS_AUTH, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, has_aws_auth),
     "Enable AWS Sigv4 Authentication"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_AWS_REGION, NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, aws_region),
     "AWS Region of your Amazon OpenSearch Service cluster"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_AWS_STS_ENDPOINT, NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, aws_sts_endpoint),
     "Custom endpoint for the AWS STS API, used with the AWS_Role_ARN option"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_AWS_ROLE_ARN, NULL,
     0, FLB_FALSE, 0,
     "AWS IAM Role to assume to put records to your Amazon OpenSearch cluster"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_AWS_EXTERNAL_ID, NULL,
     0, FLB_FALSE, 0,
     "External ID for the AWS IAM Role specified with `aws_role_arn`"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_AWS_SERVICE_NAME, "es",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, aws_service_name),
     "AWS Service Name"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_AWS_PROFILE, NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, aws_profile),
     "AWS Profile name. AWS Profiles can be configured with AWS CLI and are usually stored in "
     "$HOME/.aws/ directory."
    },
#endif

    /* Logstash compatibility */
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_LOGSTASH_FORMAT, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, logstash_format),
     "Enable Logstash format compatibility"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX, FLB_ES_DEFAULT_PREFIX,
     0, FLB_TRUE,
     offsetof(struct flb_elasticsearch_config, logstash_prefix) +
         offsetof(struct flb_es_sds_t, value),
     "When Logstash_Format is enabled, the Index name is composed using a prefix "
     "and the date, e.g: If Logstash_Prefix is equals to 'mydata' your index will "
     "become 'mydata-YYYY.MM.DD'. The last string appended belongs to the date "
     "when the data is being generated"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX_SEPARATOR, "-",
     0, FLB_TRUE,
     offsetof(struct flb_elasticsearch_config, logstash_prefix_separator) +
         offsetof(struct flb_es_sds_t, value),
     "Set a separator between logstash_prefix and date."
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX_KEY, NULL,
     0, FLB_TRUE,
     offsetof(struct flb_elasticsearch_config, logstash_prefix_key) +
         offsetof(struct flb_es_sds_t, value),
     "When included: the value in the record that belongs to the key will be looked "
     "up and over-write the Logstash_Prefix for index generation. If the key/value "
     "is not found in the record then the Logstash_Prefix option will act as a "
     "fallback. Nested keys are supported through record accessor pattern"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_LOGSTASH_DATEFORMAT, FLB_ES_DEFAULT_TIME_FMT,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, logstash_dateformat) +
         offsetof(struct flb_es_sds_t, value),
     "Time format (based on strftime) to generate the second part of the Index name"
    },

    /* Custom Time and Tag keys */
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_TIME_KEY, FLB_ES_DEFAULT_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, time_key) +
         offsetof(struct flb_es_sds_t, value),
     "When Logstash_Format is enabled, each record will get a new timestamp field. "
     "The Time_Key property defines the name of that field"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_TIME_KEY_FORMAT, FLB_ES_DEFAULT_TIME_KEYF,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, time_key_format) +
         offsetof(struct flb_es_sds_t, value),
     "When Logstash_Format is enabled, this property defines the format of the "
     "timestamp"
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_TIME_KEY_NANOS, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, time_key_nanos),
     "When Logstash_Format is enabled, enabling this property sends nanosecond "
     "precision timestamps"
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_INCLUDE_TAG_KEY, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, include_tag_key),
     "When enabled, it append the Tag name to the record"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_TAG_KEY, FLB_ES_DEFAULT_TAG_KEY,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, tag_key) +
         offsetof(struct flb_es_sds_t, value),
     "When Include_Tag_Key is enabled, this property defines the key name for the tag"
    },
    {
     FLB_CONFIG_MAP_SIZE, FLB_ES_CONFIG_PROPERTY_BUFFER_SIZE, FLB_ES_DEFAULT_HTTP_MAX,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, buffer_size),
     "Specify the buffer size used to read the response from the Elasticsearch HTTP "
     "service. This option is useful for debugging purposes where is required to read "
     "full responses, note that response size grows depending of the number of records "
     "inserted. To set an unlimited amount of memory set this value to 'false', "
     "otherwise the value must be according to the Unit Size specification"
    },

    /* Elasticsearch specifics */
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_PATH, NULL,
     0, FLB_FALSE, 0,
     "Elasticsearch accepts new data on HTTP query path '/_bulk'. But it is also "
     "possible to serve Elasticsearch behind a reverse proxy on a subpath. This "
     "option defines such path on the fluent-bit side. It simply adds a path "
     "prefix in the indexing HTTP POST URI"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_PIPELINE, NULL,
     0, FLB_FALSE, 0,
     "Newer versions of Elasticsearch allows to setup filters called pipelines. "
     "This option allows to define which pipeline the database should use. For "
     "performance reasons is strongly suggested to do parsing and filtering on "
     "Fluent Bit side, avoid pipelines"
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_GENERATE_ID, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, generate_id),
     "When enabled, generate _id for outgoing records. This prevents duplicate "
     "records when retrying ES"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_WRITE_OPERATION, "create",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, write_operation) +
         offsetof(struct flb_es_sds_t, value),
     "Operation to use to write in bulk requests"
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_DROP_UNRECOVERABLE_RECORDS, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, drop_unrecoverable_records),
     "Drop records rejected by non-retryable bulk 4xx errors; may cause data loss"
    },
    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_ID_KEY, NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, id_key) +
         offsetof(struct flb_es_sds_t, value),
     "If set, _id will be the value of the key from incoming record."
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_REPLACE_DOTS, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, replace_dots),
     "When enabled, replace field name dots with underscore, required by Elasticsearch "
     "2.0-2.3."
    },

    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_CURRENT_TIME_INDEX, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, current_time_index),
     "Use current time for index generation instead of message record"
    },

    /* Trace */
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_TRACE_OUTPUT, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, trace_output),
     "When enabled print the Elasticsearch API calls to stdout (for diag only)"
    },
    {
     FLB_CONFIG_MAP_BOOL, FLB_ES_CONFIG_PROPERTY_TRACE_ERROR, "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch_config, trace_error),
     "Log failed requests at debug and Elasticsearch responses at error level"
    },

    {
     FLB_CONFIG_MAP_STR, FLB_ES_CONFIG_PROPERTY_UPSTREAM, NULL,
     0, FLB_FALSE, 0,
     "Path to 'upstream' configuration file (define multiple nodes)"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_es_plugin = {
    .name           = "es",
    .description    = "Elasticsearch",
    .cb_init        = cb_es_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_es_flush,
    .cb_exit        = cb_es_exit,
    .workers        = 2,

    /* Configuration */
    .config_map     = config_map,

    /* Test */
    .test_formatter.callback = elasticsearch_format,
    .test_response.callback = elasticsearch_response_test,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
