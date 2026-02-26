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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <msgpack.h>
#include "splunk.h"
#include "splunk_conf.h"

static int cb_splunk_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_splunk *ctx;

    ctx = flb_splunk_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
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

static msgpack_object *local_msgpack_map_lookup(
                            msgpack_object *map_object,
                            char *key)
{
    size_t              key_length;
    size_t              index;
    msgpack_object_map *map;

    if (key == NULL) {
        return NULL;
    }

    if (map_object == NULL) {
        return NULL;
    }

    if (map_object->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    map = &map_object->via.map;

    key_length = strlen(key);

    for (index = 0; index < map->size ; index++) {
        if (map->ptr[index].key.type == MSGPACK_OBJECT_STR) {
            if (map->ptr[index].key.via.str.size == key_length) {
                if (strncmp(map->ptr[index].key.via.str.ptr,
                            key,
                            key_length) == 0) {
                    return &map->ptr[index].val;
                }
            }
        }
    }

    return NULL;
}

static int local_msgpack_map_string_lookup(
                msgpack_object *map_object,
                char *key,
                char **value,
                size_t *value_size)
{
    msgpack_object *value_object;

    value_object = local_msgpack_map_lookup(map_object, key);

    if (value_object == NULL) {
        return -1;
    }

    if (value_object->type != MSGPACK_OBJECT_STR) {
        return -2;
    }

    *value = (char *) value_object->via.str.ptr;
    *value_size = value_object->via.str.size;

    return 0;
}

static int local_msgpack_map_string_extract(
                msgpack_object *map_object,
                char *key,
                char *output_buffer,
                size_t output_buffer_size)
{
    size_t value_size;
    int    result;
    char  *value;

    result = local_msgpack_map_string_lookup(map_object,
                                             key,
                                             &value,
                                             &value_size);

    if (result != 0) {
        return -1;
    }

    if (value_size >= output_buffer_size) {
        return -2;
    }

    strncpy(output_buffer,
            value,
            value_size);

    output_buffer[value_size] = '\0';

    return 0;
}

static inline void local_msgpack_pack_cstr(msgpack_packer *packer, char *value)
{
    msgpack_pack_str(packer, strlen(value));
    msgpack_pack_str_body(packer, value, strlen(value));
}

static int pack_otel_data(struct flb_splunk *ctx,
                          msgpack_packer *mp_pck,
                          struct flb_mp_map_header *mh_pck,
                          msgpack_object *group_metadata,
                          msgpack_object *group_attributes,
                          msgpack_object *record_attributes)
{
    msgpack_object          *source_map;
    char                     schema[8];
    int                      result;
    int                      source_map_resource_attributes = FLB_FALSE;
    struct flb_mp_map_header mh_tmp;
    msgpack_object          *value;
    size_t                   index;

    result = local_msgpack_map_string_extract(group_metadata,
                                              "schema",
                                              schema,
                                              sizeof(schema));

    if (result != 0) {
        return 0;
    }

    if (strcmp(schema, "otlp") != 0) {
        return 0;
    }

    source_map  = local_msgpack_map_lookup(group_attributes, "resource");
    if (source_map != NULL) {
        source_map  = local_msgpack_map_lookup(source_map, "attributes");

        if (source_map != NULL) {
            source_map_resource_attributes = FLB_TRUE;
            value = local_msgpack_map_lookup(source_map, "host.name");

            if (value != NULL) {
                flb_mp_map_header_append(mh_pck);
                local_msgpack_pack_cstr(mp_pck, "host");
                msgpack_pack_object(mp_pck, *value);
            }
        }
    }

    flb_mp_map_header_append(mh_pck);
    local_msgpack_pack_cstr(mp_pck, "fields");
    flb_mp_map_header_init(&mh_tmp, mp_pck);

    /* check if we have resource attributes to pack */
    if (source_map_resource_attributes == FLB_TRUE) {
        for (index = 0; index < source_map->via.map.size ; index++) {
            flb_mp_map_header_append(&mh_tmp);
            msgpack_pack_object(mp_pck, source_map->via.map.ptr[index].key);
            msgpack_pack_object(mp_pck, source_map->via.map.ptr[index].val);
        }
    }

    source_map  = local_msgpack_map_lookup(record_attributes, "otlp");

    if (source_map != NULL) {
        value = local_msgpack_map_lookup(source_map,
                                         "severity_number");

        if (value != NULL &&
            (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
             value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER)) {
            flb_mp_map_header_append(&mh_tmp);

            local_msgpack_pack_cstr(mp_pck, "otel.log.severity.number");

            msgpack_pack_object(mp_pck, *value);
        }

        value = local_msgpack_map_lookup(source_map,
                                         "severity_text");

        if (value != NULL &&
            value->type == MSGPACK_OBJECT_STR) {
            flb_mp_map_header_append(&mh_tmp);
            local_msgpack_pack_cstr(mp_pck, "otel.log.severity.text");

            msgpack_pack_object(mp_pck, *value);
        }

        source_map  = local_msgpack_map_lookup(source_map, "attributes");

        if (source_map != NULL &&
            source_map->type == MSGPACK_OBJECT_MAP) {

            for (index = 0; index < source_map->via.map.size ; index++) {
                flb_mp_map_header_append(&mh_tmp);

                msgpack_pack_object(mp_pck, source_map->via.map.ptr[index].key);
                msgpack_pack_object(mp_pck, source_map->via.map.ptr[index].val);
            }
        }
    }

    flb_mp_map_header_end(&mh_tmp);

    return 0;
}

static int pack_map_meta(struct flb_splunk *ctx,
                         struct flb_mp_map_header *mh,
                         msgpack_packer *mp_pck,
                         msgpack_object map,
                         char *tag, int tag_len)
{
    int index_key_set = FLB_FALSE;
    int sourcetype_key_set = FLB_FALSE;
    flb_sds_t str;
    struct mk_list *head;
    struct flb_splunk_field *f;
    struct flb_mp_map_header mh_fields;
    struct flb_ra_value *rval;

    /* event host */
    if (ctx->event_host) {
        str = flb_ra_translate(ctx->ra_event_host, tag, tag_len,
                               map, NULL);
        if (str) {
            if (flb_sds_len(str) > 0) {
                flb_mp_map_header_append(mh);
                msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_HOST) -1);
                msgpack_pack_str_body(mp_pck,
                                      FLB_SPLUNK_DEFAULT_EVENT_HOST,
                                      sizeof(FLB_SPLUNK_DEFAULT_EVENT_HOST) - 1);
                msgpack_pack_str(mp_pck, flb_sds_len(str));
                msgpack_pack_str_body(mp_pck, str, flb_sds_len(str));
            }
            flb_sds_destroy(str);
        }
    }

    /* event source */
    if (ctx->event_source) {
        str = flb_ra_translate(ctx->ra_event_source, tag, tag_len,
                               map, NULL);
        if (str) {
            if (flb_sds_len(str) > 0) {
                flb_mp_map_header_append(mh);
                msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_SOURCE) -1);
                msgpack_pack_str_body(mp_pck,
                                      FLB_SPLUNK_DEFAULT_EVENT_SOURCE,
                                      sizeof(FLB_SPLUNK_DEFAULT_EVENT_SOURCE) - 1);
                msgpack_pack_str(mp_pck, flb_sds_len(str));
                msgpack_pack_str_body(mp_pck, str, flb_sds_len(str));
            }
            flb_sds_destroy(str);
        }
    }

    /* event sourcetype (key lookup) */
    if (ctx->event_sourcetype_key) {
        str = flb_ra_translate(ctx->ra_event_sourcetype_key, tag, tag_len,
                               map, NULL);
        if (str) {
            /* sourcetype_key was found */
            if (flb_sds_len(str) > 0) {
                flb_mp_map_header_append(mh);
                msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_SOURCET) -1);
                msgpack_pack_str_body(mp_pck,
                                      FLB_SPLUNK_DEFAULT_EVENT_SOURCET,
                                      sizeof(FLB_SPLUNK_DEFAULT_EVENT_SOURCET) - 1);
                msgpack_pack_str(mp_pck, flb_sds_len(str));
                msgpack_pack_str_body(mp_pck, str, flb_sds_len(str));
                sourcetype_key_set = FLB_TRUE;
            }
            flb_sds_destroy(str);
        }
        /* If not found, it will fallback to the value set in event_sourcetype */
    }

    if (sourcetype_key_set == FLB_FALSE && ctx->event_sourcetype) {
        flb_mp_map_header_append(mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_SOURCET) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_EVENT_SOURCET,
                              sizeof(FLB_SPLUNK_DEFAULT_EVENT_SOURCET) - 1);
        msgpack_pack_str(mp_pck, flb_sds_len(ctx->event_sourcetype));
        msgpack_pack_str_body(mp_pck,
                              ctx->event_sourcetype, flb_sds_len(ctx->event_sourcetype));
    }

    /* event index (key lookup) */
    if (ctx->event_index_key) {
        str = flb_ra_translate(ctx->ra_event_index_key, tag, tag_len,
                               map, NULL);
        if (str) {
            /* sourcetype_key was found */
            if (flb_sds_len(str) > 0) {
                flb_mp_map_header_append(mh);
                msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_INDEX) -1);
                msgpack_pack_str_body(mp_pck,
                                      FLB_SPLUNK_DEFAULT_EVENT_INDEX,
                                      sizeof(FLB_SPLUNK_DEFAULT_EVENT_INDEX) - 1);
                msgpack_pack_str(mp_pck, flb_sds_len(str));
                msgpack_pack_str_body(mp_pck, str, flb_sds_len(str));
                index_key_set = FLB_TRUE;
            }
            flb_sds_destroy(str);
        }
        /* If not found, it will fallback to the value set in event_index */
    }

    if (index_key_set == FLB_FALSE && ctx->event_index) {
        flb_mp_map_header_append(mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_INDEX) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_EVENT_INDEX,
                              sizeof(FLB_SPLUNK_DEFAULT_EVENT_INDEX) - 1);
        msgpack_pack_str(mp_pck, flb_sds_len(ctx->event_index));
        msgpack_pack_str_body(mp_pck,
                              ctx->event_index, flb_sds_len(ctx->event_index));
    }

    /* event 'fields' */
    if (mk_list_size(&ctx->fields) > 0) {
        flb_mp_map_header_append(mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT_FIELDS) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_EVENT_FIELDS,
                              sizeof(FLB_SPLUNK_DEFAULT_EVENT_FIELDS) - 1);

        /* Pack map */
        flb_mp_map_header_init(&mh_fields, mp_pck);

        mk_list_foreach(head, &ctx->fields) {
            f = mk_list_entry(head, struct flb_splunk_field, _head);
            rval = flb_ra_get_value_object(f->ra, map);
            if (!rval) {
                continue;
            }

            flb_mp_map_header_append(&mh_fields);

            /* key */
            msgpack_pack_str(mp_pck, flb_sds_len(f->key_name));
            msgpack_pack_str_body(mp_pck, f->key_name, flb_sds_len(f->key_name));

            /* value */
            msgpack_pack_object(mp_pck, rval->o);
            flb_ra_key_value_destroy(rval);
        }
        flb_mp_map_header_end(&mh_fields);
    }

    return 0;
}

static int pack_map(struct flb_splunk *ctx, msgpack_packer *mp_pck,
                    struct flb_time *tm,
                    msgpack_object *group_metadata,
                    msgpack_object *group_attributes,
                    msgpack_object *record_attributes,
                    msgpack_object map,
                    char *tag,
                    int tag_len)
{
    int result;
    int i;
    double t;
    int map_size;
    msgpack_object k;
    msgpack_object v;
    struct flb_mp_map_header mh;

    t = flb_time_to_double(tm);
    map_size = map.via.map.size;

    if (ctx->splunk_send_raw == FLB_TRUE) {
        msgpack_pack_map(mp_pck, map_size /* all k/v */);
    }
    else {
        flb_mp_map_header_init(&mh, mp_pck);

        /* Append the time key */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_TIME) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_TIME,
                              sizeof(FLB_SPLUNK_DEFAULT_TIME) - 1);
        msgpack_pack_double(mp_pck, t);

        /* Pack Splunk metadata */
        pack_map_meta(ctx, &mh, mp_pck, map, tag, tag_len);

        /* Pack Otel specific metadata */

        result = pack_otel_data(ctx,
                                mp_pck,
                                &mh,
                                group_metadata,
                                group_attributes,
                                record_attributes);

        if (result != 0) {
            flb_plg_error(ctx->ins, "failed to pack otel data");
            return -1;
        }

        /* Add k/v pairs under the key 'event' instead of to the top level object */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_EVENT,
                              sizeof(FLB_SPLUNK_DEFAULT_EVENT) - 1);

        flb_mp_map_header_end(&mh);

        msgpack_pack_map(mp_pck, map_size);
    }

    /* Append k/v */
    for (i = 0; i < map_size; i++) {
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;

        msgpack_pack_object(mp_pck, k);
        msgpack_pack_object(mp_pck, v);
    }

    return 0;
}


static inline int pack_event_key(struct flb_splunk *ctx, msgpack_packer *mp_pck,
                                 struct flb_time *tm, msgpack_object map,
                                 char *tag, int tag_len)
{
    double t;
    struct flb_mp_map_header mh;
    flb_sds_t val;

    t = flb_time_to_double(tm);
    val = flb_ra_translate(ctx->ra_event_key, tag, tag_len, map, NULL);
    if (!val || flb_sds_len(val) == 0) {
        if (val != NULL) {
            flb_sds_destroy(val);
        }

        return -1;
    }

    if (ctx->splunk_send_raw == FLB_FALSE) {
        flb_mp_map_header_init(&mh, mp_pck);

        /* Append the time key */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_TIME) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_TIME,
                              sizeof(FLB_SPLUNK_DEFAULT_TIME) - 1);
        msgpack_pack_double(mp_pck, t);

        /* Pack Splunk metadata */
        pack_map_meta(ctx, &mh, mp_pck, map, tag, tag_len);

        /* Add k/v pairs under the key 'event' instead of to the top level object */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT) -1);
        msgpack_pack_str_body(mp_pck,
                              FLB_SPLUNK_DEFAULT_EVENT,
                              sizeof(FLB_SPLUNK_DEFAULT_EVENT) - 1);

        flb_mp_map_header_end(&mh);
    }

    msgpack_pack_str(mp_pck, flb_sds_len(val));
    msgpack_pack_str_body(mp_pck, val, flb_sds_len(val));
    flb_sds_destroy(val);

    return 0;
}

#ifdef FLB_HAVE_METRICS
static inline int splunk_metrics_format(struct flb_output_instance *ins,
                                         const void *in_buf, size_t in_bytes,
                                         char **out_buf, size_t *out_size,
                                         struct flb_splunk *ctx)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text;
    cfl_sds_t host;
    struct cmt *cmt = NULL;

    if (ctx->event_host != NULL) {
        host = ctx->event_host;
    }
    else {
        host = "localhost";
    }

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) in_buf, in_bytes, &off);
    if (ret != 0) {
        flb_plg_error(ins, "could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_splunk_hec_create(cmt, host, ctx->event_index, ctx->event_source, ctx->event_sourcetype);

    /* destroy cmt context */
    cmt_destroy(cmt);

    *out_buf = text;
    *out_size = flb_sds_len(text);

    return 0;
}
#endif


/* implements functionality to get auth_header from msgpack map (metadata) */
static flb_sds_t extract_hec_token(struct flb_splunk *ctx, msgpack_object map,
                                   char *tag, int tag_len)
{
    flb_sds_t hec_token;

    /* Extract HEC token (map which is from metadata lookup) */
    if (ctx->metadata_auth_key) {
        hec_token = flb_ra_translate(ctx->ra_metadata_auth_key, tag, tag_len,
                                     map, NULL);
        /*
         * record accessor translation can return an empty string buffer if the
         * translation was not successfull or the value was not found. We consider
         * a valid token any string which length is greater than 0.
         *
         * note: flb_ra_translate_check() is not used here because it will print
         * an error message if the translation fails:
         *
         * ref: https://github.com/fluent/fluent-bit/issues/8859
         */
        if (hec_token && flb_sds_len(hec_token) > 0) {
            return hec_token;
        }

        /* destroy empty string */
        if (hec_token) {
            flb_sds_destroy(hec_token);
        }

        flb_plg_debug(ctx->ins, "Could not find hec_token in metadata");
        return NULL;
    }

    flb_plg_debug(ctx->ins, "Could not find a record accessor definition of hec_token");
    return NULL;
}

static void set_metadata_auth_header(struct flb_splunk *ctx, flb_sds_t hec_token)
{
    pthread_mutex_lock(&ctx->mutex_hec_token);

    if (ctx->metadata_auth_header != NULL) {
        flb_sds_destroy(ctx->metadata_auth_header);
    }
    ctx->metadata_auth_header = hec_token;

    pthread_mutex_unlock(&ctx->mutex_hec_token);
}

static flb_sds_t get_metadata_auth_header(struct flb_splunk *ctx)
{
    flb_sds_t auth_header = NULL;

    pthread_mutex_lock(&ctx->mutex_hec_token);

    if (ctx->metadata_auth_header) {
        auth_header = flb_sds_create(ctx->metadata_auth_header);
    }

    pthread_mutex_unlock(&ctx->mutex_hec_token);

    return auth_header;
}

static inline int splunk_format(const void *in_buf, size_t in_bytes,
                                char *tag, int tag_len,
                                char **out_buf, size_t *out_size,
                                struct flb_splunk *ctx, struct flb_config *config)
{
    int ret;
    char *err;
    msgpack_object map;
    msgpack_object metadata;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    flb_sds_t tmp;
    flb_sds_t record;
    flb_sds_t json_out;
    flb_sds_t metadata_hec_token = NULL;

    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    json_out = flb_sds_create_size(in_bytes * 1.5);
    if (!json_out) {
        flb_errno();
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_buf, in_bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_sds_destroy(json_out);

        return -1;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        map = *log_event.body;
        metadata = *log_event.metadata;
        metadata_hec_token = extract_hec_token(ctx, metadata, tag, tag_len);

        if (metadata_hec_token != NULL) {
            /* Currently, in_splunk implementation permits to
             * specify only one splunk token per one instance.
             * So, it should be valid if storing only last value of
             * splunk token per one chunk. */
            set_metadata_auth_header(ctx, metadata_hec_token);
        }

        if (ctx->event_key) {
            /* Pack the value of a event key */
            ret = pack_event_key(ctx, &mp_pck, &log_event.timestamp, map, tag, tag_len);
            if (ret != 0) {
                /*
                 * if pack_event_key fails due to missing content in the
                 * record, we just warn the user and try to pack it
                 * as a normal map.
                 */
                ret = pack_map(ctx,
                               &mp_pck,
                               &log_event.timestamp,
                               log_event.group_metadata,
                               log_event.group_attributes,
                               log_event.metadata,
                               map,
                               tag,
                               tag_len);
            }
        }
        else {
            /* Pack as a map */
            ret = pack_map(ctx,
                           &mp_pck,
                           &log_event.timestamp,
                           log_event.group_metadata,
                           log_event.group_attributes,
                           log_event.metadata,
                           map,
                           tag,
                           tag_len);
        }

        /* Validate packaging */
        if (ret != 0) {
            /* Format invalid record */
            err = flb_msgpack_to_json_str(2048, &map, config->json_escape_unicode);
            if (err) {
                /* Print error and continue processing other records */
                flb_plg_warn(ctx->ins, "could not process or pack record: %s", err);
                msgpack_sbuffer_destroy(&mp_sbuf);
                flb_free(err);
            }
            continue;
        }

        /* Format as JSON */
        record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                             config->json_escape_unicode);
        if (!record) {
            flb_errno();
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_log_event_decoder_destroy(&log_decoder);
            flb_sds_destroy(json_out);
            return -1;
        }

        /* On raw mode, append a breakline to every record */
        if (ctx->splunk_send_raw) {
            tmp = flb_sds_cat(record, "\n", 1);
            if (tmp) {
                record = tmp;
            }
        }

        tmp = flb_sds_cat(json_out, record, flb_sds_len(record));
        flb_sds_destroy(record);
        if (tmp) {
            json_out = tmp;
        }
        else {
            flb_errno();
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_log_event_decoder_destroy(&log_decoder);
            flb_sds_destroy(json_out);
            return -1;
        }
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    *out_buf = json_out;
    *out_size = flb_sds_len(json_out);

    flb_log_event_decoder_destroy(&log_decoder);

    return 0;
}

static void debug_request_response(struct flb_splunk *ctx,
                                   struct flb_http_client *c)
{
    int ret;
    int uncompressed = FLB_FALSE;
    time_t now;
    void *tmp_buf = NULL;
    size_t tmp_size;
    size_t req_size;
    char *req_buf = NULL;
    struct tm result;
    struct tm *current;
    unsigned char *ptr;
    flb_sds_t req_headers = NULL;
    flb_sds_t req_body = NULL;

    if (c->body_len > 3) {
        ptr = (unsigned char *) c->body_buf;
        if (ptr[0] == 0x1F && ptr[1] == 0x8B && ptr[2] == 0x08) {
            /* uncompress payload */
            ret = flb_gzip_uncompress((void *) c->body_buf, c->body_len,
                                      &tmp_buf, &tmp_size);
            if (ret == -1) {
                fprintf(stdout, "[out_splunk] could not uncompress data\n");
            }
            else {
                req_buf = (char *) tmp_buf;
                req_size = tmp_size;
                uncompressed = FLB_TRUE;
            }
        }
        else {
            req_buf = (char *) c->body_buf;
            req_size = c->body_len;
        }

        /* create a safe buffer */
        if (req_buf) {
            req_body = flb_sds_create_len(req_buf, req_size);
        }
    }

    req_headers = flb_sds_create_len(c->header_buf, c->header_len);

    if (c->resp.data)
    now = time(NULL);
    current = localtime_r(&now, &result);

    fprintf(stdout,
            "[%i/%02i/%02i %02i:%02i:%02i] "
            "[out_splunk] debug HTTP 400 (bad request)\n"
            ">>> request\n"
            "%s%s\n\n"
            "<<< response\n"
            "%s\n\n",

            current->tm_year + 1900,
            current->tm_mon + 1,
            current->tm_mday,
            current->tm_hour,
            current->tm_min,
            current->tm_sec,

            req_headers,
            req_body,
            c->resp.data);

    if (uncompressed) {
        flb_free(tmp_buf);
    }

    if (req_headers) {
        flb_sds_destroy(req_headers);
    }
    if (req_body) {
        flb_sds_destroy(req_body);
    }
}

static void cb_splunk_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int ret;
    int compressed = FLB_FALSE;
    size_t b_sent;
    flb_sds_t buf_data;
    size_t resp_size;
    size_t buf_size;
    struct flb_splunk *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    void *payload_buf;
    size_t payload_size;
    (void) i_ins;
    (void) config;
    flb_sds_t metadata_auth_header = NULL;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

#ifdef FLB_HAVE_METRICS
    /* Check if the event type is metrics, handle the payload differently */
    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        ret = splunk_metrics_format(ctx->ins,
                              event_chunk->data,
                              event_chunk->size,
                              &buf_data, &buf_size, ctx);
    }
#endif
    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        /* Convert binary logs into a JSON payload */
        ret = splunk_format(event_chunk->data,
                            event_chunk->size,
                            (char *) event_chunk->tag,
                            flb_sds_len(event_chunk->tag),
                            &buf_data, &buf_size, ctx,
                            config);
    }

    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Map buffer */
    payload_buf = buf_data;
    payload_size = buf_size;

    /* Should we compress the payload ? */
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) buf_data, buf_size,
                                &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        }
        else {
            compressed = FLB_TRUE;

            /* JSON buffer is not longer needed */
            flb_sds_destroy(buf_data);
        }
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_SPLUNK_DEFAULT_ENDPOINT,
                        payload_buf, payload_size, NULL, 0, NULL, 0);

    /* HTTP Response buffer size, honor value set by the user */
    if (ctx->buffer_size > 0) {
        flb_http_buffer_size(c, ctx->buffer_size);
    }
    else {
        /*
         * If no value was set, we try to accomodate by using our post
         * payload size * 1.5, on that way we make room for large responses
         * if something goes wrong, so we don't get a partial response.
         */
        resp_size = payload_size * 1.5;
        if (resp_size < 4096) {
            resp_size = 4096;
        }
        flb_http_buffer_size(c, resp_size);
    }

    metadata_auth_header = get_metadata_auth_header(ctx);

    /* HTTP Client */
    flb_http_add_header(c,
                        FLB_HTTP_HEADER_USER_AGENT,
                        sizeof(FLB_HTTP_HEADER_USER_AGENT) - 1,
                        FLB_HTTP_HEADER_USER_AGENT_DEFAULT,
                        sizeof(FLB_HTTP_HEADER_USER_AGENT_DEFAULT) - 1);

    /*
     * Authentication mechanism & order:
     *
     * 1. use the configure `http_user` and `http_passwd`
     * 2. use metadata 'hec_token', if the records are generated by Splunk input plugin, this will be set.
     * 3. use the configured `splunk_token` (if set).
     */
    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }
    else if (ctx->auth_header) {
        flb_http_add_header(c, "Authorization", 13,
                            ctx->auth_header, flb_sds_len(ctx->auth_header));
    }
    else if (metadata_auth_header) {
        flb_http_add_header(c, "Authorization", 13,
                            metadata_auth_header,
                            flb_sds_len(metadata_auth_header));
    }

    /* Append Channel identifier header */
    if (ctx->channel) {
        flb_http_add_header(c, FLB_SPLUNK_CHANNEL_IDENTIFIER_HEADER,
                            strlen(FLB_SPLUNK_CHANNEL_IDENTIFIER_HEADER),
                            ctx->channel, ctx->channel_len);
    }

    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Map debug callbacks */
    flb_http_client_debug(c, ctx->ins->callback);

    /* Perform HTTP request */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        ret = FLB_RETRY;
    }
    else {
        if (c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "http_status=%i:\n%s",
                         c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "http_status=%i", c->resp.status);
            }
            /*
             * Requests that get 4xx responses from the Splunk HTTP Event
             * Collector will 'always' fail, so there is no point in retrying
             * them:
             *
             * https://docs.splunk.com/Documentation/Splunk/8.0.5/Data/TroubleshootHTTPEventCollector#Possible_error_codes
             * From trouble shoot document on Splunk secure gateway,
             * 408 and 429 should be also handled as try again:
             *
             * https://docs.splunk.com/Documentation/SecureGateway/3.5.15/Admin/TroubleshootGateway#Troubleshoot_error_codes
             */
            ret = (c->resp.status < 400 || c->resp.status >= 500 ||
                   c->resp.status == 408 || c->resp.status == 429) ?
                FLB_RETRY : FLB_ERROR;


            if (c->resp.status == 400 && ctx->http_debug_bad_request) {
                debug_request_response(ctx, c);
            }
        }
        else {
            ret = FLB_OK;
        }
    }

    /*
     * If the payload buffer is different than incoming records in body, means
     * we generated a different payload and must be freed.
     */
    if (compressed == FLB_TRUE) {
        flb_free(payload_buf);
    }
    else {
        flb_sds_destroy(buf_data);
    }

    if (metadata_auth_header) {
        flb_sds_destroy(metadata_auth_header);
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(ret);
}

static int cb_splunk_exit(void *data, struct flb_config *config)
{
    struct flb_splunk *ctx = data;

    flb_splunk_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression mechanism. Option available is 'gzip'"
    },

    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, http_user),
     "Set HTTP auth user"
    },

    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_splunk, http_passwd),
     "Set HTTP auth password"
    },

    {
     FLB_CONFIG_MAP_SIZE, "http_buffer_size", NULL,
     0, FLB_FALSE, 0,
     "Specify the buffer size used to read the response from the Splunk HTTP "
     "service. This option is useful for debugging purposes where is required to read "
     "full responses, note that response size grows depending of the number of records "
     "inserted. To set an unlimited amount of memory set this value to 'false', "
     "otherwise the value must be according to the Unit Size specification"
    },

    {
     FLB_CONFIG_MAP_BOOL, "http_debug_bad_request", "false",
     0, FLB_TRUE, offsetof(struct flb_splunk, http_debug_bad_request),
     "If the HTTP server response code is 400 (bad request) and this flag is "
     "enabled, it will print the full HTTP request and response to the stdout "
     "interface. This feature is available for debugging purposes."
    },

    {
     FLB_CONFIG_MAP_STR, "event_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_key),
     "Specify the key name that will be used to send a single value as part of the record."
    },

    {
     FLB_CONFIG_MAP_STR, "event_host", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_host),
     "Set the host value to the event data. The value allows a record accessor "
     "pattern."
    },

    {
     FLB_CONFIG_MAP_STR, "event_source", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_source),
     "Set the source value to assign to the event data."
    },

    {
     FLB_CONFIG_MAP_STR, "event_sourcetype", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_sourcetype),
     "Set the sourcetype value to assign to the event data."
    },

    {
     FLB_CONFIG_MAP_STR, "event_sourcetype_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_sourcetype_key),
     "Set a record key that will populate 'sourcetype'. If the key is found, it will "
     "have precedence over the value set in 'event_sourcetype'."
    },

    {
     FLB_CONFIG_MAP_STR, "event_index", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_index),
     "The name of the index by which the event data is to be indexed."
    },

    {
     FLB_CONFIG_MAP_STR, "event_index_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, event_index_key),
     "Set a record key that will populate the 'index' field. If the key is found, "
     "it will have precedence over the value set in 'event_index'."
    },

    {
     FLB_CONFIG_MAP_SLIST_2, "event_field", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_splunk, event_fields),
     "Set event fields for the record. This option can be set multiple times and "
     "the format is 'key_name record_accessor_pattern'."
    },

    {
     FLB_CONFIG_MAP_STR, "splunk_token", NULL,
     0, FLB_FALSE, 0,
     "Specify the Authentication Token for the HTTP Event Collector interface. "
     "If event metadata contains a splunk_token, it will be prioritized to use instead of this token."
    },

    {
     FLB_CONFIG_MAP_BOOL, "splunk_send_raw", "off",
     0, FLB_TRUE, offsetof(struct flb_splunk, splunk_send_raw),
     "When enabled, the record keys and values are set in the top level of the "
     "map instead of under the event key. Refer to the Sending Raw Events section "
     "from the docs for more details to make this option work properly."
    },

    {
     FLB_CONFIG_MAP_STR, "channel", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, channel),
     "Specify X-Splunk-Request-Channel Header for the HTTP Event Collector interface."
    },

    /* EOF */
    {0}
};


static int cb_splunk_format_test(struct flb_config *config,
                                 struct flb_input_instance *ins,
                                 void *plugin_context,
                                 void *flush_ctx,
                                 int event_type,
                                 const char *tag, int tag_len,
                                 const void *data, size_t bytes,
                                 void **out_data, size_t *out_size)
{
    struct flb_splunk *ctx = plugin_context;

    return splunk_format(data, bytes, (char *) tag, tag_len,
                         (char**) out_data, out_size, ctx, config);
}

struct flb_output_plugin out_splunk_plugin = {
    .name         = "splunk",
    .description  = "Send events to Splunk HTTP Event Collector",
    .cb_init      = cb_splunk_init,
    .cb_flush     = cb_splunk_flush,
    .cb_exit      = cb_splunk_exit,
    .config_map   = config_map,
    .workers      = 2,
#ifdef FLB_HAVE_METRICS
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
#endif

    /* for testing */
    .test_formatter.callback = cb_splunk_format_test,
    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
