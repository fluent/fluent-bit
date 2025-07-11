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
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <msgpack.h>

#include "datadog.h"
#include "datadog_conf.h"
#include "datadog_remap.h"

static int cb_datadog_init(struct flb_output_instance *ins,
                           struct flb_config *config, void *data)
{
    struct flb_out_datadog *ctx = NULL;
    (void) data;

    ctx = flb_datadog_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    return 0;
}

static int64_t timestamp_format(const struct flb_time* tms) {
    int64_t timestamp = 0;

    /* Format the time, use milliseconds precision not nanoseconds */
    timestamp = tms->tm.tv_sec * 1000;
    timestamp += tms->tm.tv_nsec / 1000000;

    /* round up if necessary */
    if (tms->tm.tv_nsec % 1000000 >= 500000) {
        ++timestamp;
    }
    return timestamp;
}

static void dd_msgpack_pack_key_value_str(msgpack_packer* mp_pck,
                                          const char *key, size_t key_size,
                                          const char *val, size_t val_size)
{
    msgpack_pack_str(mp_pck, key_size);
    msgpack_pack_str_body(mp_pck, key, key_size);
    msgpack_pack_str(mp_pck, val_size);
    msgpack_pack_str_body(mp_pck,val, val_size);
}

static int dd_compare_msgpack_obj_key_with_str(const msgpack_object obj, const char *key, size_t key_size) {

    if (obj.via.str.size == key_size && memcmp(obj.via.str.ptr,key, key_size) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int datadog_format(struct flb_config *config,
                          struct flb_input_instance *ins,
                          void *plugin_context,
                          void *flush_ctx,
                          int event_type,
                          const char *tag, int tag_len,
                          const void *data, size_t bytes,
                          void **out_data, size_t *out_size)
{
    int i;
    int ind;
    int byte_cnt = 64;
    int remap_cnt;
    int ret;
    /* for msgpack global structs */
    size_t array_size = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    /* for sub msgpack objs */
    int map_size;
    int64_t timestamp;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;
    struct flb_out_datadog *ctx = plugin_context;
    struct flb_event_chunk *event_chunk;

    /* output buffer */
    flb_sds_t out_buf;
    flb_sds_t remapped_tags = NULL;
    flb_sds_t tmp = NULL;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    /* in normal flush callback we have the event_chunk set as flush context
     * so we don't need to calculate the event len.
     * But in test mode the formatter won't get the event_chunk as flush_ctx
     */
    if (flush_ctx != NULL) {
        event_chunk = flush_ctx;
        array_size = event_chunk->total_events;
    } else {
        array_size = flb_mp_count(data, bytes);
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Prepare array for all entries */
    msgpack_pack_array(&mp_pck, array_size);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        timestamp = timestamp_format(&log_event.timestamp);

        map = *log_event.body;
        map_size = map.via.map.size;

        /*
         * msgpack requires knowing/allocating exact map size in advance, so we need to
         * loop through the map twice. First time here to count how many attr we can
         * remap to tags, and second time later where we actually perform the remapping.
         */
        remap_cnt = 0, byte_cnt = ctx->dd_tags ? flb_sds_len(ctx->dd_tags) : 0;
        if (ctx->remap) {
            for (i = 0; i < map_size; i++) {
                if (dd_attr_need_remapping(map.via.map.ptr[i].key,
                                           map.via.map.ptr[i].val) >= 0) {
                    remap_cnt++;
                    /*
                     * here we also *estimated* the size of buffer needed to hold the
                     * remapped tags. We can't know the size for sure until we do the
                     * remapping, the estimation here is just for efficiency, so that
                     * appending tags won't cause repeated resizing/copying
                     */
                    byte_cnt += 2 * (map.via.map.ptr[i].key.via.str.size +
                                     map.via.map.ptr[i].val.via.str.size);
                }
            }

            if (!remapped_tags) {
                remapped_tags = flb_sds_create_size(byte_cnt);
                if (!remapped_tags) {
                    flb_errno();
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return -1;
                }
            }
            else if (flb_sds_len(remapped_tags) < byte_cnt) {
                tmp = flb_sds_increase(remapped_tags, byte_cnt - flb_sds_len(remapped_tags));
                if (!tmp) {
                    flb_errno();
                    flb_sds_destroy(remapped_tags);
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return -1;
                }
                remapped_tags = tmp;
            }

            /*
             * we reuse this buffer across messages, which means we have to clear it
             * for each message flb_sds doesn't have a clear function, so we copy a
             * empty string to achieve the same effect
             */
            remapped_tags = flb_sds_copy(remapped_tags, "", 0);
        }

        /*
         * build new object(map) with additional space for datadog entries for those
         * remapped attributes, we need to remove them from the map. Note: If there were
         * no dd_tags specified AND there will be remapped attributes, we need to add 1
         * to account for the new presense of the dd_tags
         */
        if (remap_cnt && (ctx->dd_tags == NULL)) {
            msgpack_pack_map(&mp_pck,
                             ctx->nb_additional_entries + map_size + 1 - remap_cnt);
        }
        else {
            msgpack_pack_map(&mp_pck, ctx->nb_additional_entries + map_size - remap_cnt);
        }

        /* timestamp */
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->json_date_key));
        msgpack_pack_str_body(&mp_pck,
                              ctx->json_date_key,
                              flb_sds_len(ctx->json_date_key));
        msgpack_pack_int64(&mp_pck, timestamp);

        /* include_tag_key */
        if (ctx->include_tag_key == FLB_TRUE) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          ctx->tag_key, flb_sds_len(ctx->tag_key),
                                          tag, tag_len);
        }

        /* dd_source */
        if (ctx->dd_source != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_SOURCE_KEY,
                                          sizeof(FLB_DATADOG_DD_SOURCE_KEY) -1,
                                          ctx->dd_source, flb_sds_len(ctx->dd_source));
        }

        /* dd_service */
        if (ctx->dd_service != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_SERVICE_KEY,
                                          sizeof(FLB_DATADOG_DD_SERVICE_KEY) -1,
                                          ctx->dd_service, flb_sds_len(ctx->dd_service));
        }

        /* dd_hostname */
        if (ctx->dd_hostname != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_HOSTNAME_KEY,
                                          sizeof(FLB_DATADOG_DD_HOSTNAME_KEY) -1,
                                          ctx->dd_hostname, flb_sds_len(ctx->dd_hostname));
        }

        /* Append initial object k/v */
        ind = 0;
        for (i = 0; i < map_size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            /*
             * actually perform the remapping here. For matched attr, we remap and
             * append them to remapped_tags buffer, then skip the rest of processing
             * (so they won't be packed as attr)
             */
            if (ctx->remap && (ind = dd_attr_need_remapping(k, v)) >=0 ) {
                ret = remapping[ind].remap_to_tag(remapping[ind].remap_tag_name, v,
                                                  &remapped_tags);
                if (ret < 0) {
                    flb_plg_error(ctx->ins, "Failed to remap tag: %s, skipping", remapping[ind].remap_tag_name);
                }
                continue;
            }

            /* Mapping between input keys to specific datadog keys */
            if (dd_compare_msgpack_obj_key_with_str(k, ctx->dd_message_key,
                                                    flb_sds_len(ctx->dd_message_key)) == FLB_TRUE) {
                msgpack_pack_str(&mp_pck, sizeof(FLB_DATADOG_DD_MESSAGE_KEY)-1);
                msgpack_pack_str_body(&mp_pck, FLB_DATADOG_DD_MESSAGE_KEY,
                                      sizeof(FLB_DATADOG_DD_MESSAGE_KEY)-1);
            }
            else {
                msgpack_pack_object(&mp_pck, k);
            }

            msgpack_pack_object(&mp_pck, v);
        }

        /* here we concatenate ctx->dd_tags and remapped_tags, depending on their presence */
        if (remap_cnt) {
            if (ctx->dd_tags != NULL) {
                ret = flb_sds_cat_safe(&remapped_tags, FLB_DATADOG_TAG_SEPERATOR,
                                       strlen(FLB_DATADOG_TAG_SEPERATOR));
                if (ret < 0) {
                    flb_errno();
                    flb_sds_destroy(remapped_tags);
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return -1;
                }

                ret = flb_sds_cat_safe(&remapped_tags, ctx->dd_tags, strlen(ctx->dd_tags));
                if (ret < 0) {
                    flb_errno();
                    flb_sds_destroy(remapped_tags);
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return -1;
                }
            }
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_TAGS_KEY,
                                          sizeof(FLB_DATADOG_DD_TAGS_KEY) -1,
                                          remapped_tags, flb_sds_len(remapped_tags));
        }
        else if (ctx->dd_tags != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_TAGS_KEY,
                                          sizeof(FLB_DATADOG_DD_TAGS_KEY) -1,
                                          ctx->dd_tags, flb_sds_len(ctx->dd_tags));
        }
    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        if (remapped_tags) {
            flb_sds_destroy(remapped_tags);
        }
        flb_log_event_decoder_destroy(&log_decoder);
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    /* Cleanup */
    flb_log_event_decoder_destroy(&log_decoder);

    if (remapped_tags) {
        flb_sds_destroy(remapped_tags);
    }

    return 0;
}

static void cb_datadog_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    struct flb_out_datadog *ctx = out_context;
    struct flb_connection *upstream_conn;
    struct flb_http_client *client;
    void *out_buf;
    size_t out_size;
    flb_sds_t payload_buf;
    size_t payload_size = 0;
    void *final_payload_buf = NULL;
    size_t final_payload_size = 0;
    size_t b_sent;
    int ret = FLB_ERROR;
    int compressed = FLB_FALSE;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    /* Get upstream connection */
    upstream_conn = flb_upstream_conn_get(ctx->upstream);
    if (!upstream_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert input data into a Datadog JSON payload */
    ret = datadog_format(config, i_ins,
                         ctx, NULL,
                         event_chunk->type,
                         event_chunk->tag, flb_sds_len(event_chunk->tag),
                         event_chunk->data, event_chunk->size,
                         &out_buf, &out_size);
    if (ret == -1) {
        flb_upstream_conn_release(upstream_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    payload_buf = (flb_sds_t) out_buf;
    payload_size = out_size;

    /* Should we compress the payload ? */
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) payload_buf, payload_size,
                                &final_payload_buf, &final_payload_size);
        if (ret == -1) {
            flb_error("[out_http] cannot gzip payload, disabling compression");
        } else {
            compressed = FLB_TRUE;
        }
    } else {
        final_payload_buf = payload_buf;
        final_payload_size = payload_size;
    }

    /* Create HTTP client context */
    client = flb_http_client(upstream_conn, FLB_HTTP_POST, ctx->uri,
                             final_payload_buf, final_payload_size,
                             ctx->host, ctx->port,
                             ctx->proxy, 0);
    if (!client) {
        flb_upstream_conn_release(upstream_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Add the required headers to the URI */
    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(client, FLB_DATADOG_API_HDR, sizeof(FLB_DATADOG_API_HDR) - 1, ctx->api_key, flb_sds_len(ctx->api_key));
    flb_http_add_header(client, FLB_DATADOG_ORIGIN_HDR, sizeof(FLB_DATADOG_ORIGIN_HDR) - 1, "Fluent-Bit", 10);
    flb_http_add_header(client, FLB_DATADOG_ORIGIN_VERSION_HDR, sizeof(FLB_DATADOG_ORIGIN_VERSION_HDR) - 1, FLB_VERSION_STR, sizeof(FLB_VERSION_STR) - 1);
    flb_http_add_header(client,
                        FLB_DATADOG_CONTENT_TYPE, sizeof(FLB_DATADOG_CONTENT_TYPE) - 1,
                        FLB_DATADOG_MIME_JSON, sizeof(FLB_DATADOG_MIME_JSON) - 1);

    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(client);
    }

    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(client,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    /* finaly send the query */
    ret = flb_http_do(client, &b_sent);
    if (ret == 0) {
        if (client->resp.status < 200 || client->resp.status > 205) {
            flb_plg_error(ctx->ins, "%s%s:%i HTTP status=%i",
                          ctx->scheme, ctx->host, ctx->port,
                          client->resp.status);
            ret = FLB_RETRY;
        }
        else {
            if (client->resp.payload) {
                flb_plg_debug(ctx->ins, "%s%s, port=%i, HTTP status=%i payload=%s",
                             ctx->scheme, ctx->host, ctx->port,
                             client->resp.status, client->resp.payload);
            }
            else {
                flb_plg_debug(ctx->ins, "%s%s, port=%i, HTTP status=%i",
                             ctx->scheme, ctx->host, ctx->port,
                             client->resp.status);
            }
            ret = FLB_OK;
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);
        ret = FLB_RETRY;
    }

    /*
     * If the final_payload_buf buffer is different than payload_buf, means
     * we generated a different payload and must be freed.
     */
    if (final_payload_buf != payload_buf) {
        flb_free(final_payload_buf);
    }
    /* Destroy HTTP client context */
    flb_sds_destroy(payload_buf);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(upstream_conn);

    FLB_OUTPUT_RETURN(ret);
}


static int cb_datadog_exit(void *data, struct flb_config *config)
{
    struct flb_out_datadog *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_datadog_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "compress", "false",
     0, FLB_FALSE, 0,
     "compresses the payload in GZIP format, "
     "Datadog supports and recommends setting this to 'gzip'."
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_datadog, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },
    {
     FLB_CONFIG_MAP_STR, "apikey", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, api_key),
     "Datadog API key"
    },
    {
     FLB_CONFIG_MAP_STR, "dd_service", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, dd_service),
     "The human readable name for your service generating the logs  "
     "(e.g. the name of your application or database). If unset, Datadog "
     "will look for the service using Service Remapper in Log Management "
     "(by default it will look at the `service` and `syslog.appname` attributes)."
     ""
    },
    {
     FLB_CONFIG_MAP_STR, "dd_source", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, dd_source),
     "A human readable name for the underlying technology of your service "
     "(e.g. 'postgres' or 'nginx'). If unset, Datadog will expect the source "
     "to be set as the `ddsource` attribute."
    },
    {
     FLB_CONFIG_MAP_STR, "dd_tags", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, dd_tags),
     "The tags you want to assign to your logs in Datadog. If unset, Datadog "
     "will expect the tags in the `ddtags` attribute."
    },
    {
     FLB_CONFIG_MAP_STR, "dd_hostname", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, dd_hostname),
     "The host that emitted logs should be associated with. If unset, Datadog "
     "will expect the host to be set as `host`, `hostname`, or `syslog.hostname` "
     "attributes. See Datadog Logs preprocessor documentation for up-to-date "
     "recognized attributes."
    },

    {
     FLB_CONFIG_MAP_STR, "proxy", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, proxy),
     "Specify an HTTP Proxy. The expected format of this value is http://host:port. "
     "Note that https is not supported yet."
    },
    {
     FLB_CONFIG_MAP_BOOL, "include_tag_key", "false",
     0, FLB_TRUE, offsetof(struct flb_out_datadog, include_tag_key),
     "If enabled, tag is appended to output. "
     "The key name is used 'tag_key' property."
    },
    {
     FLB_CONFIG_MAP_STR, "tag_key", FLB_DATADOG_DEFAULT_TAG_KEY,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, tag_key),
     "The key name of tag. If 'include_tag_key' is false, "
     "This property is ignored"
    },
    {
     FLB_CONFIG_MAP_STR, "dd_message_key", FLB_DATADOG_DEFAULT_LOG_KEY,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, dd_message_key),
     "By default, the plugin searches for the key 'log' "
     "and remap the value to the key 'message'. "
     "If the property is set, the plugin will search the property name key."
    },
    {
     FLB_CONFIG_MAP_STR, "provider", NULL,
     0, FLB_FALSE, 0,
     "To activate the remapping, specify configuration flag provider with value 'ecs'"
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", FLB_DATADOG_DEFAULT_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_out_datadog, json_date_key),
     "Date key name for output."
    },
    {
    FLB_CONFIG_MAP_STR, "site", NULL, 0, FLB_FALSE, offsetof(struct flb_out_datadog, site),
    "DataDog site for telemetry data (e.g., 'datadoghq.eu', 'datadoghq.com', 'us3.datadoghq.com'). The plugin will construct the full hostname by prepending 'http-intake.logs.' to this value."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_datadog_plugin = {
    .name         = "datadog",
    .description  = "Send events to DataDog HTTP Event Collector",
    .cb_init      = cb_datadog_init,
    .cb_flush     = cb_datadog_flush,
    .cb_exit      = cb_datadog_exit,

    /* Test */
    .test_formatter.callback = datadog_format,

    /* Config map */
    .config_map   = config_map,

    /* Plugin flags */
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
