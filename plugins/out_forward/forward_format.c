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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "forward.h"

void flb_forward_format_bin_to_hex(uint8_t *buf, size_t len, char *out)
{
    int i;
    static char map[] = "0123456789abcdef";

	for (i = 0; i < len; i++) {
		out[i * 2]     = map[buf[i] >> 4];
        out[i * 2 + 1] = map[buf[i] & 0x0f];
	}
}

int flb_forward_format_append_tag(struct flb_forward *ctx,
                                  struct flb_forward_config *fc,
                                  msgpack_packer *mp_pck,
                                  msgpack_object *map,
                                  const char *tag, int tag_len)
{
#ifdef FLB_HAVE_RECORD_ACCESSOR
    flb_sds_t tmp;
    msgpack_object m;
    
    memset(&m, 0, sizeof(m));

    if (!fc->ra_tag) {
        msgpack_pack_str(mp_pck, tag_len);
        msgpack_pack_str_body(mp_pck, tag, tag_len);
        return 0;
    }

    if (map) {
        m = *map;
    }

    /* Tag */
    tmp = flb_ra_translate(fc->ra_tag, (char *) tag, tag_len, m, NULL);
    if (!tmp) {
        flb_plg_warn(ctx->ins, "Tag translation failed, using default Tag");
        msgpack_pack_str(mp_pck, tag_len);
        msgpack_pack_str_body(mp_pck, tag, tag_len);
    }
    else {
        msgpack_pack_str(mp_pck, flb_sds_len(tmp));
        msgpack_pack_str_body(mp_pck, tmp, flb_sds_len(tmp));
        flb_sds_destroy(tmp);
    }
#else
    msgpack_pack_str(mp_pck, tag_len);
    msgpack_pack_str_body(mp_pck, tag, tag_len);

#endif

    return 0;
}

static int append_options(struct flb_forward *ctx,
                          struct flb_forward_config *fc,
                          int event_type,
                          msgpack_packer *mp_pck,
                          int entries, void *data, size_t bytes,
                          msgpack_object *metadata,
                          char *out_chunk)
{
    char *chunk = NULL;
    uint8_t checksum[64];
    int     result;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_mp_map_header mh;
    struct flb_slist_entry *eopt_key;
    struct flb_slist_entry *eopt_val;

    /* options is map, use the dynamic map type */
    flb_mp_map_header_init(&mh, mp_pck);

    if (fc->require_ack_response == FLB_TRUE) {
        /*
         * for ack we calculate  sha512 of context, take 16 bytes,
         * make 32 byte hex string of it
         */
        result = flb_hash_simple(FLB_HASH_SHA512,
                                 data, bytes,
                                 checksum, sizeof(checksum));

        if (result != FLB_CRYPTO_SUCCESS) {
            return -1;
        }

        flb_forward_format_bin_to_hex(checksum, 16, out_chunk);

        out_chunk[32] = '\0';
        chunk = (char *) out_chunk;
    }

    /* "chunk": '<checksum-base-64>' */
    if (chunk) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 5);
        msgpack_pack_str_body(mp_pck, "chunk", 5);
        msgpack_pack_str(mp_pck, 32);
        msgpack_pack_str_body(mp_pck, out_chunk, 32);
    }

    /* "size": entries */
    if (entries > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "size", 4);
        msgpack_pack_int64(mp_pck, entries);
    }

    /* "compressed": "gzip" */
    if (entries > 0 &&                      /* not message mode */
        fc->time_as_integer == FLB_FALSE && /* not compat mode */
        fc->compress == COMPRESS_GZIP) {

        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "compressed", 10);
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "gzip", 4);
    }
    else if (fc->compress == COMPRESS_GZIP &&
             /* for metrics or traces, we're also able to send as
              * gzipped payloads */
             (event_type == FLB_EVENT_TYPE_METRICS ||
              event_type == FLB_EVENT_TYPE_TRACES)) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "compressed", 10);
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "gzip", 4);
    }

    /* event type (FLB_EVENT_TYPE_LOGS, FLB_EVENT_TYPE_METRICS, FLB_EVENT_TYPE_TRACES) */
    flb_mp_map_header_append(&mh);
    msgpack_pack_str(mp_pck, 13);
    msgpack_pack_str_body(mp_pck, "fluent_signal", 13);
    msgpack_pack_int64(mp_pck, event_type);

    /* process 'extra_option(s)' */
    if (fc->extra_options) {
        flb_config_map_foreach(head, mv, fc->extra_options) {
            eopt_key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
            eopt_val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

            flb_mp_map_header_append(&mh);
            msgpack_pack_str(mp_pck, flb_sds_len(eopt_key->str));
            msgpack_pack_str_body(mp_pck, eopt_key->str, flb_sds_len(eopt_key->str));
            msgpack_pack_str(mp_pck, flb_sds_len(eopt_val->str));
            msgpack_pack_str_body(mp_pck, eopt_val->str, flb_sds_len(eopt_val->str));
        }
    }

    if (metadata != NULL &&
        metadata->type == MSGPACK_OBJECT_MAP &&
        metadata->via.map.size > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str_with_body(mp_pck, "metadata", 8);
        msgpack_pack_object(mp_pck, *metadata);
    }

    flb_mp_map_header_end(&mh);

    flb_plg_debug(ctx->ins,
                  "send options records=%d chunk='%s'",
                  entries, out_chunk ? out_chunk : "NULL");
    return 0;
}

#ifdef FLB_HAVE_RECORD_ACCESSOR
/*
 * Forward Protocol: Message Mode
 * ------------------------------
 * This mode is only used if the Tag is dynamically composed using some
 * content of the records.
 *
 *  [
 *    "TAG",
 *    TIMESTAMP,
 *    RECORD/MAP,
 *    *OPTIONS*
 *  ]
 *
 */
static int flb_forward_format_message_mode(struct flb_forward *ctx,
                                           struct flb_forward_config *fc,
                                           struct flb_forward_flush *ff,
                                           const char *tag, int tag_len,
                                           const void *data, size_t bytes,
                                           void **out_buf, size_t *out_size)
{
    int entries = 0;
    size_t pre = 0;
    size_t off = 0;
    size_t record_size;
    char *chunk;
    char chunk_buf[33];
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    struct flb_time tm;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    /*
     * Our only reason to use Message Mode is because the user wants to generate
     * dynamic Tags based on records content.
     */
    if (!fc->ra_tag) {
        return -1;
    }

    /*
     * if the case, we need to compose a new outgoing buffer instead
     * of use the original one.
     */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        flb_time_copy(&tm, &log_event.timestamp);

        /* Prepare main array: tag, timestamp and record/map */
        msgpack_pack_array(&mp_pck, 4);

        /* Generate dynamic Tag or use default one */
        flb_forward_format_append_tag(ctx, fc, &mp_pck,
                                      log_event.body,
                                      tag, tag_len);

        /* Pack timestamp */
        if (fc->time_as_integer == FLB_TRUE) {
            flb_time_append_to_msgpack(&log_event.timestamp,
                                       &mp_pck,
                                       FLB_TIME_ETFMT_INT);
        }
        else {
            flb_time_append_to_msgpack(&log_event.timestamp,
                                       &mp_pck,
                                       FLB_TIME_ETFMT_V1_FIXEXT);
        }

        /* Pack records */
        msgpack_pack_object(&mp_pck, *log_event.body);

        record_size = off - pre;

        if (ff) {
            chunk = ff->checksum_hex;
        }
        else {
            chunk = chunk_buf;
        }

        append_options(ctx, fc, FLB_EVENT_TYPE_LOGS, &mp_pck, 0,
                       (char *) data + pre, record_size,
                       log_event.metadata,
                       chunk);

        pre = off;
        entries++;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return entries;
}
#endif

int flb_forward_format_transcode(
        struct flb_forward *ctx, int format,
        char *input_buffer, size_t input_length,
        char **output_buffer, size_t *output_length)
{
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event         log_event;
    int                          result;

    result = flb_log_event_decoder_init(&log_decoder, input_buffer, input_length);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", result);

        return -1;
    }

    result = flb_log_event_encoder_init(&log_encoder, format);

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", result);

        flb_log_event_decoder_destroy(&log_decoder);

        return -1;
    }

    while ((result = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        result = flb_log_event_encoder_begin_record(&log_encoder);

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_set_timestamp(
                        &log_encoder, &log_event.timestamp);
        }

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_set_metadata_from_msgpack_object(
                        &log_encoder,
                        log_event.metadata);
        }

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_set_body_from_msgpack_object(
                        &log_encoder,
                        log_event.body);
        }

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_commit_record(&log_encoder);
        }
    }

    if (log_encoder.output_length > 0) {
        *output_buffer = log_encoder.output_buffer;
        *output_length = log_encoder.output_length;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

        result = 0;
    }
    else {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %d", result);

        result = -1;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return result;
}

/*
 * Forward Protocol: Forward Mode
 * ------------------------------
 * In forward mode we don't format the serialized entries. We just compose
 * the outgoing 'options'.
 */
static int flb_forward_format_forward_mode(struct flb_forward *ctx,
                                           struct flb_forward_config *fc,
                                           struct flb_forward_flush *ff,
                                           int event_type,
                                           const char *tag, int tag_len,
                                           const void *data, size_t bytes,
                                           void **out_buf, size_t *out_size)
{
    int result;
    int entries = 0;
    char *chunk;
    char chunk_buf[33];
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    char *transcoded_buffer;
    size_t transcoded_length;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (ff) {
        chunk = ff->checksum_hex;
    }
    else {
        chunk = chunk_buf;
    }

    if (fc->send_options == FLB_TRUE || (event_type == FLB_EVENT_TYPE_METRICS || event_type == FLB_EVENT_TYPE_TRACES)) {
        if (event_type == FLB_EVENT_TYPE_LOGS) {
            entries = flb_mp_count(data, bytes);
        }
        else {
            /* for non logs, we don't count the number of entries */
            entries = 0;
        }

        if (!fc->fwd_retain_metadata && event_type == FLB_EVENT_TYPE_LOGS) {
            result = flb_forward_format_transcode(ctx, FLB_LOG_EVENT_FORMAT_FORWARD,
                                                  (char *) data, bytes,
                                                  &transcoded_buffer,
                                                  &transcoded_length);

            if (result == 0) {
                append_options(ctx, fc, event_type, &mp_pck, entries,
                               transcoded_buffer,
                               transcoded_length,
                               NULL, chunk);

                free(transcoded_buffer);
            }
        }
        else {
            append_options(ctx, fc, event_type, &mp_pck, entries, (char *) data, bytes, NULL, chunk);
        }
    }

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

/*
 * Forward Protocol: Forward Mode Compat (for Fluentd <= 0.12)
 * -----------------------------------------------------------
 * Use Forward mode but format the timestamp as integers
 *
 * note: yes, the function name it's a big long...
 */
static int flb_forward_format_forward_compat_mode(struct flb_forward *ctx,
                                                  struct flb_forward_config *fc,
                                                  struct flb_forward_flush *ff,
                                                  const char *tag, int tag_len,
                                                  const void *data, size_t bytes,
                                                  void **out_buf, size_t *out_size)
{
    int entries = 0;
    char *chunk;
    char chunk_buf[33];
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (ff) {
        chunk = ff->checksum_hex;
    }
    else {
        chunk = chunk_buf;
    }

    msgpack_pack_array(&mp_pck, fc->send_options ? 3 : 2);

    /* Tag */
    flb_forward_format_append_tag(ctx, fc, &mp_pck,
                                  NULL, tag, tag_len);

    /* Entries */
    entries = flb_mp_count(data, bytes);
    msgpack_pack_array(&mp_pck, entries);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        msgpack_pack_array(&mp_pck, 2);

        /* Pack timestamp */
        if (fc->time_as_integer == FLB_TRUE) {
            flb_time_append_to_msgpack(&log_event.timestamp,
                                       &mp_pck,
                                       FLB_TIME_ETFMT_INT);
        }
        else {
            flb_time_append_to_msgpack(&log_event.timestamp,
                                       &mp_pck,
                                       FLB_TIME_ETFMT_V1_FIXEXT);
        }

        /* Pack records */
        msgpack_pack_object(&mp_pck, *log_event.body);
    }

    if (fc->send_options == FLB_TRUE) {
        append_options(ctx, fc, FLB_EVENT_TYPE_LOGS, &mp_pck, entries,
                       (char *) data, bytes, NULL, chunk);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_forward_format(struct flb_config *config,
                       struct flb_input_instance *ins,
                       void *ins_ctx,
                       void *flush_ctx,
                       int event_type,
                       const char *tag, int tag_len,
                       const void *data, size_t bytes,
                       void **out_buf, size_t *out_size)
{
    int ret = 0;
    int mode = MODE_FORWARD;
    struct flb_upstream_node *node = NULL;
    struct flb_forward_config *fc;
    struct flb_forward_flush *ff = flush_ctx;
    struct flb_forward *ctx = ins_ctx;

    if (!flush_ctx) {
        fc = flb_forward_target(ctx, &node);
    }
    else {
        fc = ff->fc;
    }

    if (!fc) {
        flb_plg_error(ctx->ins, "cannot get an Upstream single or HA node");
        return -1;
    }

    if (event_type == FLB_EVENT_TYPE_METRICS) {
        mode = MODE_FORWARD;
        goto do_formatting;
    }
    else if (event_type == FLB_EVENT_TYPE_TRACES) {
        mode = MODE_FORWARD;
        goto do_formatting;
    }

#ifdef FLB_HAVE_RECORD_ACCESSOR
    /*
     * Based in the configuration, decide the preferred protocol mode
     */
    if (fc->ra_tag && fc->ra_static == FLB_FALSE) {
        /*
         * Dynamic tag per records needs to include the Tag for every entry,
         * if record accessor option has been enabled we jump into this
         * mode.
         */
        mode = MODE_MESSAGE;
    }
    else {
#endif
        /* Forward Modes */
        if (fc->time_as_integer == FLB_FALSE) {
            /*
             * In forward mode we optimize in memory allocation and we reuse the
             * original msgpack buffer. So we don't compose the outgoing buffer
             * and just let the caller handle it.
             */
            mode = MODE_FORWARD;
        }
        else if (fc->time_as_integer == FLB_TRUE) {
            /*
             * This option is similar to MODE_FORWARD but since we have to convert the
             * timestamp to integer type, we need to format the buffer (in the previous
             * case we avoid that step.
             */
            mode = MODE_FORWARD_COMPAT;
        }

#ifdef FLB_HAVE_RECORD_ACCESSOR
    }
#endif


do_formatting:

    /* Message Mode: the user needs custom Tags */
    if (mode == MODE_MESSAGE) {
#ifdef FLB_HAVE_RECORD_ACCESSOR
        ret = flb_forward_format_message_mode(ctx, fc, ff,
                                              tag, tag_len,
                                              data, bytes,
                                              out_buf, out_size);
#endif
    }
    else if (mode == MODE_FORWARD) {
        ret = flb_forward_format_forward_mode(ctx, fc, ff,
                                              event_type,
                                              tag, tag_len,
                                              data, bytes,
                                              out_buf, out_size);
    }
    else if (mode == MODE_FORWARD_COMPAT) {
        ret = flb_forward_format_forward_compat_mode(ctx, fc, ff,
                                                     tag, tag_len,
                                                     data, bytes,
                                                     out_buf, out_size);
    }

    if (ret == -1) {
        return -1;
    }

    return mode;
}
