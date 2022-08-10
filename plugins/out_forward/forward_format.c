/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_record_accessor.h>
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
                          msgpack_packer *mp_pck,
                          int entries, void *data, size_t bytes,
                          char *out_chunk)
{
    int opt_count = 0;
    char *chunk = NULL;
    uint8_t checksum[64];
    int     result;

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
        opt_count++;
    }

    if (entries > 0) {
        opt_count++;
    }

    if (entries > 0 &&                      /* not message mode */
        fc->time_as_integer == FLB_FALSE && /* not compat mode */
        fc->compress == COMPRESS_GZIP) {
        opt_count++;
    }

    /* options is map */
    msgpack_pack_map(mp_pck, opt_count);

    /* "chunk": '<checksum-base-64>' */
    if (chunk) {
        msgpack_pack_str(mp_pck, 5);
        msgpack_pack_str_body(mp_pck, "chunk", 5);
        msgpack_pack_str(mp_pck, 32);
        msgpack_pack_str_body(mp_pck, out_chunk, 32);
    }

    /* "size": entries */
    if (entries > 0) {
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "size", 4);
        msgpack_pack_int64(mp_pck, entries);
    }

    if (entries > 0 &&                      /* not message mode */
        fc->time_as_integer == FLB_FALSE && /* not compat mode */
        fc->compress == COMPRESS_GZIP) {
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "compressed", 10);
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "gzip", 4);
    }

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
 *    RECORD/MAP
 *  ]
 */
static int flb_forward_format_message_mode(struct flb_forward *ctx,
                                           struct flb_forward_config *fc,
                                           struct flb_forward_flush *ff,
                                           const char *tag, int tag_len,
                                           const void *data, size_t bytes,
                                           void **out_buf, size_t *out_size)
{
    int entries = 0;
    int ok = MSGPACK_UNPACK_SUCCESS;
    int s;
    size_t pre = 0;
    size_t off = 0;
    size_t record_size;
    char *chunk;
    char chunk_buf[33];
    msgpack_object   *mp_obj;
    msgpack_object   root;
    msgpack_object   ts;
    msgpack_object   *map;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    struct flb_time tm;

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
    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, data, bytes, &off) == ok) {
        root = result.data;

        ts = root.via.array.ptr[0];
        map = &root.via.array.ptr[1];

        /* Gather time */
        flb_time_pop_from_msgpack(&tm, &result, &mp_obj);

        /* Prepare main array: tag, timestamp and record/map */
        s = 3;
        if (fc->require_ack_response == FLB_TRUE) {
            s++;
        }
        msgpack_pack_array(&mp_pck, s);

        /* Generate dynamic Tag or use default one */
        flb_forward_format_append_tag(ctx, fc, &mp_pck, map, tag, tag_len);

        /* Pack timestamp */
        if (fc->time_as_integer == FLB_TRUE) {
            msgpack_pack_uint64(&mp_pck, tm.tm.tv_sec);
        }
        else {
            msgpack_pack_object(&mp_pck, ts);
        }

        /* Pack records */
        msgpack_pack_object(&mp_pck, *mp_obj);

        record_size = off - pre;

        if (ff) {
            chunk = ff->checksum_hex;
        }
        else {
            chunk = chunk_buf;
        }

        if (fc->require_ack_response == FLB_TRUE) {
            append_options(ctx, fc, &mp_pck, 0, (char *) data + pre, record_size,
                           chunk);
        }

        pre = off;
        entries++;
    }

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;
    msgpack_unpacked_destroy(&result);

    return entries;
}
#endif

static int flb_forward_format_metrics_mode(struct flb_forward *ctx,
                                           struct flb_forward_config *fc,
                                           struct flb_forward_flush *ff,
                                           const char *tag, int tag_len,
                                           const void *data, size_t bytes,
                                           void **out_buf, size_t *out_size)
{
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    struct flb_time tm;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 3);

    if (fc->tag) {
        msgpack_pack_str(&mp_pck, flb_sds_len(fc->tag));
        msgpack_pack_str_body(&mp_pck, fc->tag, flb_sds_len(fc->tag));
    }
    else {
        msgpack_pack_str(&mp_pck, tag_len);
        msgpack_pack_str_body(&mp_pck, tag, tag_len);
    }

    /* timestamp */
    flb_time_get(&tm);
    flb_time_append_to_msgpack(&tm, &mp_pck, 0);

    /* metrics */
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "cmetrics", 8);
    msgpack_pack_bin(&mp_pck, bytes);
    msgpack_pack_bin_body(&mp_pck, data, bytes);

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
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
                                           const char *tag, int tag_len,
                                           const void *data, size_t bytes,
                                           void **out_buf, size_t *out_size)
{
    int entries = 0;
    char *chunk;
    char chunk_buf[33];
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (ff) {
        chunk = ff->checksum_hex;
    }
    else {
        chunk = chunk_buf;
    }

    if (fc->send_options == FLB_TRUE) {
        entries = flb_mp_count(data, bytes);
        append_options(ctx, fc, &mp_pck, entries, (char *) data, bytes, chunk);
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
    int ok = MSGPACK_UNPACK_SUCCESS;
    size_t off = 0;
    char *chunk;
    char chunk_buf[33];
    msgpack_object   *mp_obj;
    msgpack_object   root;
    msgpack_object   ts;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    struct flb_time tm;

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
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == ok) {
        root = result.data;

        ts = root.via.array.ptr[0];

        msgpack_pack_array(&mp_pck, 2);

        /* Gather time */
        flb_time_pop_from_msgpack(&tm, &result, &mp_obj);

        /* Pack timestamp */
        if (fc->time_as_integer == FLB_TRUE) {
            msgpack_pack_uint64(&mp_pck, tm.tm.tv_sec);
        }
        else {
            msgpack_pack_object(&mp_pck, ts);
        }

        /* Pack records */
        msgpack_pack_object(&mp_pck, *mp_obj);
    }

    if (fc->send_options == FLB_TRUE) {
        append_options(ctx, fc, &mp_pck, entries, (char *) data, bytes, chunk);
    }

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_forward_format(struct flb_config *config,
                       struct flb_input_instance *ins,
                       void *ins_ctx,
                       void *flush_ctx,
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

    /* metric handling */
    if (flb_input_event_type_is_metric(ins)) {
        ret = flb_forward_format_metrics_mode(ctx, fc, ff,
                                              tag, tag_len,
                                              data, bytes,
                                              out_buf, out_size);
        if (ret != 0) {
            return -1;
        }

        return MODE_MESSAGE;
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
