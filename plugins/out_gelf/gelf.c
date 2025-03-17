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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "gelf.h"

#ifndef MSG_DONTWAIT
    #define MSG_DONTWAIT 0
#endif

#ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
#endif

/*
 * Version 1.1 (11/2013)
 * A GELF message is a GZIP’d or ZLIB’d JSON string with the following fields:
 *   version string (UTF-8) GELF spec version – “1.1”; MUST be set by client
 *     library.
 *   host string (UTF-8) the name of the host, source or application that sent
 *     this message; MUST be set by client library.
 *   short_message string (UTF-8) a short descriptive message; MUST be set by
 *      client library.
 *   full_message string (UTF-8) a long message that can i.e. contain a
 *      backtrace; optional.
 *   timestamp number Seconds since UNIX epoch with optional decimal places
 *      for milliseconds; SHOULD be set by client library. Will be set to NOW
 *      by server if absent.
 *   level number the level equal to the standard syslog levels; optional,
 *      default is 1 (ALERT).
 *   facility string (UTF-8) optional, deprecated. Send as additional field i
 *      instead.
 *   line number the line in a file that caused the error (decimal); optional,
 *      deprecated. Send as additional field instead.
 *   file string (UTF-8) the file (with path if you want) that caused the error
 *      (string); optional, deprecated. Send as additional field instead.
 *   _[additional field] string (UTF-8) or number every field you send and
 *       prefix with a _ (underscore) will be treated as an additional field.
 *       Allowed characters in field names are any word character (letter,
 *       number, underscore), dashes and dots. The verifying regular expression
 *       is: ^[\w\.\-]*$
 * Libraries SHOULD not allow to send id as additional field (_id). Graylog
 * server nodes omit this field automatically.
 */

/*
 * Generate a unique message ID. The upper 48-bit is milliseconds
 * since the Epoch, the lower 16-bit is a random nonce.
 */
static uint64_t message_id(void)
{
    uint64_t now;
    uint16_t nonce;
    struct flb_time tm;

    if (flb_time_get(&tm) != -1) {
        now = (uint64_t) tm.tm.tv_sec * 1000 + tm.tm.tv_nsec / 1000000;
    }
    else {
        now = (uint64_t) time(NULL) * 1000;
    }
    nonce = (uint16_t) rand();

    return (now << 16) | nonce;
}

/*
 * A GELF header is 12 bytes in size. It has the following
 * structure:
 *
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 * | MAGIC |           MESSAGE ID          |SEQ|NUM|
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 *
 * NUM is the total number of packets to send. SEQ is the
 * unique sequence number for each packet (zero-indexed).
 */
#define GELF_MAGIC "\x1e\x0f"
#define GELF_HEADER_SIZE 12

static void init_chunk_header(uint8_t *buf, int count)
{
    uint64_t msgid = message_id();

    memcpy(buf, GELF_MAGIC, 2);
    memcpy(buf + 2, &msgid, 8);
    buf[10] = 0;
    buf[11] = count;
}

/*
 * Chunked GELF
 * Prepend the following structure to your GELF message to make it chunked:
 *   Chunked GELF magic bytes 2 bytes 0x1e 0x0f
 *   Message ID 8 bytes Must be the same for every chunk of this message.
 *     Identifying the whole message and is used to reassemble the chunks later.
 *     Generate from millisecond timestamp + hostname for example.
 *   Sequence number 1 byte The sequence number of this chunk. Starting at 0
 *     and always less than the sequence count.
 *   Sequence count 1 byte Total number of chunks this message has.
 * All chunks MUST arrive within 5 seconds or the server will discard all
 * already arrived and still arriving chunks.
 * A message MUST NOT consist of more than 128 chunks.
 */
static int gelf_send_udp_chunked(struct flb_out_gelf_config *ctx, void *msg,
                                 size_t msg_size)
{
    int ret;
    uint8_t n;
    size_t chunks;
    size_t offset;
    size_t len;
    uint8_t *buf = (uint8_t *) ctx->pckt_buf;

    chunks = msg_size / ctx->pckt_size;
    if (msg_size % ctx->pckt_size != 0) {
        chunks++;
    }

    if (chunks > 128) {
        flb_plg_error(ctx->ins, "message too big: %zd bytes", msg_size);
        return -1;
    }

    init_chunk_header(buf, chunks);

    offset = 0;
    for (n = 0; n < chunks; n++) {
        buf[10] = n;

        len = msg_size - offset;
        if (ctx->pckt_size < len) {
            len = ctx->pckt_size;
        }
        memcpy(buf + GELF_HEADER_SIZE, (char *) msg + offset, len);

        ret = send(ctx->fd, buf, len + GELF_HEADER_SIZE,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
        if (ret == -1) {
            flb_errno();
        }
        offset += ctx->pckt_size;
    }
    return 0;
}

static int gelf_send_udp_pckt (struct flb_out_gelf_config *ctx, char *msg,
                               size_t msg_size)
{
    int ret;

    if (msg_size > ctx->pckt_size) {
        gelf_send_udp_chunked(ctx, msg, msg_size);
    }
    else {
        ret = send(ctx->fd, msg, msg_size, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (ret == -1) {
            flb_errno();
            return -1;
        }
    }

    return 0;
}

static int gelf_send_udp(struct flb_out_gelf_config *ctx, char *msg,
                         size_t msg_size)
{
    int ret;
    int status;
    void *zdata;
    size_t zdata_len;

    if (ctx->compress == FLB_TRUE || (msg_size > ctx->pckt_size)) {
        ret = flb_gzip_compress(msg, msg_size, &zdata, &zdata_len);
        if (ret != 0) {
            return -1;
        }

        status = gelf_send_udp_pckt (ctx, zdata, zdata_len);
        flb_free(zdata);
        if (status < 0) {
            return status;
        }
    }
    else {
        status = send(ctx->fd, msg, msg_size, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (status < 0) {
            return status;
        }
    }

    return 0;
}

static int inject_tag(msgpack_object *map,
                      struct flb_event_chunk *event_chunk,
                      struct flb_out_gelf_config *ctx,
                      char** out_buf, int* out_size)
{
    int i;
    int len;
    size_t map_num;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;

    len = map->via.map.size;
    map_num = 1 + len;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pck, map_num);

    for (i = 0; i < len; i++) {
        msgpack_pack_object(&pck, map->via.map.ptr[i].key);
        msgpack_pack_object(&pck, map->via.map.ptr[i].val);
    }

    msgpack_pack_str(&pck, strlen(ctx->tag_key));
    msgpack_pack_str_body(&pck, ctx->tag_key, strlen(ctx->tag_key));
    msgpack_pack_str(&pck, flb_sds_len(event_chunk->tag));
    msgpack_pack_str_body(&pck, event_chunk->tag, flb_sds_len(event_chunk->tag));

    *out_buf = sbuf.data;
    *out_size = sbuf.size;

    return 0;
}

static void cb_gelf_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    flb_sds_t s;
    flb_sds_t tmp;
    size_t off = 0;
    size_t prev_off = 0;
    size_t size = 0;
    size_t bytes_sent;
    msgpack_object map;
    struct flb_connection *u_conn = NULL;
    struct flb_out_gelf_config *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    char *tag_injected_map;
    int injected_size;

    if (ctx->mode != FLB_GELF_UDP) {
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "no upstream connections available");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        if (ctx->mode != FLB_GELF_UDP) {
            flb_upstream_conn_release(u_conn);
        }

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder.offset;
        size = off - prev_off;
        prev_off = off;
        s = NULL;

        map = *log_event.body;

        if (ctx->tag_key) {
            ret = inject_tag(&map, event_chunk, ctx, &tag_injected_map, &injected_size);

            if (ret != 0) {
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            tmp = flb_msgpack_raw_to_gelf(tag_injected_map, injected_size, &log_event.timestamp,
                                          &(ctx->fields));
            flb_free(tag_injected_map);
        }
        else {
            size = (size * 1.4);
            s = flb_sds_create_size(size);
            if (s == NULL) {
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            tmp = flb_msgpack_to_gelf(&s, &map, &log_event.timestamp,
                                      &(ctx->fields));
        }
        if (tmp != NULL) {
            s = tmp;
            if (ctx->mode == FLB_GELF_UDP) {
                ret = gelf_send_udp(ctx, s, flb_sds_len(s));
                if (ret == -1) {
                    if (ctx->mode != FLB_GELF_UDP) {
                        flb_upstream_conn_release(u_conn);
                    }

                    flb_log_event_decoder_destroy(&log_decoder);

                    flb_sds_destroy(s);

                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }
            }
            else {
                /* write gelf json plus \0 */
                ret = flb_io_net_write(u_conn,
                                       s, flb_sds_len(s) + 1, &bytes_sent);
                if (ret == -1) {
                    flb_errno();

                    if (ctx->mode != FLB_GELF_UDP) {
                        flb_upstream_conn_release(u_conn);
                    }

                    flb_log_event_decoder_destroy(&log_decoder);

                    flb_sds_destroy(s);

                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }
            }
        }
        else {
            flb_plg_error(ctx->ins, "error encoding to GELF");
        }

        flb_sds_destroy(s);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    if (ctx->mode != FLB_GELF_UDP) {
        flb_upstream_conn_release(u_conn);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_gelf_init(struct flb_output_instance *ins, struct flb_config *config,
                        void *data)
{
    int ret;
    const char *tmp;
    struct flb_out_gelf_config *ctx = NULL;

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 12201, ins);

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_gelf_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "flb_output_config_map_set failed");
        flb_free(ctx);
        return -1;
    }

    /* Config Mode */
    tmp = flb_output_get_property("mode", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "tcp")) {
            ctx->mode = FLB_GELF_TCP;
        }
        else if (!strcasecmp(tmp, "tls")) {
            ctx->mode = FLB_GELF_TLS;
        }
        else if (!strcasecmp(tmp, "udp")) {
            ctx->mode = FLB_GELF_UDP;
        }
        else {
            flb_plg_error(ctx->ins, "Unknown gelf mode %s", tmp);
            flb_free(ctx);
            return -1;
        }
    }
    else {
        ctx->mode = FLB_GELF_UDP;
    }

    /* Config Gelf_Timestamp_Key */
    tmp = flb_output_get_property("gelf_timestamp_key", ins);
    if (tmp) {
        ctx->fields.timestamp_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Host_Key */
    tmp = flb_output_get_property("gelf_host_key", ins);
    if (tmp) {
        ctx->fields.host_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Short_Message_Key */
    tmp = flb_output_get_property("gelf_short_message_key", ins);
    if (tmp) {
        ctx->fields.short_message_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Full_Message_Key */
    tmp = flb_output_get_property("gelf_full_message_key", ins);
    if (tmp) {
        ctx->fields.full_message_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Level_Key */
    tmp = flb_output_get_property("gelf_level_key", ins);
    if (tmp) {
        ctx->fields.level_key = flb_sds_create(tmp);
    }

    /* init random seed */
    if (flb_random_bytes((unsigned char *) &ctx->seed, sizeof(int))) {
        ctx->seed = time(NULL);
    }
    srand(ctx->seed);

    ctx->fd = -1;
    ctx->pckt_buf = NULL;

    if (ctx->mode == FLB_GELF_UDP) {
        ctx->fd = flb_net_udp_connect(ins->host.name, ins->host.port,
                                      ins->net_setup.source_address);
        if (ctx->fd < 0) {
            flb_free(ctx);
            return -1;
        }
        ctx->pckt_buf = flb_malloc(GELF_HEADER_SIZE + ctx->pckt_size);
        if (ctx->pckt_buf == NULL) {
            flb_socket_close(ctx->fd);
            flb_free(ctx);
            return -1;
        }
    }
    else {
        int io_flags = FLB_IO_TCP;

        if (ctx->mode == FLB_GELF_TLS) {
            io_flags = FLB_IO_TLS;
        }

        if (ins->host.ipv6 == FLB_TRUE) {
            io_flags |= FLB_IO_IPV6;
        }

        ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                             io_flags, ins->tls);
        if (!(ctx->u)) {
            flb_free(ctx);
            return -1;
        }
        flb_output_upstream_set(ctx->u, ins);
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    return 0;
}

static int cb_gelf_exit(void *data, struct flb_config *config)
{
    struct flb_out_gelf_config *ctx = data;

    if (ctx == NULL) {
        return 0;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
    }

    flb_sds_destroy(ctx->fields.timestamp_key);
    flb_sds_destroy(ctx->fields.host_key);
    flb_sds_destroy(ctx->fields.short_message_key);
    flb_sds_destroy(ctx->fields.full_message_key);
    flb_sds_destroy(ctx->fields.level_key);

    flb_free(ctx->pckt_buf);
    flb_free(ctx);

    return 0;
}


static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "mode", "udp",
     0, FLB_FALSE, 0,
     "The protocol to use. 'tls', 'tcp' or 'udp'"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_gelf_config, tag_key),
     "Tag key name (Optional in GELF)"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_short_message_key", NULL,
     0, FLB_FALSE, 0,
     "A short descriptive message (MUST be set in GELF)"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_timestamp_key", NULL,
     0, FLB_FALSE, 0,
     "Timestamp key name (SHOULD be set in GELF)"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_host_key", NULL,
     0, FLB_FALSE, 0,
     "Key which its value is used as the name of the host,"
     "source or application that sent this message. (MUST be set in GELF) "
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_full_message_key", NULL,
     0, FLB_FALSE, 0,
     "Key to use as the long message that can i.e. contain a backtrace. "
     "(Optional in GELF)"
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_level_key", NULL,
     0, FLB_FALSE, 0,
     "Key to be used as the log level. "
     "Its value must be in standard syslog levels (between 0 and 7). "
     "(Optional in GELF)"
    },
    {
     FLB_CONFIG_MAP_INT, "packet_size", "1420",
     0, FLB_TRUE, offsetof(struct flb_out_gelf_config, pckt_size),
     "If transport protocol is udp, you can set the size of packets to be sent."
    },
    {
     FLB_CONFIG_MAP_BOOL, "compress", "true",
     0, FLB_TRUE, offsetof(struct flb_out_gelf_config, compress),
     "If transport protocol is udp, "
     "you can set this if you want your UDP packets to be compressed."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_gelf_plugin = {
    .name           = "gelf",
    .description    = "GELF Output",
    .cb_init        = cb_gelf_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_gelf_flush,
    .cb_exit        = cb_gelf_exit,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .config_map     = config_map
};
