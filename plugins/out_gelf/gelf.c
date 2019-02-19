/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_network.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <zlib.h>

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

struct flb_output_plugin out_gelf_plugin;

static int gelf_zlib_init (z_stream *stream)
{
    memset(stream, 0, sizeof(z_stream));
    stream->zalloc = Z_NULL;
    stream->zfree = Z_NULL;
    stream->opaque = Z_NULL;
    stream->data_type = Z_TEXT;

    if (deflateInit(stream, 6) != Z_OK) {
        flb_error("[out_gelf] error initialising zlib deflate");
        return -1;
    }
    return 0;
}

static int gelf_zlib_compress(z_stream *stream,
    void *msg, size_t msg_size, void *data, size_t data_size)
{
    int status;

    status = deflateReset(stream);
    if(status != Z_OK)
        return -1;

    stream->avail_in = msg_size;
    stream->next_in = msg;

    stream->avail_out = data_size;
    stream->next_out = data;

    if (deflate(stream, Z_FINISH) == Z_STREAM_ERROR) {
        flb_error("[out_gelf] error compressing with zlib deflate");
        return -1;
    }

    return (int) stream->total_out;
}

static void gelf_zlib_end(z_stream *stream)
{
    deflateEnd(stream);
}

static int gelf_send_udp_chunked (struct flb_out_gelf_config *ctx, void *msg,
                                  size_t msg_size)
{
    int ret;
    uint8_t header[12];
    uint8_t n;
    size_t chunks;
    size_t offset;
    struct flb_time tm;
    uint64_t messageid;
    struct msghdr msghdr;
    struct iovec iov[2];

    chunks = msg_size / ctx->pckt_size;
    if ((msg_size % ctx->pckt_size) != 0)
        chunks++;

    if (chunks > 128) {
        flb_error("[out_gelf] message too big: %zd bytes, too many chunks",
                  msg_size);
        return -1;
    }

    flb_time_get(&tm);

    messageid = ((uint64_t)(tm.tm.tv_nsec*1000000 + tm.tm.tv_nsec) << 32) |
                (uint64_t)rand_r(&(ctx->seed));

    header[0] = 0x1e;
    header[1] = 0x0f;
    memcpy (header+2, &messageid, 8);
    header[10] = chunks;

    iov[0].iov_base = header;
    iov[0].iov_len = 12;

    memset(&msghdr, 0, sizeof(struct msghdr));
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 2;

    offset = 0;
    for (n = 0; n < chunks; n++) {
        header[11] = n;

        iov[1].iov_base = msg + offset;
        if ((msg_size - offset) < ctx->pckt_size) {
            iov[1].iov_len = msg_size - offset;
        }
        else {
            iov[1].iov_len = ctx->pckt_size;
        }

        ret = sendmsg(ctx->fd, &msghdr, MSG_DONTWAIT | MSG_NOSIGNAL);
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
    int status;

    if (ctx->compress == FLB_TRUE || (msg_size > ctx->pckt_size)) {
        int size;
        size_t zdata_size = msg_size * 1.001 + 12;
        void *zdata;

        zdata = flb_malloc(zdata_size);
        if (zdata == NULL) {

          return -1;
        }

        size = gelf_zlib_compress(&(ctx->stream), msg, msg_size, zdata, zdata_size);
        if (size < 0) {
          flb_free(zdata);
          return size;
        }
        status = gelf_send_udp_pckt (ctx, zdata, size);
        if (status < 0) {
           flb_free(zdata);
           return status;
        }
        flb_free(zdata);
    }
    else {
      status = send(ctx->fd, msg, msg_size, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (status < 0) return status;
    }

  return 0;
}

void cb_gelf_flush(void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_input_instance *i_ins,
                   void *out_context,
                   struct flb_config *config)
{
    struct flb_out_gelf_config *ctx = out_context;
    flb_sds_t s;
    flb_sds_t tmp;
    msgpack_unpacked result;
    size_t off = 0;
    size_t prev_off = 0;
    size_t size = 0;
    size_t bytes_sent;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    struct flb_time tm;
    struct flb_upstream_conn *u_conn;
    int ret;

    if (ctx->mode != FLB_GELF_UDP) {
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_error("[out_gelf] no upstream connections available");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        size = off - prev_off;
        prev_off = off;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map = root.via.array.ptr[1];

        size = (size * 1.4);
        s = flb_sds_create_size(size);
        if (s == NULL) {
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        tmp = flb_msgpack_to_gelf(&s, &map, &tm, &(ctx->fields));
        if (tmp != NULL) {
            s = tmp;
            if (ctx->mode == FLB_GELF_UDP) {
                ret = gelf_send_udp(ctx, s, flb_sds_len(s));
                if (ret == -1) {
                    msgpack_unpacked_destroy(&result);
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
                    flb_upstream_conn_release(u_conn);
                    msgpack_unpacked_destroy(&result);
                    flb_sds_destroy(s);
                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }
            }
        }
        else {
            flb_error("[out_gelf] error encoding to GELF");
        }

        flb_sds_destroy(s);
    }

    msgpack_unpacked_destroy(&result);

    if (ctx->mode != FLB_GELF_UDP) {
        flb_upstream_conn_release(u_conn);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_gelf_init(struct flb_output_instance *ins, struct flb_config *config,
                 void *data)
{
    int ret;
    int fd;
    char *tmp;
    struct flb_out_gelf_config *ctx = NULL;


    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 12201;
    }

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_gelf_config));
    if (!ctx) {
        flb_errno();
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
            flb_error("[out_gelf] Unknown gelf mode %s", tmp);
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

    /* Config UDP Packet_Size */
    tmp = flb_output_get_property("packet_size", ins);
    if (tmp != NULL && atoi(tmp) >= 0) {
        ctx->pckt_size = atoi(tmp);
    }
    else {
        ctx->pckt_size = 1420;
    }

    /* Config UDP Compress */
    tmp = flb_output_get_property("compress", ins);
    if (tmp) {
        if (strcasecmp(tmp, "true") == 0 ||
            strcasecmp(tmp, "on") == 0) {
            ctx->compress = FLB_TRUE;
        }
        else if (strcasecmp(tmp, "false") == 0 ||
                 strcasecmp(tmp, "off") == 0) {
            ctx->compress = FLB_FALSE;
        }
    }
    else {
        ctx->compress = FLB_TRUE;
    }

    ret = gelf_zlib_init(&(ctx->stream));
    if (ret < 0) return ret;

    /* init random seed */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        ctx->seed = time(NULL);
    }
    else {
        unsigned int val;
        ret = read(fd, &val, sizeof(val));
        if (ret > 0) {
            ctx->seed = val;
        }
        else {
            ctx->seed = time(NULL);
        }
        close(fd);
    }

    ctx->fd = -1;
    if (ctx->mode == FLB_GELF_UDP) {
        ctx->fd = flb_net_udp_connect(ins->host.name, ins->host.port);
        if (ctx->fd < 0) {
            flb_free(ctx);
            return -1;
        }
    } else {
        int io_flags = FLB_IO_TCP;

        if (ctx->mode == FLB_GELF_TLS) {
            io_flags = FLB_IO_TLS;
        }

        if (ins->host.ipv6 == FLB_TRUE) {
            io_flags |= FLB_IO_IPV6;
        }

        ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                             io_flags, (void *) &ins->tls);
        if (!(ctx->u)) {
            flb_free(ctx);
            return -1;
        }
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    return 0;
}

int cb_gelf_exit(void *data, struct flb_config *config)
{
    struct flb_out_gelf_config *ctx = data;

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

    gelf_zlib_end(&(ctx->stream));

    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_gelf_plugin = {
    .name           = "gelf",
    .description    = "GELF Output",
    .cb_init        = cb_gelf_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_gelf_flush,
    .cb_exit        = cb_gelf_exit,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
