/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *  Copyright (C) 2015-2016 Takeshi HASEGAWA
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
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <msgpack.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <termios.h>

#include "in_serial.h"
#include "in_serial_config.h"

static inline int process_line(const char *line, int len,
                               struct flb_in_serial_config *ctx)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("msg"),
                FLB_LOG_EVENT_STRING_VALUE(line, len));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    flb_debug("[in_serial] message '%s'", line);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = 0;
    }
    else {
        ret = -1;
    }

    return ret;
}

static inline int process_pack(struct flb_in_serial_config *ctx,
                               char *pack, size_t size)
{
    int ret;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object entry;

    ret = FLB_EVENT_ENCODER_SUCCESS;

    /* First pack the results, iterate concatenated messages */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        entry = result.data;

        ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("msg"),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&entry));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
        }
    }

    msgpack_unpacked_destroy(&result);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = 0;
    }
    else {
        ret = -1;
    }

    return ret;
}

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

/* Callback triggered when some serial msgs are available */
static int cb_serial_collect(struct flb_input_instance *in,
                             struct flb_config *config, void *in_context)
{
    int ret;
    int bytes = 0;
    int available;
    int len;
    int hits;
    char *sep;
    char *buf;
    struct flb_in_serial_config *ctx = in_context;

    flb_log_event_encoder_reset(ctx->log_encoder);

    ret = 0;

    while (1) {
        available = (sizeof(ctx->buf_data) -1) - ctx->buf_len;
        if (available > 1) {
            bytes = read(ctx->fd, ctx->buf_data + ctx->buf_len, available);

            if (bytes == -1) {
                if (errno == EPIPE || errno == EINTR) {
                    ret = -1;
                }
                else {
                    ret = 0;
                }

                break;
            }
            else if (bytes == 0) {
                ret = 0;

                break;
            }
        }
        ctx->buf_len += bytes;

        /* Always set a delimiter to avoid buffer trash */
        ctx->buf_data[ctx->buf_len] = '\0';

        /* Check if our buffer is full */
        if (ctx->buffer_id + 1 == SERIAL_BUFFER_SIZE) {
            ret = flb_engine_flush(config, &in_serial_plugin);
            if (ret == -1) {
                ctx->buffer_id = 0;
            }
        }

        sep = NULL;
        buf = ctx->buf_data;
        len = ctx->buf_len;
        hits = 0;

        /* Handle FTDI handshake */
        if (ctx->buf_data[0] == '\0') {
            consume_bytes(ctx->buf_data, 1, ctx->buf_len);
            ctx->buf_len--;
        }

        /* Strip CR or LF if found at first byte */
        if (ctx->buf_data[0] == '\r' || ctx->buf_data[0] == '\n') {
            /* Skip message with one byte with CR or LF */
            flb_trace("[in_serial] skip one byte message with ASCII code=%i",
                      ctx->buf_data[0]);
            consume_bytes(ctx->buf_data, 1, ctx->buf_len);
            ctx->buf_len--;
        }

        /* Handle the case when a Separator is set */
        if (ctx->separator) {
            while ((sep = strstr(ctx->buf_data, ctx->separator))) {
                len = (sep - ctx->buf_data);
                if (len > 0) {
                    /* process the line based in the separator position */
                    process_line(buf, len, ctx);
                    consume_bytes(ctx->buf_data, len + ctx->sep_len, ctx->buf_len);
                    ctx->buf_len -= (len + ctx->sep_len);
                    hits++;
                }
                else {
                    consume_bytes(ctx->buf_data, ctx->sep_len, ctx->buf_len);
                    ctx->buf_len -= ctx->sep_len;
                }
                ctx->buf_data[ctx->buf_len] = '\0';
            }

            if (hits == 0 && available <= 1) {
                flb_debug("[in_serial] no separator found, no more space");
                ctx->buf_len = 0;
                ret = 0;

                break;
            }
        }
        else if (ctx->format == FLB_SERIAL_FORMAT_JSON) {
            /* JSON Format handler */
            char *pack;
            int out_size;

            ret = flb_pack_json_state(ctx->buf_data, ctx->buf_len,
                                      &pack, &out_size, &ctx->pack_state);
            if (ret == FLB_ERR_JSON_PART) {
                flb_debug("[in_serial] JSON incomplete, waiting for more data...");

                ret = 0;

                break;
            }
            else if (ret == FLB_ERR_JSON_INVAL) {
                flb_debug("[in_serial] invalid JSON message, skipping");
                flb_pack_state_reset(&ctx->pack_state);
                flb_pack_state_init(&ctx->pack_state);
                ctx->pack_state.multiple = FLB_TRUE;

                ret = -1;

                break;
            }

            /*
             * Given the Tokens used for the packaged message, append
             * the records and then adjust buffer.
             */
            process_pack(ctx, pack, out_size);
            flb_free(pack);

            consume_bytes(ctx->buf_data, ctx->pack_state.last_byte, ctx->buf_len);
            ctx->buf_len -= ctx->pack_state.last_byte;
            ctx->buf_data[ctx->buf_len] = '\0';

            flb_pack_state_reset(&ctx->pack_state);
            flb_pack_state_init(&ctx->pack_state);
            ctx->pack_state.multiple = FLB_TRUE;
        }
        else {
            /* Process and enqueue the received line */
            process_line(ctx->buf_data, ctx->buf_len, ctx);
            ctx->buf_len = 0;
        }
    }

    if (ctx->log_encoder->output_length > 0) {
        flb_input_log_append(in, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    return ret;
}

/* Cleanup serial input */
static int cb_serial_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_serial_config *ctx = in_context;

    flb_trace("[in_serial] Restoring original termios...");
    tcsetattr(ctx->fd, TCSANOW, &ctx->tio_orig);

    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_pack_state_reset(&ctx->pack_state);
    flb_free(ctx);

    return 0;
}

/* Init serial input */
static int cb_serial_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int fd;
    int ret;
    int br;
    struct flb_in_serial_config *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_serial_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->format = FLB_SERIAL_FORMAT_NONE;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        flb_free(ctx);

        return -1;
    }

    if (!serial_config_read(ctx, in)) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    /* Initialize JSON pack state */
    if (ctx->format == FLB_SERIAL_FORMAT_JSON) {
        flb_pack_state_init(&ctx->pack_state);
        ctx->pack_state.multiple = FLB_TRUE;
    }

    /* Input instance */
    ctx->i_ins = in;

    /* set context */
    flb_input_set_context(in, ctx);

    /* open device */
    fd = open(ctx->file, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd == -1) {
        perror("open");
        flb_error("[in_serial] Could not open serial port device");
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }
    ctx->fd = fd;

    /* Store original settings */
    tcgetattr(fd, &ctx->tio_orig);

    /* Reset for new... */
    memset(&ctx->tio, 0, sizeof(ctx->tio));
    tcgetattr(fd, &ctx->tio);

    br = atoi(ctx->bitrate);
    cfsetospeed(&ctx->tio, (speed_t) flb_serial_speed(br));
    cfsetispeed(&ctx->tio, (speed_t) flb_serial_speed(br));

    /* Settings */
    ctx->tio.c_cflag     &=  ~PARENB;        /* 8N1 */
    ctx->tio.c_cflag     &=  ~CSTOPB;
    ctx->tio.c_cflag     &=  ~CSIZE;
    ctx->tio.c_cflag     |=  CS8;
    ctx->tio.c_cflag     &=  ~CRTSCTS;       /* No flow control */
    ctx->tio.c_cc[VMIN]   =  ctx->min_bytes; /* Min number of bytes to read  */
    ctx->tio.c_cflag     |=  CREAD | CLOCAL; /* Enable READ & ign ctrl lines */

    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &ctx->tio);

#if __linux__
    /* Set our collector based on a file descriptor event */
    ret = flb_input_set_collector_event(in,
                                        cb_serial_collect,
                                        ctx->fd,
                                        config);
#else
    /* Set our collector based on a timer event */
    ret = flb_input_set_collector_time(in,
                                       cb_serial_collect,
                                       IN_SERIAL_COLLECT_SEC,
                                       IN_SERIAL_COLLECT_NSEC,
                                       config);
#endif

    if (ret == -1) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
        return -1;
    }

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "file", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_serial_config, file),
     "Set the serial character device file name"
    },
    {
     FLB_CONFIG_MAP_STR, "bitrate", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_serial_config, bitrate),
     "Set the serial bitrate (baudrate)"
    },
    {
     FLB_CONFIG_MAP_STR, "separator", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_serial_config, separator),
     "Set the record separator"
    },
    {
     FLB_CONFIG_MAP_STR, "format", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_serial_config, format_str),
     "Set the serial format: json or none"
    },
    {
     FLB_CONFIG_MAP_INT, "min_bytes", "0",
     0, FLB_TRUE, offsetof(struct flb_in_serial_config, min_bytes),
     "Set the serial minimum bytes"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_serial_plugin = {
    .name         = "serial",
    .description  = "Serial input",
    .cb_init      = cb_serial_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_serial_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = cb_serial_exit,
    .config_map   = config_map,
};
