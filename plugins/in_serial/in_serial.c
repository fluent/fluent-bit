/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2015 Takeshi HASEGAWA
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <inttypes.h>
#include <termios.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>

#include "in_serial.h"
#include "in_serial_config.h"

void *in_serial_flush(void *in_context, int *size)
{
    char *buf;
    msgpack_sbuffer *sbuf;
    struct flb_in_serial_config *ctx = in_context;

    if (ctx->buffer_id == 0)
        return NULL;

    sbuf = &ctx->mp_sbuf;
    *size = sbuf->size;
    buf = malloc(sbuf->size);
    if (!buf) {
        return NULL;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    ctx->buffer_id = 0;

    return buf;
}

static inline int process_line(char *line, struct flb_in_serial_config *ctx)
{
    int line_len;
    uint64_t val;
    char *p = line;
    char *end = NULL;
    char msg[1024];

    /* Increase buffer position */
    ctx->buffer_id++;

    errno = 0;
    val = strtol(p, &end, 10);
    if ((errno == ERANGE && (val == INT_MAX || val == INT_MIN))
        || (errno != 0 && val == 0)) {
        goto fail;
    }

    /* Now process the human readable message */

    line_len = strlen(p);
    strncpy(msg, p, line_len);
    msg[line_len] = '\0';

    /*
     * Store the new data into the MessagePack buffer,
     * we handle this as a list of maps.
     */
    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));

    msgpack_pack_map(&ctx->mp_pck, 1);
    msgpack_pack_bin(&ctx->mp_pck, 3);
    msgpack_pack_bin_body(&ctx->mp_pck, "msg", 3);
    msgpack_pack_bin(&ctx->mp_pck, line_len);
    msgpack_pack_bin_body(&ctx->mp_pck, p, line_len);

    flb_debug("[in_serial] '%s'",
              (const char *) msg);

    return 0;

 fail:
    ctx->buffer_id--;
    return -1;
}

/* Callback triggered when some serial msgs are available */
int in_serial_collect(struct flb_config *config, void *in_context)
{
    int ret;
    int bytes;
    char line[2024];
    struct flb_in_serial_config *ctx = in_context;

    bytes = read(ctx->fd, &line, sizeof(line) - 1);
    if (bytes == -1) {
        if (errno == -EPIPE) {
            return -1;
        }
        return 0;
    }
    /* Always set a delimiter to avoid buffer trash */
    line[bytes - 1] = '\0';

    /* Check if our buffer is full */
    if (ctx->buffer_id + 1 == SERIAL_BUFFER_SIZE) {
        ret = flb_engine_flush(config, &in_serial_plugin);
        if (ret == -1) {
            ctx->buffer_id = 0;
        }
    }

    /* Process and enqueue the received line */
    process_line(line, ctx);
    return 0;
}

/* Init serial input */
int in_serial_init(struct flb_config *config)
{
    int fd;
    int ret;
    struct flb_in_serial_config *ctx;

    ctx = calloc(1, sizeof(struct flb_in_serial_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    if (!config->file) {
        flb_utils_error_c("serial input plugin needs configuration file");
        return -1;
    }

    serial_config_read(ctx, config->file);

    /* set context */
    ret = flb_input_set_context("serial", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for"
                "serial input plugin");
    }

    if (ret == -1) {
        flb_utils_error_c("Could not set collector for serial input plugin");
    }

    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    tcgetattr(fd, &ctx->tio_orig);
    memset(&ctx->tio, 0, sizeof(ctx->tio));
    switch (atoi(ctx->bitrate)) {
        case 1200:
            ctx->tio.c_cflag = B1200;
            break;
        case 2400:
            ctx->tio.c_cflag = B2400;
            break;
        case 4800:
            ctx->tio.c_cflag = B4800;
            break;
        case 9600:
            ctx->tio.c_cflag = B9600;
            break;
        case 19200:
            ctx->tio.c_cflag = B19200;
            break;
        case 38400:
            ctx->tio.c_cflag = B38400;
            break;

#ifdef __LINUX__
        case 576000:
            ctx->tio.c_cflag = B576000;
            break;
        case 115200:
            ctx->tio.c_cflag = B115200;
            break;
#endif

        default:
            flb_utils_error_c("Invalid bitrate for serial plugin");
    }

    ctx->tio.c_cflag |= CRTSCTS | CS8 | CLOCAL | CREAD;
    ctx->tio.c_iflag = IGNPAR | IGNCR;
    ctx->tio.c_oflag = 0;
    ctx->tio.c_lflag = ICANON;

    /* open device */
    fd = open(ctx->file, O_RDWR | O_NOCTTY);
    if (fd == -1) {
        perror("open");
        flb_utils_error_c("Could not open serial port device");
    }
    ctx->fd = fd;

    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &ctx->tio);

    /* Set our collector based on a file descriptor event */
    ret = flb_input_set_collector_event("serial",
                                        in_serial_collect,
                                        ctx->fd,
                                        config);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_serial_plugin = {
    .name         = "serial",
    .description  = "Serial input",
    .cb_init      = in_serial_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_serial_collect,
    .cb_flush_buf = in_serial_flush
};
