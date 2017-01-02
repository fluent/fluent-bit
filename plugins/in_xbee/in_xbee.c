/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>

#include <xbee.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <msgpack.h>

#include "in_xbee.h"
#include "in_xbee_iosampling.h"
#include "in_xbee_config.h"

/*
 * We need to declare the xbee_init() function here as for some reason the
 * libxbee-v3 on prepare.h file is not exporting the symbol or something
 * is wrong when linking.
 */
void xbee_init(void);

void in_xbee_flush_if_needed(struct flb_in_xbee_config *ctx)
{
    /* a caller should acquire mutex before calling this function */
    int ret;

    if (ctx->buffer_id + 1 >= FLB_XBEE_BUFFER_SIZE) {
        ret = flb_engine_flush(ctx->config, &in_xbee_plugin);
        if (ret == -1) {
            ctx->buffer_id = 0;
        }
    }
}

void in_xbee_rx_queue_raw(struct flb_in_xbee_config *ctx, const char *buf ,int len)
{
    /* Increase buffer position */

    pthread_mutex_lock(&ctx->mtx_mp);

    in_xbee_flush_if_needed(ctx);

    ctx->buffer_id++;

    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    msgpack_pack_map(&ctx->mp_pck, 1);
    msgpack_pack_bin(&ctx->mp_pck, 4);
    msgpack_pack_bin_body(&ctx->mp_pck, "data", 4);
    msgpack_pack_bin(&ctx->mp_pck, len);
    msgpack_pack_bin_body(&ctx->mp_pck, buf, len);

    pthread_mutex_unlock(&ctx->mtx_mp);
}

/*
 * This plugin accepts following formats of MessagePack:
 *     { map => val, map => val, map => val }
 *  or [ time, { map => val, map => val, map => val } ]
 */
int in_xbee_rx_queue_msgpack(struct flb_in_xbee_config *ctx, const char *buf ,int len)
{
    msgpack_unpacked record;
    msgpack_unpacked field;
    msgpack_unpacked_init(&record);
    msgpack_unpacked_init(&field);

    size_t off = 0;
    size_t start = 0;
    size_t off2;
    size_t mp_offset;
    int queued = 0;
    uint64_t t;

    pthread_mutex_lock(&ctx->mtx_mp);

    while (msgpack_unpack_next(&record, buf, len, &off)) {
        if (record.data.type == MSGPACK_OBJECT_ARRAY && record.data.via.array.size == 2) {
            /*  [ time, { map => val, map => val, map => val } ] */

            msgpack_unpacked_destroy(&field);
            msgpack_unpacked_init(&field);
            off2 = 0;

            if (! msgpack_unpack_next(&field, buf + 1, len - 1, &off2))
                break;

            if (field.data.type != MSGPACK_OBJECT_POSITIVE_INTEGER)
                break;

            t = field.data.via.u64;
            mp_offset = off2;

            if (! msgpack_unpack_next(&field, buf + 1, len - 1, &off2))
                break;

            if (field.data.type != MSGPACK_OBJECT_MAP)
                break;

            in_xbee_flush_if_needed(ctx);
            ctx->buffer_id++;

            msgpack_pack_array(&ctx->mp_pck, 2);
            msgpack_pack_uint64(&ctx->mp_pck, t);
            msgpack_pack_bin_body(&ctx->mp_pck, (char*) buf + 1 + mp_offset, off2 - mp_offset);

        } else if (record.data.type == MSGPACK_OBJECT_MAP) {
            /*  { map => val, map => val, map => val } */

            in_xbee_flush_if_needed(ctx);
            ctx->buffer_id++;

            msgpack_pack_array(&ctx->mp_pck, 2);
            msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
            msgpack_pack_bin_body(&ctx->mp_pck, buf + start, off - start);

        } else {
            break;

        }
        start = off;
        queued++;
    }

    msgpack_unpacked_destroy(&record);
    msgpack_unpacked_destroy(&field);
    pthread_mutex_unlock(&ctx->mtx_mp);
    return queued;
}

void in_xbee_cb(struct xbee *xbee, struct xbee_con *con,
                struct xbee_pkt **pkt, void **data)
{
    struct flb_in_xbee_config *ctx;

    if ((*pkt)->dataLen == 0) {
        flb_warn("xbee data length too short, skip");
        return;
    }

    ctx = *data;

#if 0
    int i;
    for (i = 0; i < (*pkt)->dataLen; i++) {
        printf("%2.2x ", *((unsigned char*) (*pkt)->data + i));
    }
    printf("\n");
#endif

    if (! in_xbee_rx_queue_msgpack(ctx, (const char*) (*pkt)->data, (*pkt)->dataLen)) {
        in_xbee_rx_queue_raw(ctx, (const char*) (*pkt)->data, (*pkt)->dataLen);
    }
}

void *in_xbee_flush(void *in_context, size_t *size)
{
    char *buf;
    msgpack_sbuffer *sbuf;
    struct flb_in_xbee_config *ctx = in_context;

    pthread_mutex_lock(&ctx->mtx_mp);

    if (ctx->buffer_id == 0) {
        goto fail;
    }

    sbuf = &ctx->mp_sbuf;
    *size = sbuf->size;
    buf = flb_malloc(sbuf->size);
    if (!buf) {
        goto fail;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    ctx->buffer_id = 0;

    pthread_mutex_unlock(&ctx->mtx_mp);
    return buf;

fail:
    pthread_mutex_unlock(&ctx->mtx_mp);
    return NULL;
}

/* Init xbee input */
int in_xbee_init(struct flb_input_instance *in,
                 struct flb_config *config, void *data)
{
    int ret;
    struct stat dev_st;
    struct xbee *xbee;
    struct xbee_conAddress address;
    struct flb_in_xbee_config *ctx;
    struct xbee_conSettings settings;
    (void) data;

    /* Prepare the configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_in_xbee_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    ret = xbee_config_read(in, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    flb_info("XBee device=%s, baudrate=%i", ctx->file, ctx->baudrate);

    ret = stat(ctx->file, &dev_st);
    if (ret < 0) {
        printf("Error: could not open %s device\n", ctx->file);
        flb_free(ctx->file);
        exit(EXIT_FAILURE);
    }

    if (!S_ISCHR(dev_st.st_mode)) {
        printf("Error: invalid device %s \n", ctx->file);
        flb_free(ctx->file);
        exit(EXIT_FAILURE);
    }

    if (access(ctx->file, R_OK | W_OK) == -1) {
        printf("Error: cannot open the device %s (permission denied ?)\n",
               ctx->file);
        flb_free(ctx->file);
        exit(EXIT_FAILURE);
    }

    ctx->config = config;
    pthread_mutex_init(&ctx->mtx_mp, NULL);
    ctx->buffer_len = 0;

    /* Init library */
    xbee_init();

    ret = xbee_setup(&xbee, ctx->xbeeMode, ctx->file, ctx->baudrate);
    if (ret != XBEE_ENONE) {
        flb_utils_error_c("xbee_setup");
        return ret;
    }

    /* 000000000000FFFF: broadcast address */
    memset(&address, 0, sizeof(address));
    address.addr64_enabled = 1;
    address.addr64[0] = 0x00;
    address.addr64[1] = 0x00;
    address.addr64[2] = 0x00;
    address.addr64[3] = 0x00;
    address.addr64[4] = 0x00;
    address.addr64[5] = 0x00;
    address.addr64[6] = 0xFF;
    address.addr64[7] = 0xFF;

    if (ctx->xbeeLogLevel >= 0)
        xbee_logLevelSet(xbee, ctx->xbeeLogLevel);

    /* Prepare a connection with the peer XBee */

    if ((ret = xbee_conNew(xbee, &ctx->con_data, "Data", &address)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
        return ret;
    }

    xbee_conSettings(ctx->con_data, NULL, &settings);
    settings.disableAck = ctx->xbeeDisableAck ? 1 : 0;
    settings.catchAll = ctx->xbeeCatchAll ? 1 : 0;
    xbee_conSettings(ctx->con_data, &settings, NULL);

    if ((ret = xbee_conDataSet(ctx->con_data, ctx, NULL)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conDataSet() returned: %d", ret);
        return ret;
    }

    if ((ret = xbee_conCallbackSet(ctx->con_data, in_xbee_cb, NULL)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
        return ret;
    }


    if ((ret = xbee_conNew(xbee, &ctx->con_io, "I/O", &address)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
        return ret;
    }

    xbee_conSettings(ctx->con_io, NULL, &settings);
    settings.disableAck = ctx->xbeeDisableAck ? 1 : 0;
    settings.catchAll = ctx->xbeeCatchAll ? 1 : 0;
    xbee_conSettings(ctx->con_io, &settings, NULL);

    if ((ret = xbee_conDataSet(ctx->con_io, ctx, NULL)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conDataSet() returned: %d", ret);
        return ret;
    }

    if ((ret = xbee_conCallbackSet(ctx->con_io, in_xbee_iosampling_cb, NULL)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
        return ret;
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_xbee_plugin = {
    .name         = "xbee",
    .description  = "XBee Device",
    .cb_init      = in_xbee_init,
    .cb_pre_run   = NULL,
    .cb_flush_buf = in_xbee_flush,
};
