/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>

#include <xbee.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <msgpack.h>

#include "in_xbee.h"
#include "in_xbee_config.h"

/*
 * We need to declare the xbee_init() function here as for some reason the
 * libxbee-v3 on prepare.h file is not exporting the symbol or something
 * is wrong when linking.
 */
void xbee_init(void);



void in_xbee_rx_queue_raw(struct flb_in_xbee_config *ctx, const char *buf ,int len)
{
    /* Increase buffer position */
    ctx->buffer_id++;

    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    msgpack_pack_map(&ctx->mp_pck, 1);
    msgpack_pack_bin(&ctx->mp_pck, 4);
    msgpack_pack_bin_body(&ctx->mp_pck, "data", 4);
    msgpack_pack_bin(&ctx->mp_pck, len);
    msgpack_pack_bin_body(&ctx->mp_pck, buf, len);
}


void in_xbee_rx_queue_msgpack(struct flb_in_xbee_config *ctx, const char *buf ,int len)
{
    /* Increase buffer position */
    ctx->buffer_id++;

    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    msgpack_pack_bin_body(&ctx->mp_pck, buf, len);
}

int in_xbee_rx_validate_msgpack(const char *buf, int len)
{
    msgpack_unpacked result;
    msgpack_unpacked_init(&result);

    size_t off = 0;
    if (! msgpack_unpack_next(&result, buf, len, &off)) {
        goto fail;
    }

    if (result.data.type != MSGPACK_OBJECT_MAP) {
        goto fail;
    }
    /* ToDo: validate msgpack length */

    /* can handle as MsgPack */

    msgpack_unpacked_destroy(&result);
    return 1;

fail:
    msgpack_unpacked_destroy(&result);
    return 0;
}

void in_xbee_cb(struct xbee *xbee, struct xbee_con *con,
                struct xbee_pkt **pkt, void **data)
{
    struct flb_in_xbee_config *ctx;
    int ret;

    if ((*pkt)->dataLen == 0) {
        flb_debug("xbee data length too short, skip");
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

    if (ctx->buffer_id + 1 >= FLB_XBEE_BUFFER_SIZE) {
        flb_debug("buffer is full (FixMe)");
        return;
#if 0
        ret = flb_engine_flush(config, &in_xbee_plugin, NULL);
        if (ret == -1) {
            ctx->buffer_id = 0;
        } 
#endif
    }

    if (in_xbee_rx_validate_msgpack((const char*) (*pkt)->data, (*pkt)->dataLen)) {
        in_xbee_rx_queue_msgpack(ctx, (const char*) (*pkt)->data, (*pkt)->dataLen);
    } else {
        in_xbee_rx_queue_raw(ctx, (const char*) (*pkt)->data, (*pkt)->dataLen);
    }
}

/* Callback triggered by timer */
int in_xbee_collect(struct flb_config *config, void *in_context)
{
    int ret = 0;
    void *p = NULL;
    (void) config;
    struct flb_in_xbee_config *ctx = in_context;

    if ((ret = xbee_conCallbackGet(ctx->con,
                                   (xbee_t_conCallback*) &p)) != XBEE_ENONE) {
        flb_debug("xbee_conCallbackGet() returned: %d", ret);
        return ret;
    }

    return 0;
}

void *in_xbee_flush(void *in_context, int *size)
{
    char *buf;
    msgpack_sbuffer *sbuf;
    struct flb_in_xbee_config *ctx = in_context;

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

/* Init xbee input */
int in_xbee_init(struct flb_config *config)
{
    int ret;
    int opt_baudrate = 9600;
    char *opt_device;
    struct stat dev_st;
    struct xbee *xbee;
    struct xbee_con *con;
    struct xbee_conAddress address;
    struct flb_in_xbee_config *ctx;
    struct xbee_conSettings settings;

    /* Prepare the configuration context */
    ctx = calloc(1, sizeof(struct flb_in_xbee_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    if (!config->file) {
        flb_utils_error_c("XBee input plugin needs configuration file");
        return -1;
    }

    xbee_config_read(ctx, config->file);

    /* Device name */
    if (ctx->file) {
        opt_device = strdup(ctx->file);
    } else {
        opt_device = strdup(FLB_XBEE_DEFAULT_DEVICE);
    }

    /* Check an optional baudrate */
    if (ctx->baudrate)
        opt_baudrate = atoi((char*) ctx->baudrate);

    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    flb_info("XBee device=%s, baudrate=%i", opt_device, opt_baudrate);

    ret = stat(opt_device, &dev_st);
    if (ret < 0) {
        printf("Error: could not open %s device\n", opt_device);
        free(opt_device);
        exit(EXIT_FAILURE);
    }

    if (!S_ISCHR(dev_st.st_mode)) {
        printf("Error: invalid device %s \n", opt_device);
        free(opt_device);
        exit(EXIT_FAILURE);
    }

    if (access(opt_device, R_OK | W_OK) == -1) {
        printf("Error: cannot open the device %s (permission denied ?)\n",
               opt_device);
        free(opt_device);
        exit(EXIT_FAILURE);
    }

    /* Init library */
    xbee_init();

    ret = xbee_setup(&xbee, "xbeeZB", opt_device, opt_baudrate);
    if (ret != XBEE_ENONE) {
        flb_utils_error_c("xbee_setup");
        return ret;
    }

    /* FIXME: just a built-in example */
    memset(&address, 0, sizeof(address));
    address.addr64_enabled = 1;
#if 0
    address.addr64[0] = 0x00;
    address.addr64[1] = 0x13;
    address.addr64[2] = 0xA2;
    address.addr64[3] = 0x00;
    address.addr64[4] = 0x40;
    address.addr64[5] = 0xB7;
#endif
    address.addr64[6] = 0xFF;
    address.addr64[7] = 0xFF;

    if (ctx->xbeeLogLevel >= 0)
        xbee_logLevelSet(xbee, ctx->xbeeLogLevel);

    /* Prepare a connection with the peer XBee */
    if ((ret = xbee_conNew(xbee, &con, "Data", &address)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
        return ret;
    }


    xbee_conSettings(con, NULL, &settings);
    settings.disableAck = 1;
    settings.catchAll = 1;
    xbee_conSettings(con, &settings, NULL);


    ctx->device     = opt_device;
    ctx->baudrate   = opt_baudrate;
    ctx->con        = con;
    ctx->buffer_len = 0;

    if ((ret = xbee_conDataSet(con, ctx, NULL)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conDataSet() returned: %d", ret);
        return ret;
    }


    if ((ret = xbee_conCallbackSet(con, in_xbee_cb, NULL)) != XBEE_ENONE) {
        xbee_log(xbee, -1, "xbee_conCallbackSet() returned: %d", ret);
        return ret;
    }


    /* Set the context */
    ret = flb_input_set_context("xbee", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for xbee input plugin");
    }

    /*
     * Set our collector based on time. We will trigger a collection at certain
     * intervals. For now it works but it's not the ideal implementation. I am
     * talking with libxbee maintainer to check possible workarounds and use
     * proper events mechanism.
     */
    ret = flb_input_set_collector_time("xbee",
                                       in_xbee_collect,
                                       IN_XBEE_COLLECT_SEC,
                                       IN_XBEE_COLLECT_NSEC,
                                       config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for xbee input plugin");
    }

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_xbee_plugin = {
    .name         = "xbee",
    .description  = "XBee Device",
    .cb_init      = in_xbee_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_xbee_collect,
    .cb_flush_buf = in_xbee_flush,
};
