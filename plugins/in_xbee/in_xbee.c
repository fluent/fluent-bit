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

#include "in_xbee.h"

/*
 * We need to declare the xbee_init() function here as for some reason the
 * libxbee-v3 on prepare.h file is not exporting the symbol or something
 * is wrong when linking.
 */
void xbee_init(void);

void in_xbee_cb(struct xbee *xbee, struct xbee_con *con,
                struct xbee_pkt **pkt, void **data)
{
    struct iovec *v;
    struct flb_in_xbee_config *ctx;

	if ((*pkt)->dataLen == 0) {
		flb_debug("xbee data length too short, skip");
		return;
	}

    ctx = *data;

    if (ctx->buffer_len + 1 >= FLB_XBEE_BUFFER_SIZE) {
        /* fixme: use flb_engine_flush() */
        return;
    }

    /* Insert entry into the iovec */
    v = &ctx->buffer[ctx->buffer_len];
    v->iov_base = malloc((*pkt)->dataLen);
    memcpy(v->iov_base, (*pkt)->data, (*pkt)->dataLen);
    v->iov_len = (*pkt)->dataLen;
    ctx->buffer_len++;
}

/* Callback triggered by timer */
int in_xbee_collect(struct flb_config *config, void *in_context)
{
    int ret;
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

void *in_xbee_flush_iov(void *in_context, int *size)
{
    struct flb_in_xbee_config *ctx = in_context;

    *size = ctx->buffer_len;
    return ctx->buffer;
}

void in_xbee_flush_end(void *in_context)
{
    int i;
    struct iovec *iov;
    struct flb_in_xbee_config *ctx = in_context;

    for (i = 0; i < ctx->buffer_len; i++) {
        iov = &ctx->buffer[i];
        free(iov->iov_base);
        iov->iov_len = 0;
    }

    ctx->buffer_len = 0;
}

/* Init kmsg input */
int in_xbee_init(struct flb_config *config)
{
    int ret;
    int opt_baudrate = 9600;
    char *tmp;
    char *opt_device = FLB_XBEE_DEFAULT_DEVICE;
    struct stat dev_st;
	struct xbee *xbee;
	struct xbee_con *con;
	struct xbee_conAddress address;
    struct flb_in_xbee_config *ctx;

    /* Check an optional baudrate */
    tmp = getenv("FLB_XBEE_BAUDRATE");
    if (tmp) {
        opt_baudrate = atoi(tmp);
    }

    /* Get the target device entry */
    tmp = getenv("FLB_XBEE_DEVICE");
    if (tmp) {
        opt_device = strdup(tmp);
    }
    flb_info("XBee device=%s, baudrate=%i", opt_device, opt_baudrate);

    ret = stat(opt_device, &dev_st);
    if (ret < 0) {
        printf("Error: could not open %s device\n", opt_device);
        exit(EXIT_FAILURE);
    }

    if (!S_ISCHR(dev_st.st_mode)) {
        printf("Error: invalid device %s \n", opt_device);
        exit(EXIT_FAILURE);
    }

    if (access(opt_device, R_OK | W_OK) == -1) {
        printf("Error: cannot open the device %s (permission denied ?)\n",
               opt_device);
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
	address.addr64[0] = 0x00;
	address.addr64[1] = 0x13;
	address.addr64[2] = 0xA2;
	address.addr64[3] = 0x00;
    address.addr64[4] = 0x40;
    address.addr64[5] = 0xB7;
    address.addr64[6] = 0xB1;
    address.addr64[7] = 0xEB;

    /* Prepare a connection with the peer XBee */
	if ((ret = xbee_conNew(xbee, &con, "Data", &address)) != XBEE_ENONE) {
		xbee_log(xbee, -1, "xbee_conNew() returned: %d (%s)", ret, xbee_errorToStr(ret));
		return ret;
	}

    /* Prepare the configuration context */
    ctx = calloc(1, sizeof(struct flb_in_xbee_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }
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
    .cb_flush_buf = NULL,
    .cb_flush_iov = in_xbee_flush_iov,
    .cb_flush_end = in_xbee_flush_end,
};
