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
#include <fluent-bit/in_xbee.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>


/* Callback invoked after setup but before to join the main loop */
int in_xbee_pre_run(void *in_context, struct flb_config *config)
{
}


/* Callback triggered when some Kernel Log buffer msgs are available */
int in_xbee_collect(void *in_context)
{
}

void *in_xbee_flush(void *in_context, int *size)
{
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

    /* Prepare the configuration context */
    ctx = calloc(1, sizeof(struct flb_in_xbee_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }
    ctx->device = opt_device;
    ctx->baudrate = opt_baudrate;

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
    .name       = "xbee",
    .cb_init    = in_xbee_init,
    .cb_pre_run = in_xbee_pre_run,
    .cb_collect = in_xbee_collect,
    .cb_flush   = in_xbee_flush
};
