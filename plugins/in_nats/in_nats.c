#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include "in_nats.h"

#define NATS_GET_MSG_TIMEOUT 10000
#define NATS_SUBSCRIBE_TIMEOUT 500

static void onMsg(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure)
{
    flb_input_chunk_append_raw((struct flb_input_instance *) closure, NULL, 0, (void *) natsMsg_GetData(msg), natsMsg_GetDataLength(msg));
    
    natsMsg_Destroy(msg);
}

// TODO Consolidate this duplicate code!
static void setProperty(struct flb_input_instance *ins, char *property, char **dest, char **defaultValue){
    *dest = flb_input_get_property(property, ins);
    /*if (strlen(defaultValue) > 0 && (*dest == NULL || strlen(*dest) == 0)) {
        *dest = defaultValue; // Default property if it is undefined/empty
    }*/
    flb_info("NATS set property '%s' to '%s'", property, *dest); // TODO Change to debug
}

/* Initialize plugin */
static int in_nats_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    flb_info("NATS input initializing"); // TODO Change to debug

    struct flb_in_nats_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_nats_config));
    if (ctx == NULL) {
        return -1;
    }

    ctx->connection   = NULL;
    ctx->options      = NULL;
    ctx->subscription = NULL;
    ctx->closed       = true;


    flb_info("NATS creating options"); // TODO Change to debug
    if (natsOptions_Create(&ctx->options) != NATS_OK) {
        flb_error("NATS Error (%d) when creating options: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return 1;
    }

    setProperty(ins, "subject", &ctx->subject, "fluent-bit");
    setProperty(ins, "url", &ctx->url, &NATS_DEFAULT_URL);

    flb_info("NATS using URL: '%s'", ctx->url); // TODO Change to debug
    ctx->status = natsOptions_SetURL(ctx->options, ctx->url);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "URL", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    ctx->status = natsOptions_SetTimeout(ctx->options, 1000);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "Timeout", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    ctx->status = natsOptions_SetMaxReconnect(ctx->options, 50);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "Max Reconnect", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }
    
    ctx->status = natsOptions_SetReconnectWait(ctx->options, 100);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "Reconnect Wait", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }
    ctx->status = natsOptions_SetRetryOnFailedConnect(ctx->options, true, NULL, NULL);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "Reconnect Wait", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    ctx->status = natsConnection_Connect(&ctx->connection, ctx->options);
    flb_info("NATS Connect call returned: %s", natsStatus_GetText(ctx->status)); // TODO Change to debug
    if (ctx->status != NATS_OK) {
        flb_error("NATS Connect failed: %s", natsStatus_GetText(ctx->status));
        return 1;
    } else {
        ctx->closed = false;
    }

    flb_info("NATS Connected ok to '%s'", ctx->url); // TODO Change to debug

    ctx->status = natsConnection_SubscribeTimeout(&ctx->subscription, ctx->connection, ctx->subject, NATS_SUBSCRIBE_TIMEOUT, onMsg, ins);

    if (ctx->status != NATS_OK) {
        flb_error("NATS Subscription failed: '%s'", natsStatus_GetText(ctx->status));
        return 1;
    }

    flb_error("NATS Subscribed ok to '%s'", ctx->subject);

    flb_input_set_context(ins, ctx);

    return 0;
}

static int in_nats_exit(void *data, struct flb_config *config)
{
    flb_info("NATS input exiting"); // TODO Change to debug

    (void) *config;
    struct flb_in_nats_config *ctx = data;

    // TODO Is this enough, or are if condtions required
    natsSubscription_Destroy(ctx->subscription);
    natsConnection_Destroy(ctx->connection);
    natsOptions_Destroy(ctx->options);
    nats_Close();

    return 0;
}


struct flb_input_plugin in_nats_plugin = {
    .name         = "nats",
    .description  = "Nats.io input",
    .cb_init      = in_nats_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_nats_exit
};
