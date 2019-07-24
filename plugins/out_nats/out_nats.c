#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>

#include <fluent-bit/flb_nats.h>

#include <stdio.h>
#include <msgpack.h>

#include "out_nats.h"

static void
connectedCB(natsConnection *nc, void *closure)
{
    char url[256];

    natsConnection_GetConnectedUrl(nc, url, sizeof(url));
    flb_info("NATS Connecting to: %s\n", url);
}

static void
closedCB(natsConnection *nc, void *closure)
{
    bool        *closed = (bool*)closure;
    const char  *err    = NULL;

    natsConnection_GetLastError(nc, &err);
    flb_info("NATS closed the connection: %s", err);
    *closed = true;
}

/*static void printOptions(struct __natsOptions *opt) {
    //flb_info("NATS options - URL: '%s', USERNAME: '%s'", opt->url, opt->user); // TODO Change to debug
}*/

static void cleanup(struct flb_out_nats_config *ctx) {
    flb_info("NATS cleaning up"); // TODO Change to debug
    if (ctx != NULL) {
        if (ctx->connection != NULL) {
            natsConnection_Destroy(ctx->connection);
        }
        if (ctx->options != NULL) {
            natsOptions_Destroy(ctx->options);
        }
        flb_free(ctx);
    }
    nats_Close();
}

static void setProperty(struct flb_output_instance *ins, char *property, const char **dest, const char *defaultValue){
    *dest = flb_output_get_property(property, ins);
    if ((*dest == NULL || strlen(*dest) == 0) && strlen(defaultValue) > 0) {
        *dest = defaultValue; // Default property if it is undefined/empty
    }
    flb_info("[NATS] Set property '%s' to '%s'", property, *dest); // TODO Change to debug
}

int cb_nats_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{

    struct flb_out_nats_config *ctx;
    /* Allocate plugin context */
    ctx = flb_malloc(sizeof(struct flb_out_nats_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    ctx->connection   = NULL;
    ctx->options      = NULL;
    ctx->closed       = true;

    if (natsOptions_Create(&ctx->options) != NATS_OK) {
        flb_error("NATS Error (%d) when creating options: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return 1;
    }

    setProperty(ins, "subject", &ctx->subject, "fluent-bit");
    setProperty(ins, "url", &ctx->url, NATS_DEFAULT_URL);

    flb_info("NATS using URL: '%s'", ctx->url); // TODO Change to debug
    ctx->status = natsOptions_SetURL(ctx->options, ctx->url);

    //printOptions(ctx->options);

    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "URL", ctx->status, natsStatus_GetText(ctx->status));
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

    int64_t start = nats_Now();
    ctx->status = natsConnection_Connect(&ctx->connection, ctx->options);
    int64_t elapsed = nats_Now() - start;
    
    if (ctx->status != NATS_OK) {
        flb_error("NATS Error connecting: %d - %s",  ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    flb_info("NATS Connection call took %" PRId64 " ms and returned: %s", elapsed, natsStatus_GetText(ctx->status));

    if (ctx->connection != NULL) {
        natsConnection_Destroy(ctx->connection);
    }
    ctx->connection = NULL;

    ctx->status = natsOptions_SetMaxReconnect(ctx->options, 10);
    if (ctx->status != NATS_OK)
    {
        flb_error(nats_setting_error, "Max Reconnect", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    ctx->status = natsOptions_SetRetryOnFailedConnect(ctx->options, true, connectedCB, NULL);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "Retry on failed connect callback", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    
    ctx->status = natsOptions_SetClosedCB(ctx->options, closedCB, (void*)&ctx->closed);
    if (ctx->status != NATS_OK) {
        flb_error(nats_setting_error, "Closed CB callback", ctx->status, natsStatus_GetText(ctx->status));
    }
    
    ctx->status = natsConnection_Connect(&ctx->connection, ctx->options);
    flb_info("NATS Connect call returned: %s", natsStatus_GetText(ctx->status)); // TODO Change to debug
    if (ctx->status != NATS_OK) {
        flb_error("NATS Connect failed: %s", natsStatus_GetText(ctx->status));
        return 1;
    } else {
        ctx->closed = false;
    }

    

    flb_output_set_context(ins, ctx);

    return 0;
}

void cb_nats_flush(void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_input_instance *i_ins,
                   void *out_context,
                   struct flb_config *config)
{   
    struct flb_out_nats_config *ctx = out_context;

    if (ctx->connection == NULL || ctx->closed) {
        if (ctx->connection == NULL) {
            flb_error("NATS Error: Unable to publish because connection is undefined", "");
        }
        if (ctx->closed) {
            flb_error("NATS Error: Unable to publish because connection is closed", "");
        }
        FLB_OUTPUT_RETURN(FLB_ERROR);
    } 

    flb_info("NATS publish to '%s', length %d", ctx->subject, bytes); // TODO Change to debug
    natsConnection_Publish(ctx->connection, ctx->subject, data, bytes);
    
    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_nats_exit(void *data, struct flb_config *config)
{
    //(void) config;
    //struct flb_out_nats_config *ctx = data;

    flb_info("NATS finishing"); // TODO Change to debug

    cleanup((struct flb_out_nats_config*) data);

    return 0;
}

struct flb_output_plugin out_stan_plugin = {
    .name         = "nats",
    .description  = "NATS output client",
    .cb_init      = cb_nats_init,
    .cb_flush     = cb_nats_flush,
    .cb_exit      = cb_nats_exit,
    //.flags        = FLB_OUTPUT_NET,
};
