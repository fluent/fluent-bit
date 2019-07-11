
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_output.h>
/*
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <stdio.h>
*/

#include "out_stan.h"

static void stan_connection_lost(stanConnection *sc, const char *errTxt, void *closure)
{
    bool *closed = (bool*) closure;

    flb_error("[STAN] NATS Streaming client lost connection");
    *closed = true;
}

static void nats_disconnected(natsConnection *nc, void *closure)
{
    bool        *closed = (bool*)closure;
    const char  *err    = NULL;

    natsConnection_GetLastError(nc, &err);
    flb_warn("[STAN] NATS lost the connection: %s", err);
    *closed = true;
}

static void nats_connected(natsConnection *nc, void *closure)
{
    bool        *closed = (bool*)closure;
    flb_warn("[STAN] NATS connected");
    *closed = false;
}

// TODO Consolidate this duplicate code!??
static void setProperty(struct flb_output_instance *ins, char *property, const char **dest, const char *defaultValue){
    *dest = flb_output_get_property(property, ins);
    if ((*dest == NULL || strlen(*dest) == 0) && strlen(defaultValue) > 0) {
        *dest = defaultValue; // Default property if it is undefined/empty
    }
    flb_info("[STAN] Set property '%s' to '%s'", property, *dest); // TODO Change to debug
}

static int configure_nats(struct flb_out_stan_config **config) {
    struct flb_out_stan_config *ctx = *config;

    // Initialize Nats options
    if (natsOptions_Create(&ctx->nats_options) != NATS_OK) {
        flb_error("[STAN] Error (%d) when creating options: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Set connection url
    flb_info("[STAN] NATS Streaming using URL: '%s'", ctx->url); // TODO Change to debug
    ctx->status = natsOptions_SetURL(ctx->nats_options, ctx->url);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "URL", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Set delay before trying to reconnect
    ctx->status = natsOptions_SetReconnectWait(ctx->nats_options, 100);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Reconnect Wait", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Enable reconnect attempts
    ctx->status = natsOptions_SetRetryOnFailedConnect(ctx->nats_options, true, nats_connected, (void*)&ctx->nats_closed);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Retry on failed connect callback", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    ctx->status = natsOptions_SetClosedCB(ctx->nats_options, nats_disconnected, (void*)&ctx->nats_closed);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Closed CB callback", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    ctx->status = natsOptions_SetSecure(ctx->nats_options, true);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to enable TLS: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    /*ctx->status = natsOptions_SkipServerVerification(ctx->nats_options, true);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to skip server verification: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }*/

    ctx->status = natsOptions_LoadCATrustedCertificates(ctx->nats_options, "/certs/ca/ca.crt");
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to load CA: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }
    ctx->status = natsOptions_LoadCertificatesChain(ctx->nats_options, "/certs/client/tls.crt", "/certs/client/tls.key");
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to load certificates: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    return 0;
}

static int configure_stan(struct flb_out_stan_config **config) {
    struct flb_out_stan_config *ctx = *config;

    // Initialize STAN options
    if (stanConnOptions_Create(&ctx->stan_options) != NATS_OK) {
        flb_error("[STAN] NATS Streaming Error (%d) when creating options: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Set a callback handler when losing connection
    ctx->status = stanConnOptions_SetConnectionLostHandler(ctx->stan_options, stan_connection_lost, (void*)&ctx->stan_closed);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "Connection lost handler", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Set the ping interval and max out values. 
    ctx->status = stanConnOptions_SetPings(ctx->stan_options, 1, 5);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "Pings", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    ctx->status = stanConnOptions_SetNATSOptions(ctx->stan_options, ctx->nats_options);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "options with NATS options", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    return 0;
}

static void cleanup(struct flb_out_stan_config *ctx)
{
    flb_info("[STAN] NATS Streaming cleaning up"); // TODO Change to debug
    if (ctx != NULL) {
        if (!ctx->stan_closed && (ctx->connection != NULL))
        {
            natsStatus closeSts = stanConnection_Close(ctx->connection);
            if ((ctx->status == NATS_OK) && (closeSts != NATS_OK)) {
                ctx->status = closeSts;
            }
        }
        stanConnection_Destroy(ctx->connection);
        natsOptions_Destroy(ctx->nats_options);
        stanConnOptions_Destroy(ctx->stan_options);
        flb_free(ctx);
    }
    nats_Sleep(50);
    nats_Close();
}

void cb_stan_flush(void *data, size_t bytes, char *tag, int tag_len, struct flb_input_instance *i_ins, void *out_context, struct flb_config *config)
{
    struct flb_out_stan_config *ctx = out_context;

    if (ctx->connection == NULL || ctx->stan_closed) {
        if (ctx->connection == NULL) {
            flb_error("[STAN] NATS Error: Unable to publish because connection is undefined", "");
        }
        if (ctx->stan_closed) {
            flb_error("[STAN] NATS Error: Unable to publish because connection is closed", "");
        }
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    flb_info("[STAN] NATS Streaming publish to '%s', length %d", ctx->subject, bytes); // TODO Change to debug
    ctx->status = stanConnection_Publish(ctx->connection, ctx->subject, data, bytes);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] NATS Streaming Error (%d) - Unable to publish message: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_stan_exit(void *data, struct flb_config *config)
{
    flb_info("[STAN] NATS Streaming finishing"); // TODO Change to debug

    cleanup((struct flb_out_stan_config*) data);

    return 0;
}
int cb_stan_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    struct flb_out_stan_config *ctx;

    ctx = flb_malloc(sizeof(struct flb_out_stan_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    ctx->connection   = NULL;
    ctx->stan_options = NULL;
    ctx->nats_options = NULL;
    ctx->nats_closed  = true;
    ctx->stan_closed  = true;

    // Get and set fluentd pluging configuation property. Fallback to default value.
    setProperty(ins, "subject", &ctx->subject, "fluent-bit");
    setProperty(ins, "url", &ctx->url, NATS_DEFAULT_URL);
    setProperty(ins, "cluster", &ctx->cluster, "LOG_STREAMING");


    

    if (configure_nats(&ctx) < 0) {
        flb_error("[NATS] Unable to configure");
        return -1;
    }

    if (configure_stan(&ctx) < 0) {
        flb_error("[STAN] Unable to configure");
        return -1;
    }

    ctx->status = stanConnection_Connect(&ctx->connection, ctx->cluster, "A-RANDOM-ID", ctx->stan_options);

    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to connect: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    ctx->stan_closed = false;

    flb_output_set_context(ins, ctx);

    return 0;
}

struct flb_output_plugin out_stan_plugin = {
    .name         = "stan",
    .description  = "NATS Streaming output client",
    .cb_init      = cb_stan_init,
    .cb_flush     = cb_stan_flush,
    .cb_exit      = cb_stan_exit,
};
