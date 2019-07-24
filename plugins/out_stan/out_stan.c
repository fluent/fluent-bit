#include "out_stan.h"
#include <fluent-bit/flb_nats.h>
#include<pthread.h> 

/*static void stan_connection_lost(stanConnection *sc, const char *errTxt, void *closure)
{
    bool *closed = (bool*) closure;

    flb_error("[STAN] NATS Streaming client lost connection");
    *closed = true;
}*/

int stan_try_to_connect(struct flb_out_stan_config **config) {
    struct flb_out_stan_config *ctx = *config;

    flb_info("[STAN] Connecting to '%s'", ctx->stan->nats->url); // TODO change to debug?
    ctx->stan->nats->status = stanConnection_Connect(&ctx->stan->connection, ctx->stan->cluster, ctx->stan->client_id, ctx->stan->options);

    if (ctx->stan->nats->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to connect: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        //pthread_mutex_unlock(&ctx->stan->nats->connlock);
        //return -1; // Ignore error
    }

    /*if (pthread_mutex_trylock(&ctx->stan->nats->connlock) != 0){
        flb_info("[STAN] Unable to lock mutex (busy), skipping connection attempt"); // TODO change to debug?
        return -1;
    }
    
    if (ctx->stan->connection != NULL){
        stanConnection_Destroy(ctx->stan->connection);
    }

    flb_info("[STAN] Connecting to '%s'", ctx->stan->nats->url); // TODO change to debug?
    ctx->stan->nats->status = stanConnection_Connect(&ctx->stan->connection, ctx->stan->cluster, ctx->stan->cluster, ctx->stan->options);

    if (ctx->stan->nats->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to connect: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        //pthread_mutex_unlock(&ctx->stan->nats->connlock);
        return -1;
    }

    ctx->stan->closed = false;
    //pthread_mutex_unlock(&ctx->stan->nats->connlock);
    */
    return 0;
}

static void nats_connection_lost(natsConnection *nc, void *closure)
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

    char url[512];

    natsConnection_GetConnectedUrl(nc, url, sizeof(url));
    flb_info("[STAN] NATS connected to '%s'", url);
    *closed = false;
}


int configure_nats(struct flb_common_nats_config **config) {
    struct flb_common_nats_config *ctx = *config;
    
    // Initialize Nats options
    ctx->status = natsOptions_Create(&ctx->options);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) when creating options: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Set connection url
    flb_info("[STAN] NATS Streaming using URL: '%s'", ctx->url); // TODO Change to debug
    ctx->status = natsOptions_SetURL(ctx->options, ctx->url); //"nats://streaming:hfgdhsjdfgsdhfj@rd-unified-log-nats-int.logging:4222");
    //ctx->status = natsUrl_Create(&ctx->options.url, ctx->url);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "URL", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    /*
    ctx->status = natsOptions_SetTimeout(ctx->options, 1000);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Timeout", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Set delay before trying to reconnect
    ctx->status = natsOptions_SetReconnectWait(ctx->options, 100);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Reconnect Wait", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }
    
    ctx->status = natsOptions_SetAllowReconnect(ctx->options, true);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Allow reconnect", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    // Enable reconnect attempts
    ctx->status = natsOptions_SetRetryOnFailedConnect(ctx->options, true, nats_connected, (void*)&ctx->closed);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Retry on failed connect callback", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    ctx->status = natsOptions_SetClosedCB(ctx->options, nats_connection_lost, (void*)&ctx->closed);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "Closed CB callback", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }*/

    /*ctx->status = natsOptions_SetSecure(ctx->options, true);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to enable TLS: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    /*ctx->status = natsOptions_SkipServerVerification(ctx->options, true);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to skip server verification: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    ctx->status = natsOptions_LoadCATrustedCertificates(ctx->options, "/certs/ca/ca.crt");
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to load CA: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }
    ctx->status = natsOptions_LoadCertificatesChain(ctx->options, "/certs/client/tls.crt", "/certs/client/tls.key");
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to load certificates: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }*/

    return 0;
}

int configure_stan(struct flb_common_stan_config **config) {
    struct flb_common_stan_config *ctx = *config;

    // Initialize STAN options
    ctx->nats->status = stanConnOptions_Create(&ctx->options);
    if (ctx->nats->status != NATS_OK) {
        flb_error("[STAN] NATS Streaming Error (%d) when creating options: '%s'", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }

    /*
    // Set a callback handler when losing connection
    ctx->nats->status = stanConnOptions_SetConnectionLostHandler(ctx->options, stan_connection_lost, (void*)&ctx->closed);
    if (ctx->nats->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "Connection lost handler", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }

    // Set the ping interval and max out values. 
    ctx->nats->status = stanConnOptions_SetPings(ctx->options, 1, 5);
    if (ctx->nats->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "Pings", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }
    */

    ctx->nats->status = stanConnOptions_SetNATSOptions(ctx->options, ctx->nats->options);
    if (ctx->nats->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "options with NATS options", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }

    return 0;
}

void cleanupStan(struct flb_out_stan_config *ctx)
{
    flb_info("[STAN] NATS Streaming cleaning up"); // TODO Change to debug
    if (ctx != NULL) {
        if (!ctx->stan->closed && (ctx->stan->connection != NULL))
        {
            natsStatus closeSts = stanConnection_Close(ctx->stan->connection);
            if ((ctx->stan->nats->status == NATS_OK) && (closeSts != NATS_OK)) {
                ctx->stan->nats->status = closeSts;
            }
        }
        
        if (ctx->stan != NULL) {
            stanConnection_Destroy(ctx->stan->connection);
            if (ctx->stan->nats->options != NULL) {
                stanConnOptions_Destroy(ctx->stan->options);
            }
            if (ctx->stan->nats != NULL) {
                if (ctx->stan->nats->options != NULL) {
                    natsOptions_Destroy(ctx->stan->nats->options);
                }
                pthread_mutex_destroy(&ctx->stan->nats->connlock); 
                flb_free(ctx->stan->nats);
            }
            flb_free(ctx->stan);
        }
        flb_free(ctx);
    }
    nats_Sleep(50);
    nats_Close();
}

void cb_stan_flush(void *data, size_t bytes, char *tag, int tag_len, struct flb_input_instance *i_ins, void *out_context, struct flb_config *config)
{
    struct flb_out_stan_config *ctx = out_context;

    if (ctx->stan->connection == NULL) {
        if (ctx->stan->connection == NULL) {
            flb_error("[STAN] Error: Unable to publish because connection is undefined", "");
        } /*else if (ctx->stan->closed) {
            flb_error("[STAN] Error: Unable to publish because connection is closed", "");
        } */
        //flb_info("[STAN] Trying to connect for flush"); // TODO Change to debug?
        /*if (stan_try_to_connect(&ctx) < 0) {
            FLB_OUTPUT_RETURN(FLB_RETRY);    
        }*/
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_info("[STAN] NATS Streaming publish to '%s', length %d", ctx->stan->nats->subject, bytes); // TODO Change to debug
    ctx->stan->nats->status = stanConnection_Publish(ctx->stan->connection, ctx->stan->nats->subject, data, bytes);
    if (ctx->stan->nats->status != NATS_OK) {
        flb_error("[STAN] NATS Streaming Error (%d) - Unable to publish message: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_stan_exit(void *data, struct flb_config *config)
{
    flb_info("[STAN] NATS Streaming finishing"); // TODO Change to debug

    cleanupStan((struct flb_out_stan_config*) data);

    return 0;
}
int cb_stan_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    struct flb_out_stan_config *ctx;

    ctx = flb_malloc(sizeof(struct flb_out_stan_config));
    if (!ctx) {
        perror("malloc flb_common_stan_config");
        return -1;
    }

    ctx->stan = flb_malloc(sizeof(struct flb_common_stan_config));
    if (!ctx->stan) {
        perror("malloc flb_common_stan_config->stan");
        return -1;
    }

    ctx->stan->nats = flb_malloc(sizeof(struct flb_common_nats_config));
    if (!ctx->stan->nats) {
        perror("malloc flb_common_stan_config->stan->nats");
        return -1;
    }

    /*if (pthread_mutex_init(&ctx->stan->nats->connlock, NULL) != 0) 
    { 
        perror("init mutex flb_common_stan_config->stan->nats->connlock");
        return -1;
    }*/

    ctx->stan->connection    = NULL;
    ctx->stan->options       = NULL;
    ctx->stan->closed        = true;
    ctx->stan->nats->closed  = true;
    ctx->stan->nats->options = NULL;
     
    // Get and set fluentd pluging configuation property. Fallback to default value.
    setByOutputProperty(ins, "subject", &ctx->stan->nats->subject, "fluent-bit");
    setByOutputProperty(ins, "url", &ctx->stan->nats->url, NATS_DEFAULT_URL);
    setByOutputProperty(ins, "cluster", &ctx->stan->cluster, "LOG_STREAMING");
    setByOutputProperty(ins, "client-id", &ctx->stan->client_id, "LOG_STREAMING_CLIENT");
    //setByOutputProperty(ins, "queue-id", &ctx->stan->queue_id, NULL);

    if (configure_nats(&ctx->stan->nats) < 0) {
        flb_error("[STAN] NATS unable to configure");
        return -1;
    }

    if (configure_stan(&ctx->stan) < 0) {
        flb_error("[STAN] Unable to configure");
        return -1;
    }
    
    //natsConnection_ConnectTo
    //stan_try_to_connect(&ctx);
    flb_info("[STAN] Connecting to '%s'", ctx->stan->nats); // TODO change to debug?
    ctx->stan->nats->status = stanConnection_Connect(&ctx->stan->connection, ctx->stan->cluster, ctx->stan->client_id, ctx->stan->options);

    if (ctx->stan->nats->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to connect: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        //pthread_mutex_unlock(&ctx->stan->nats->connlock);
        //return -1; // Ignore error
    }

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
