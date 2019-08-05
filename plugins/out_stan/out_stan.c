#include "out_stan.h"
#include <fluent-bit/flb_nats.h>
#include<pthread.h> 

static void stan_connection_lost(stanConnection *sc, const char *errTxt, void *closure)
{
    bool *closed = (bool*) closure;

    flb_error("[STAN] NATS Streaming client lost connection: '%s'", errTxt);
    *closed = true;
}

int configure_nats(struct flb_common_nats_config **config) {
    struct flb_common_nats_config *ctx = *config;

    ctx->status = natsOptions_Create(&ctx->options);
    if (ctx->status != NATS_OK) {
        flb_error("[STAN] Error (%d) when creating options: '%s'", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    flb_info("[STAN] NATS Streaming using URL: '%s'", ctx->url); // TODO Change to debug
    ctx->status = natsOptions_SetURL(ctx->options, ctx->url);
    if (ctx->status != NATS_OK) {
        flb_error(stan_setting_error, "NATS", "URL", ctx->status, natsStatus_GetText(ctx->status));
        return -1;
    }

    if (flb_utils_bool(ctx->tls_enable)) {
        flb_info("[STAN] NATS Streaming enabling tls", ""); // TODO Change to debug
        ctx->status = natsOptions_SetSecure(ctx->options, true);
        if (ctx->status != NATS_OK) {
            flb_error("[STAN] Error (%d) - Unable to enable TLS: '%s'", ctx->status, natsStatus_GetText(ctx->status));
            return -1;
        }
    
        if (ctx->tls_ca_path != NULL && strlen(ctx->tls_ca_path) > 0) {
            flb_info("[STAN] NATS Streaming loading CA from '%s'", ctx->tls_ca_path); // TODO Change to debug
            ctx->status = natsOptions_LoadCATrustedCertificates(ctx->options, ctx->tls_ca_path);
            if (ctx->status != NATS_OK) {
                flb_error("[STAN] Error (%d) - Unable to load CA: '%s'", ctx->status, natsStatus_GetText(ctx->status));
                return -1;
            }
        }

        if (ctx->tls_crt_path != NULL || ctx->tls_key_path != NULL) {
            bool cert_err = true;
            if ((ctx->tls_crt_path == NULL || strlen(ctx->tls_crt_path) <= 0) && (ctx->tls_crt_path == NULL || strlen(ctx->tls_crt_path) <= 0)) {
                flb_error("[STAN] Error (%d) - Unable to load certificates since CRT and KEY path must be set", "");
            } else if (ctx->tls_crt_path == NULL || strlen(ctx->tls_crt_path) <= 0) {
                flb_error("[STAN] Error (%d) - Unable to load certificates since CRT path must also be set", "");
            } else if (ctx->tls_key_path == NULL || strlen(ctx->tls_key_path) <= 0) {
                flb_error("[STAN] Error (%d) - Unable to load certificates since KEY path must also be set", "");
            } else {
                cert_err = false;
            }

            if (!cert_err) {
                flb_info("[STAN] NATS Streaming loading certificates from '%s' and '%s'", ctx->tls_crt_path, ctx->tls_key_path); // TODO Change to debug
                ctx->status = natsOptions_LoadCertificatesChain(ctx->options, ctx->tls_crt_path, ctx->tls_key_path);
                if (ctx->status != NATS_OK) {
                    flb_error("[STAN] Error (%d) - Unable to load certificates from '%s' and '%s': '%s'", ctx->status, ctx->tls_crt_path, ctx->tls_key_path, natsStatus_GetText(ctx->status));
                    return -1;
                }
            } else {
                return -1;
            }
        }

        if (flb_utils_bool(ctx->tls_unverified)) {
            flb_info("[STAN] NATS Streaming skipping tls verification", ""); // TODO Change to debug
            ctx->status = natsOptions_SkipServerVerification(ctx->options, true);
            if (ctx->status != NATS_OK) {
                flb_error("[STAN] Error (%d) - Unable to skip server verification: '%s'", ctx->status, natsStatus_GetText(ctx->status));
                return -1;
            }
        }

        if (ctx->tls_ciphers != NULL && strlen(ctx->tls_ciphers) > 0) {
            flb_info("[STAN] NATS Streaming setting tls ciphers to '%s'", ctx->tls_ciphers); // TODO Change to debug
            ctx->status = natsOptions_SetCiphers(ctx->options, ctx->tls_ciphers);
            if (ctx->status != NATS_OK) {
                flb_error("[STAN] Error (%d) - Unable to set ciphers '%s': '%s'", ctx->status, ctx->tls_ciphers, natsStatus_GetText(ctx->status));
                return -1;
            }
        }
    }

    return 0;
}

int configure_stan_subscription(struct flb_common_stan_config **config) {
    struct flb_common_stan_config *ctx = *config;

    ctx->nats->status = stanSubOptions_Create(&ctx->subscription_options);
    if (ctx->nats->status != NATS_OK) {
        flb_error("[STAN] NATS Streaming Error (%d) when creating subscription options: '%s'", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }
    return 0;
}

int configure_stan(struct flb_common_stan_config **config) {
    struct flb_common_stan_config *ctx = *config;

    ctx->nats->status = stanConnOptions_Create(&ctx->options);
    if (ctx->nats->status != NATS_OK) {
        flb_error("[STAN] NATS Streaming Error (%d) when creating options: '%s'", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }

    if (ctx->discovery_prefix != NULL) {
        flb_info("[STAN] Setting discovery prefix to '%s'", ctx->discovery_prefix); // TODO Change to debug
        ctx->nats->status = stanConnOptions_SetDiscoveryPrefix(ctx->options, ctx->discovery_prefix);
        if (ctx->nats->status != NATS_OK) {
            flb_error(stan_setting_error, "STAN", "Discovery prefix", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
            return -1;
        }
    }

    if (ctx->wait_time != NULL) {
        char *end;
        long val = 0;

        errno = 0;
        val = strtol(ctx->wait_time, &end, 10);
        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
            flb_error(stan_setting_error, "STAN", "Wait time", errno, "Value out of bounds");
            return -1;
        }
        if (end == ctx->wait_time) {
            flb_error(stan_setting_error, "STAN", "Wait time", errno, "Initial char pointer hasn't changed after 'strtol' operation");
            return -1;
        }

        if (ctx->wait_time + strlen(ctx->wait_time) != end) {
            flb_warn("[STAN] Wait-time parsed to %d, with '%s' remaining", val, end);
        }

        flb_info("[STAN] Setting wait time to '%d'", val); // TODO Change to debug
        stanConnOptions_SetConnectionWait(ctx->options, (int64_t) val);
        if (ctx->nats->status != NATS_OK) {
            flb_error(stan_setting_error, "STAN", "Wait time", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
            return -1;
        }
    }

    if (ctx->durable_name != NULL) {
        if (ctx->subscription_options == NULL) {
            if (configure_stan_subscription(&ctx) != 0) {
                flb_error("[STAN] Unable to configure subscription options");
                return 1;
            }
        }
        flb_info("[STAN] Setting durable name to '%s'", ctx->durable_name); // TODO Change to debug
        stanSubOptions_SetDurableName(ctx->subscription_options, ctx->durable_name);
        if (ctx->nats->status != NATS_OK) {
            flb_error(stan_setting_error, "STAN", "Durable name", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
            return -1;
        }
    }

    flb_info("[STAN] Setting connection lost handler", ""); // TODO Change to debug
    ctx->nats->status = stanConnOptions_SetConnectionLostHandler(ctx->options, stan_connection_lost, (void*)&ctx->closed);
    if (ctx->nats->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "Connection lost handler", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
        return -1;
    }

    flb_info("[STAN] Setting NATS options", ""); // TODO Change to debug
    ctx->nats->status = stanConnOptions_SetNATSOptions(ctx->options, ctx->nats->options);
    if (ctx->nats->status != NATS_OK) {
        flb_error(stan_setting_error, "STAN", "NATS options", ctx->nats->status, natsStatus_GetText(ctx->nats->status));
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
    
    while (ctx->stan->closed) {
        flb_info("[STAN] Trying to connect to '%s'", ctx->stan->nats->url); // TODO change to debug?
        
        ctx->stan->nats->status = stanConnection_Close(ctx->stan->connection);
        if (ctx->stan->nats->status != NATS_OK) {
            flb_error("[STAN] Error (%d): Unable to close connection: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        }

        ctx->stan->nats->status = stanConnection_Connect(&ctx->stan->connection, ctx->stan->cluster, ctx->stan->client_id, ctx->stan->options);
        if (ctx->stan->nats->status != NATS_OK) {
            flb_error("[STAN] Error (%d): Unable to connect: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        } else {
            flb_info("[STAN] Connected to '%s'", ctx->stan->nats->url);
            ctx->stan->closed = false;
        }
    }

    flb_info("[STAN] trying to publishing to '%s', length %d", ctx->stan->nats->subject, bytes); // TODO Change to debug
    ctx->stan->nats->status = stanConnection_Publish(ctx->stan->connection, ctx->stan->nats->subject, data, bytes);
    if (ctx->stan->nats->status != NATS_OK) {
        flb_error("[STAN] Error (%d) - Unable to publish message: '%s'", ctx->stan->nats->status, natsStatus_GetText(ctx->stan->nats->status));
        FLB_OUTPUT_RETURN(FLB_RETRY);
    } else {
        flb_info("[STAN] published ok to '%s'", ctx->stan->nats->subject); // TODO Change to debug
        FLB_OUTPUT_RETURN(FLB_OK);
    }
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
    
    setByOutputProperty(ins, "discovery-prefix", &ctx->stan->discovery_prefix, NULL);
    setByOutputProperty(ins, "durable-name", &ctx->stan->durable_name, NULL);
    setByOutputProperty(ins, "wait-time", &ctx->stan->wait_time, NULL);

    setByOutputProperty(ins, "tls-enabled", &ctx->stan->nats->tls_enable, "false");
    setByOutputProperty(ins, "tls-unverified", &ctx->stan->nats->tls_unverified, "false");
    setByOutputProperty(ins, "tls-ca-path", &ctx->stan->nats->tls_ca_path, NULL);
    setByOutputProperty(ins, "tls-crt-path", &ctx->stan->nats->tls_crt_path, NULL);
    setByOutputProperty(ins, "tls-key-path", &ctx->stan->nats->tls_key_path, NULL);
    setByOutputProperty(ins, "tls-ciphers", &ctx->stan->nats->tls_ciphers, NULL);

    setByOutputProperty(ins, "queue-id", &ctx->stan->queue_id, NULL);

    if (configure_nats(&ctx->stan->nats) != 0) {
        flb_error("[STAN] NATS unable to configure");
        return -1;
    }

    if (configure_stan(&ctx->stan) != 0) {
        flb_error("[STAN] Unable to configure");
        return -1;
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
