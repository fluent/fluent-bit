#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>

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

static void setProperty(char *dest, char *property, char *defaultValue){
    dest = flb_output_get_property(property, ins);
    if (strlen(dest) == 0) {
        dest = defaultValue; // Default property if it is undefined/empty
    }
}

int cb_nats_init(struct flb_output_instance *ins, struct flb_config *config,
                   void *data)
{

    struct flb_out_nats_config *ctx;
    /* Allocate plugin context */
    ctx = flb_malloc(sizeof(struct flb_out_nats_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    *ctx->connection   = NULL;
    *ctx->options      = NULL;
    *ctx->subscription = NULL;
    ctx->closed       = true;

    setProperty(ctx->subject, "subject", "fluent-bit");
    setProperty(ctx->host, "host", "localhost");
    setProperty(ctx->port, "port", "4222");
    setProperty(ctx->username, "username", "");
    setProperty(ctx->password, "password", "");

    char        *serverUrls[NATS_MAX_SERVERS];
    memset(serverUrls, 0, sizeof(serverUrls));
    

    ctx->status = natsOptions_SetServers(ctx->options, 50);


    ctx->status = natsOptions_SetMaxReconnect(ctx->options, 50);
    if (ctx->status == NATS_OK) {
        ctx->status = natsOptions_SetReconnectWait(ctx->options, 100);
    }
    if (ctx->status == NATS_OK)
        ctx->status = natsOptions_SetRetryOnFailedConnect(ctx->options, true, NULL, NULL);

    int64_t start = nats_Now();
    ctx->status = natsConnection_Connect(&ctx->connection, ctx->options);
    int64_t elapsed = nats_Now() - start;

    flb_info("NATS Connection call took %" PRId64 " ms and returned: %s", elapsed, natsStatus_GetText(ctx->status));

    natsConnection_Destroy(ctx->connection);
    ctx->connection = NULL;

    ctx->status = natsOptions_SetMaxReconnect(ctx->options, 10);
    if (ctx->status == NATS_OK)
        ctx->status = natsOptions_SetRetryOnFailedConnect(ctx->options, true, connectedCB, NULL);
    if (ctx->status == NATS_OK)
        ctx->status = natsOptions_SetClosedCB(ctx->options, closedCB, (void*)&ctx->closed);

    if (ctx->status != NATS_OK)
    {
        flb_error("NATS Error: %d - %s", ctx->status, natsStatus_GetText(ctx->status));
        return(1);
    }

    ctx->status = natsConnection_Connect(&ctx->connection, ctx->options);
    flb_info("NATS Connect call returned: %s", natsStatus_GetText(ctx->status)); // TODO Change to debug
    if (ctx->status != NATS_OK) {
        flb_error("NATS Connect failed: %s", natsStatus_GetText(ctx->status));
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

    flb_info("NATS publish ('%s'): '%s'", ctx->subject, "Nats message..."); // TODO Change to debug
    natsConnection_PublishString(ctx->connection, ctx->subject, "got it?");
    
    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_nats_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_out_nats_config *ctx = data;

    natsSubscription_Destroy(ctx->subscription);
    natsConnection_Destroy(ctx->connection);
    natsOptions_Destroy(ctx->options);
    nats_Close();

    flb_free(ctx);

    return 0;
}

struct flb_output_plugin out_nats_plugin = {
    .name         = "nats",
    .description  = "NATS Server",
    .cb_init      = cb_nats_init,
    .cb_flush     = cb_nats_flush,
    .cb_exit      = cb_nats_exit,
    .flags        = FLB_OUTPUT_NET,
};
