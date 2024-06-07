#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <mongoc/mongoc.h>

#include "mongo.h"

static int
cb_mongodb_init(struct flb_output_instance *ins, struct flb_config *config, void *data) {

  int ret = 0;
  int io_flags = 0;
  struct flb_mongodb *ctx;
  struct flb_upstream *upstream;

  /* Set default network configuration */
  flb_output_net_default(FLB_MONGODB_HOST, FLB_MONGODB_PORT, ins);

  /* Allocate plugin context */
  ctx = flb_calloc(1, sizeof(struct flb_mongodb));
  if (!ctx) {
    flb_errno();
    return -1;
  }
  ctx->instance = ins;

  /* Register context with plugin instance */
  flb_output_set_context(ins, ctx);

  /*
   * This plugin instance uses the HTTP client interface, let's register
   * it debugging callbacks.
   * NOTE: is the macro even set?
   */
  flb_output_set_http_debug_callbacks(ins);

  /* Load config map */
  ret = flb_output_config_map_set(ins, (void *)ctx);
  if (ret == -1) {
    flb_free(ctx);
    return -1;
  }

  /* Set io properties based on features. */
  if (ins->use_tls == FLB_TRUE) {
    io_flags = FLB_IO_TLS;
  } else {
    io_flags = FLB_IO_TCP;
  }

  if (ins->host.ipv6 == FLB_TRUE) {
    io_flags |= FLB_IO_IPV6;
  }

  /* Prepare an upstream handler */
  upstream = flb_upstream_create(config, ins->host.name, ins->host.port, io_flags, ins->tls);
  if (NULL != upstream) {
    ctx->upstream = upstream;
    flb_output_upstream_set(ctx->upstream, ins);
  } else {
    flb_free(ctx);
    return -1;
  }

  flb_time_zero(&ctx->ts_dupe);
  flb_time_zero(&ctx->ts_last);

  flb_plg_debug(ctx->instance, "host=%s port=%i", ins->host.name, ins->host.port);
  printf("host=%s port=%i\n", ins->host.name, ins->host.port);

  return 0;
}

int
mongodb_format(const char *tag, int tag_len, const void *data, size_t event_sz, size_t *out_sz,
               struct flb_mongodb *ctx) {

  int ret = 0;
  struct flb_time time;
  struct flb_log_event log_event;
  struct flb_log_event_decoder log_decoder;
  ret = flb_log_event_decoder_init(&log_decoder, (char *)data, event_sz);

  if (ret != FLB_EVENT_DECODER_SUCCESS) {
    flb_plg_error(ctx->instance, "Log event decoder initialization error : %d", ret);
    return 1;
  }

  while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) ==
         FLB_EVENT_DECODER_SUCCESS) {
    flb_time_copy(&time, &log_event.timestamp);
    printf("time: %ld %ld\n", time.tm.tv_sec, time.tm.tv_nsec);
  }

    flb_log_event_decoder_destroy(&log_decoder);

    return 0;
  }

  static void cb_mongodb_flush(
      struct flb_event_chunk * event_chunk, struct flb_output_flush * out_flush,
      struct flb_input_instance * i_ins, void *out_context, struct flb_config *config) {
    int ret = 0;
    size_t bytes;
    struct flb_connection *connection;
    struct flb_mongodb *output_ctx = (struct flb_mongodb *)out_context;

    /* Convert format: metrics / logs */
    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
      /* format metrics */
      printf("metrics are not yet supported.\n");
      assert(0 && "TODO");
    } else {
      /* format logs */
      printf("log event\n");
      ret = mongodb_format(event_chunk->tag, flb_sds_len(event_chunk->tag), event_chunk->data,
                           event_chunk->size, &bytes, output_ctx);

      if (0 != ret) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
      }
    }

    // NOTE: temporary
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Get upstream connection */
    connection = flb_upstream_conn_get(output_ctx->upstream);
    if (!connection) {
      printf("retry\n");
      FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    printf("connection acquired\n");
  }

  static int cb_mongodb_exit(void *data, struct flb_config *config) {
    printf("Exit ran\n");
    return 0;
  }

  struct flb_output_plugin out_mongo_plugin = {
      .name = "mongo",
      .description = "MongoDB",
      .cb_init = cb_mongodb_init,
      .cb_pre_run = NULL,
      .cb_flush = cb_mongodb_flush,
      .cb_exit = cb_mongodb_exit,
      .config_map = NULL,
      .flags = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
      .event_type = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
  };
