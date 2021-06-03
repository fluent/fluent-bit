/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_client.h>

#include "skywalking.h"

#define DEFAULT_SW_OAP_HOST "0.0.0.0"
#define DEFAULT_SW_OAP_PORT 12800
#define DEFAULT_SW_SVC_NAME "sw-service"
#define DEFAULT_SW_INS_NAME "fluent-bit"

static int cb_sw_init(struct flb_output_instance *ins, struct flb_config *config, void *data) {
  int io_flags;
  struct flb_output_sw *ctx;

  const char* tmp;

  /* Set default network configuration */
  flb_output_net_default(DEFAULT_SW_OAP_HOST, DEFAULT_SW_OAP_PORT, ins);

  /* Allocate plugin context */
  ctx = flb_calloc(1, sizeof(struct flb_output_sw));
  if (!ctx) {
    flb_errno();
    return -1;
  }
  ctx->ins = ins;

  /* Set the plugin context */
  flb_output_set_context(ins, ctx);

  /* scheme configuration */
  if (ins->use_tls == FLB_TRUE) {
    io_flags = FLB_IO_TLS;
    ctx->http_scheme = flb_sds_create("https://");
  } else {
    io_flags = FLB_IO_TCP;
    ctx->http_scheme = flb_sds_create("http://");
  }

  /* setup host and port */
  ctx->host = ins->host.name;
  ctx->port = ins->host.port;
  flb_plg_debug(ctx->ins, "OAP address: %s:%d", ctx->host, ctx->port);

  /* setup access token */
  tmp = flb_output_get_property("auth_token", ins);
  if (tmp) {
    flb_plg_debug(ctx->ins, "OAP token: %s", ctx->auth_token);
    ctx->auth_token = flb_sds_create(tmp);
  }

  /* setup uri */
  ctx->uri = flb_sds_create("/v3/logs");
  if (!ctx->uri) {
    flb_plg_error(ctx->ins, "failed to configure endpoint");
    flb_free(ctx);
    return -1;
  }

  /* configure service/instance name */
  tmp = flb_output_get_property("service_name", ins);
  if (tmp) {
    ctx->svc_name = flb_sds_create(tmp);
  } else {
    ctx->svc_name = flb_sds_create(DEFAULT_SW_SVC_NAME);
  }

  tmp = flb_output_get_property("instance_name", ins);
  if (tmp) {
    ctx->svc_inst_name = flb_sds_create(tmp);
  } else {
    ctx->svc_inst_name = flb_sds_create(DEFAULT_SW_INS_NAME);
  }

  flb_plg_debug(ctx->ins, "configured %s/%s", ctx->svc_name, ctx->svc_inst_name);

  /* configure upstream instance */
  ctx->u = flb_upstream_create(config, ctx->host, ctx->port, io_flags, ins->tls);
  if (!ctx->u) {
    flb_plg_error(ctx->ins, "failed to create upstream context");
    flb_free(ctx);
    return -1;
  }
  flb_output_upstream_set(ctx->u, ins);

  return 0;
}

static int64_t timestamp_format(const struct flb_time* tms) {
  int64_t timestamp = 0;

  /* Format the time, use milliseconds precision not nanoseconds */
  timestamp = tms->tm.tv_sec * 1000;
  timestamp += tms->tm.tv_nsec / 1000000;

  /* round up if necessary */
  if (tms->tm.tv_nsec % 1000000 >= 500000) {
    ++timestamp;
  }
  return timestamp;
}

static void sw_msgpack_pack_kv_str(msgpack_packer* pk, const char* key,
                                   size_t key_len, const char *value, size_t value_len) {
  msgpack_pack_str(pk, key_len);
  msgpack_pack_str_body(pk, key, key_len);
  msgpack_pack_str(pk, value_len);
  msgpack_pack_str_body(pk, value, value_len);
}

static void sw_msgpack_pack_kv_int64_t(msgpack_packer* pk, const char* key,
                                       size_t key_len, int64_t value) {
  msgpack_pack_str(pk, key_len);
  msgpack_pack_str_body(pk, key, key_len);
  msgpack_pack_int64(pk, value);
}


static void sw_msgpack_pack_log_body(msgpack_packer* pk,
                                     msgpack_object* obj, size_t obj_size) {
  int i;
  int log_entry_num = 0;
  msgpack_sbuffer sbuf;
  msgpack_packer body_pk;
  msgpack_object key;
  msgpack_object value;
  flb_sds_t out_body_str;
  size_t out_body_str_len;

  msgpack_sbuffer_init(&sbuf);
  msgpack_packer_init(&body_pk, &sbuf, msgpack_sbuffer_write);

  msgpack_pack_str(pk, 4);
  msgpack_pack_str_body(pk, "body", 4);
  msgpack_pack_map(pk, 1);

  /* body['json'] */
  msgpack_pack_str(pk, 4);
  msgpack_pack_str_body(pk, "json", 4);

  for (i = 0; i < obj_size; ++i) {
    key = obj->via.map.ptr[i].key;
    value = obj->via.map.ptr[i].val;

    if (key.type != MSGPACK_OBJECT_STR || value.type != MSGPACK_OBJECT_STR) {
      continue;
    }

    ++log_entry_num;
  }

  msgpack_pack_map(pk, log_entry_num);

  /* body['json']['json'] */
  for (i = 0; i < obj_size; ++i) {
    key = obj->via.map.ptr[i].key;
    value = obj->via.map.ptr[i].val;

    if (key.type != MSGPACK_OBJECT_STR || value.type != MSGPACK_OBJECT_STR) {
      continue;
    }

    sw_msgpack_pack_kv_str(&body_pk, key.via.str.ptr, key.via.str.size, value.via.str.ptr, value.via.str.size);
  }

  out_body_str = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);
  out_body_str_len = flb_sds_len(out_body_str);

  msgpack_pack_str(pk, 4);
  msgpack_pack_str_body(pk, "json", 4);
  msgpack_pack_str(pk, out_body_str_len);
  msgpack_pack_str_body(pk, out_body_str, out_body_str_len);

  msgpack_sbuffer_destroy(&sbuf);
  flb_sds_destroy(out_body_str);
}

static int sw_format(struct flb_output_sw* ctx, const void *data,
                     size_t bytes, void** buf, size_t* buf_len) {
  size_t off = 0;
  uint32_t map_size;
  msgpack_sbuffer sbuf;
  msgpack_packer pk;
  msgpack_unpacked result;
  msgpack_object root;
  msgpack_object map;
  msgpack_object *obj;
  struct flb_time tms;
  int64_t timestamp;
  flb_sds_t out_str;

  msgpack_sbuffer_init(&sbuf);
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

  msgpack_unpacked_init(&result);

  while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
    root = result.data;

    /* Get timestamp and object */
    flb_time_pop_from_msgpack(&tms, &result, &obj);
    timestamp = timestamp_format(&tms);

    map = root.via.array.ptr[1];
    map_size = map.via.map.size;

    msgpack_pack_map(&pk, 4);

    sw_msgpack_pack_kv_int64_t(&pk, "timestamp", 9, timestamp);
    sw_msgpack_pack_kv_str(&pk, "service", 7, ctx->svc_name, flb_sds_len(ctx->svc_name));
    sw_msgpack_pack_kv_str(&pk, "serviceInstance", 15, ctx->svc_inst_name, flb_sds_len(ctx->svc_inst_name));
    sw_msgpack_pack_log_body(&pk, &map, map_size);
  }

  out_str = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);

  *buf = out_str;
  *buf_len = flb_sds_len(out_str);

  msgpack_sbuffer_destroy(&sbuf);
  msgpack_unpacked_destroy(&result);

  return 0;
}

static void cb_sw_flush(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        struct flb_input_instance *i_ins,
                        void *out_context, struct flb_config *config) {
  int flush_ret = -1;
  int tmp_ret = -1;
  struct flb_output_sw *ctx = out_context;
  struct flb_upstream_conn *conn = NULL;
  struct flb_http_client *client = NULL;
  void* buf = NULL;
  size_t buf_len;
  size_t sent_size;

  conn = flb_upstream_conn_get(ctx->u);
  if (!conn) {
    flb_plg_error(ctx->ins, "failed to establish connection to %s:%i", ctx->host, ctx->port);
    flush_ret = FLB_RETRY;
    goto done;
  }

  tmp_ret = sw_format(ctx, data, bytes, &buf, &buf_len);
  if (tmp_ret != 0) {
    flb_plg_error(ctx->ins, "failed to create buffer");
    flush_ret = FLB_ERROR;
    goto done;
  }

  client = flb_http_client(conn, FLB_HTTP_POST, ctx->uri,
          (const char*)buf, buf_len, ctx->host, ctx->port, NULL, 0);
  if (!client) {
    flb_plg_error(ctx->ins, "failed to create HTTP client");
    flush_ret = FLB_ERROR;
    goto done;
  }

  if (flb_sds_len(ctx->auth_token) != 0) {
    flb_http_add_header(client, "Authentication", 10, ctx->auth_token, strlen(ctx->auth_token));
  }

  flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
  flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);

  tmp_ret = flb_http_do(client, &sent_size);
  if (tmp_ret == 0) {
    flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i", ctx->host, ctx->port, client->resp.status);

    if (client->resp.status < 200 || client->resp.status > 205) {
      flush_ret = FLB_RETRY;
    } else {
      flush_ret = FLB_OK;
    }
  } else {
    flb_plg_error(ctx->ins, "failed to flush buffer to %s:%i", ctx->host, ctx->port);
    flush_ret = FLB_RETRY;
  }

done:
  if (buf) {
    flb_free(buf);
  }
  if (client) {
    flb_http_client_destroy(client);
  }
  if (conn) {
    flb_upstream_conn_release(conn);
  }

  FLB_OUTPUT_RETURN(flush_ret);
}

static int cb_sw_exit(void *data, struct flb_config *config) {
  struct flb_output_sw *ctx;
  ctx = (struct flb_output_sw*)data;
  if (!ctx) {
    return 0;
  }

  if (ctx->host) {
    flb_sds_destroy(ctx->host);
  }
  if (ctx->auth_token) {
    flb_sds_destroy(ctx->auth_token);
  }
  if (ctx->svc_name) {
    flb_sds_destroy(ctx->svc_name);
  }
  if (ctx->svc_inst_name) {
    flb_sds_destroy(ctx->svc_inst_name);
  }
  if (ctx->u) {
    flb_upstream_destroy(ctx->u);
  }
  if (ctx->http_scheme) {
    flb_sds_destroy(ctx->http_scheme);
  }
  if (ctx->uri) {
    flb_sds_destroy(ctx->uri);
  }

  flb_free(ctx);
  return 0;
}

struct flb_output_plugin out_sw_plugin = {
  .name = "skywalking",
  .description = "Send logs into log collector on SkyWalking OAP",
  .cb_init = cb_sw_init,
  .cb_flush = cb_sw_flush,
  .cb_exit = cb_sw_exit,
  .flags = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
