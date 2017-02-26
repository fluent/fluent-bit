/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kube_conf.h"
#include "kube_meta.h"

static int file_to_buffer(char *path, char **out_buf, size_t *out_size)
{
    int ret;
    char *buf;
    ssize_t bytes;
    FILE *fp;
    struct stat st;

    if (!(fp = fopen(path, "r"))) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, (st.st_size + 1));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

/* Load local information from a POD context */
static int get_local_pod_info(struct flb_kube_meta *meta)
{
    int ret;
    char *ns;
    size_t ns_size;
    char *tk;
    size_t tk_size;
    char *hostname;

    /* Get the namespace name */
    ret = file_to_buffer(FLB_KUBE_NAMESPACE, &ns, &ns_size);
    if (ret == -1) {
        /*
         * If it fails, it's just informational, as likely the caller
         * wanted to connect using the Proxy instead from inside a POD.
         */
        flb_warn("[filter_kube] cannot open %s", FLB_KUBE_NAMESPACE);
        return FLB_FALSE;
    }

    /* If a namespace was recognized, a token is mandatory */
    ret = file_to_buffer(FLB_KUBE_TOKEN, &tk, &tk_size);
    if (ret == -1) {
        flb_free(ns);
        flb_warn("[filter_kube] cannot open %s", FLB_KUBE_TOKEN);
        return FLB_FALSE;
    }

    hostname = getenv("HOSTNAME");

    meta->namespace = ns;
    meta->namespace_len = ns_size;
    meta->token = tk;
    meta->token_len = tk_size;
    meta->updated = time(NULL);
    meta->hostname = flb_strdup(hostname);

    meta->auth = flb_malloc(tk_size + 32);
    if (!meta->auth) {
        return FLB_FALSE;
    }
    meta->auth_len = snprintf(meta->auth, tk_size + 32,
                              "Authorization: Bearer %s",
                              tk);

    snprintf(meta->api_endpoint, sizeof(meta->api_endpoint) -1,
             FLB_KUBE_API_FMT,
             meta->namespace, meta->hostname);

    return FLB_TRUE;
}

/* Gather metadata from API Server */
static int get_api_server_info(struct flb_kube *ctx)
{
    int ret;
    size_t b_sent;
    char *out_buf;
    int  out_size;
    struct flb_kube_meta *meta = ctx->meta;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_error("[filter_kube] upstream connection error");
        return -1;
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_GET,
                        /* FIXME */
                        "/api/v1/namespaces/kube-system/pods/fluent-bit-rz47v",
                        NULL, 0, NULL, 0, NULL, FLB_HTTP_10);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Connection", 10, "close", 5);
    flb_http_add_header(c, "Authorization", 13, meta->auth, meta->auth_len);

    /* Perform request */
    ret = flb_http_do(c, &b_sent);
    flb_info("[filter_kube] http_do=%i", ret);

    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &out_buf, &out_size);

    /* release resources */
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    /* validate pack */
    if (ret == -1) {
        flb_error("[filter_kube] invalid JSON -> msgpack");
    }

    /* FIXME: we got k8s meta */
    flb_pack_print(out_buf, out_size);

    return 0;
}

static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    int len;
    struct flb_kube_meta *meta = data;

    len = strlen((char *)name);
    msgpack_pack_str(meta->mp_pck, len);
    msgpack_pack_str_body(meta->mp_pck, (char *) name, len);
    msgpack_pack_str(meta->mp_pck, vlen);
    msgpack_pack_str_body(meta->mp_pck, (char *) value, vlen);
}

static inline int tag_to_meta(struct flb_kube *ctx, char *tag, int tag_len,
                              char **out_buf, size_t *out_size)
{
    ssize_t n;
    struct flb_regex_search result;
    struct flb_kube_meta meta;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    n = flb_regex_do(ctx->regex_tag, (unsigned char *) tag, tag_len, &result);
    if (n <= 0) {
        return -1;
    }

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, n);
    meta.mp_pck = &tmp_pck;

    flb_regex_parse(ctx->regex_tag, &result, cb_results, &meta);
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return 0;
}

static int flb_kube_network_init(struct flb_kube *ctx, struct flb_config *config)
{
    int io_type = FLB_IO_TCP;

    if (ctx->api_https == FLB_TRUE) {
        ctx->tls_ca_file  = FLB_KUBE_CA;
        ctx->tls.context = flb_tls_context_new(FLB_TRUE,
                                               ctx->tls_ca_file,
                                               NULL, NULL, NULL);
        io_type = FLB_IO_TLS;
    }

    /* Create an Upstream context */
    ctx->upstream = flb_upstream_create(config,
                                        ctx->api_host,
                                        ctx->api_port,
                                        io_type,
                                        &ctx->tls);

    /* Remove async flag from upstream */
    ctx->upstream->flags &= ~(FLB_IO_ASYNC);

    return 0;
}

/* Initialize local context */
int flb_kube_meta_init(struct flb_kube *ctx, struct flb_config *config)
{
    int ret;
    struct flb_kube_meta *meta;

    /* Allocate meta context */
    meta = flb_calloc(1, sizeof(struct flb_kube_meta));
    if (!meta) {
        flb_errno();
        return -1;
    }
    ctx->meta = meta;

    /* Gather local info */
    ret = get_local_pod_info(ctx->meta);
    if (ret == FLB_TRUE) {
        flb_info("[filter_kube] local POD info OK");
    }
    else {
        flb_info("[filter_kube] not running in a POD");
    }

    /* Init network */
    flb_kube_network_init(ctx, config);
    /* Gather info from API server */
    ret = get_api_server_info(ctx);

    return 0;
}

int flb_kube_meta_get(struct flb_kube *ctx,
                      char *tag, int tag_len,
                      char **out_buf, size_t *out_size)
{
    int id;
    int ret;

    ret = flb_hash_get(ctx->hash_table, tag, tag_len,
                       out_buf, out_size);
    if (ret == -1) {
        /* The entry was not found, create it */
        ret = tag_to_meta(ctx, tag, tag_len, out_buf, out_size);
        if (ret != 0) {
            return -1;
        }

        id = flb_hash_add(ctx->hash_table,
                          tag, tag_len,
                          *out_buf, *out_size);
        if (id >= 0) {
            /*
             * Release the original buffer created on tag_to_meta() as a new
             * copy have been generated into the hash table, then re-set
             * the outgoing buffer and size.
             */
            flb_free(*out_buf);
            flb_hash_get_by_id(ctx->hash_table, id, out_buf, out_size);
            return 0;
        }
    }

    return 0;
}
