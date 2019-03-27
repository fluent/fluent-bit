/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <msgpack.h>

#include "forward.h"

struct flb_output_plugin out_forward_plugin;

#define SECURED_BY "Fluent Bit"

#ifdef FLB_HAVE_TLS

#define secure_forward_tls_error(ret) \
    _secure_forward_tls_error(ret, __FILE__, __LINE__)

void _secure_forward_tls_error(int ret, char *file, int line)
{
    char err_buf[72];

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    flb_error("[io_tls] flb_io_tls.c:%i %s", line, err_buf);
}
#endif

static inline void print_msgpack_status(int ret, char *context)
{
    switch (ret) {
    case MSGPACK_UNPACK_EXTRA_BYTES:
        flb_error("[out_fw] %s MSGPACK_UNPACK_EXTRA_BYTES", context);
        break;
    case MSGPACK_UNPACK_CONTINUE:
        flb_trace("[out_fw] %s MSGPACK_UNPACK_CONTINUE", context);
        break;
    case MSGPACK_UNPACK_PARSE_ERROR:
        flb_error("[out_fw] %s MSGPACK_UNPACK_PARSE_ERROR", context);
        break;
    case MSGPACK_UNPACK_NOMEM_ERROR:
        flb_error("[out_fw] %s MSGPACK_UNPACK_NOMEM_ERROR", context);
        break;
    }
}

#ifdef FLB_HAVE_TLS

/* Read a secure forward msgpack message */
static int secure_forward_read(struct flb_upstream_conn *u_conn,
                               char *buf, size_t size, size_t *out_len)
{
    int ret;
    size_t off;
    size_t avail;
    size_t buf_off = 0;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);
    while (1) {
        avail = size - buf_off;
        if (avail < 1) {
            goto error;
        }

        /* Read the message */
        ret = flb_io_net_read(u_conn, buf + buf_off, size - buf_off);
        if (ret <= 0) {
            goto error;
        }
        buf_off += ret;

        /* Validate */
        off = 0;
        ret = msgpack_unpack_next(&result, buf, buf_off, &off);
        switch (ret) {
        case MSGPACK_UNPACK_SUCCESS:
            msgpack_unpacked_destroy(&result);
            *out_len = buf_off;
            return 0;
        default:
            print_msgpack_status(ret, "handshake");
            goto error;
        };
    }

 error:
    msgpack_unpacked_destroy(&result);
    return -1;
}

static void secure_forward_bin_to_hex(uint8_t *buf, size_t len, char *out)
{
    int i;
    char map[] = "0123456789abcdef";

	for (i = 0; i < len; i++) {
		out[i * 2]     = map[buf[i] >> 4];
        out[i * 2 + 1] = map[buf[i] & 0x0f];
	}
}

static int secure_forward_ping(struct flb_upstream_conn *u_conn,
                               msgpack_object map,
                               struct flb_forward_config *fc,
                               struct flb_forward *ctx)
{
    int i;
    int ret;
    uint8_t *nonce_data;
    int nonce_size;
    size_t bytes_sent;
    unsigned char shared_key[64];
    char shared_key_hexdigest[128];
    msgpack_object key;
    msgpack_object val;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    mbedtls_sha512_context sha512;

    /* Lookup nonce field */
    for (i = 0; i < map.via.map.size; i++) {
        key = map.via.map.ptr[i].key;
        if (strncmp(key.via.str.ptr, "nonce", 5) == 0 &&
            key.via.str.size == 5){
            val = map.via.map.ptr[i].val;
            break;
        }
    }

    if (i >= map.via.map.size) {
        flb_error("[out_fw] nonce not found");
        return -1;
    }

    nonce_data = (unsigned char *) val.via.bin.ptr;
    nonce_size = val.via.bin.size;

    /* Compose the shared key */
    mbedtls_sha512_init(&sha512);
    mbedtls_sha512_starts(&sha512, 0);
    mbedtls_sha512_update(&sha512, fc->shared_key_salt, 16);
    mbedtls_sha512_update(&sha512,
                          (unsigned char *) fc->self_hostname,
                          flb_sds_len(fc->self_hostname));
    mbedtls_sha512_update(&sha512,
                          nonce_data, nonce_size);
    mbedtls_sha512_update(&sha512, (unsigned char *) fc->shared_key,
                          flb_sds_len(fc->shared_key));
    mbedtls_sha512_finish(&sha512, shared_key);
    mbedtls_sha512_free(&sha512);

    /* Make hex digest representation of the new shared key */
    secure_forward_bin_to_hex(shared_key, 64, shared_key_hexdigest);

    /* Prepare outgoing msgpack PING */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, 6);

    /* [0] PING */
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "PING", 4);

    /* [1] Hostname */
    msgpack_pack_str(&mp_pck, flb_sds_len(fc->self_hostname));
    msgpack_pack_str_body(&mp_pck, fc->self_hostname,
                          flb_sds_len(fc->self_hostname));

    /* [2] Shared key salt */
    msgpack_pack_str(&mp_pck, 16);
    msgpack_pack_str_body(&mp_pck, fc->shared_key_salt, 16);

    /* [3] Shared key in Hexdigest format */
    msgpack_pack_str(&mp_pck, 128);
    msgpack_pack_str_body(&mp_pck, shared_key_hexdigest, 128);

    /* [4] Username (disabled) */
    msgpack_pack_str(&mp_pck, 0);
    msgpack_pack_str_body(&mp_pck, "", 0);

    /* [5] Password-hexdigest (disabled) */
    msgpack_pack_str(&mp_pck, 0);
    msgpack_pack_str_body(&mp_pck, "", 0);

    ret = flb_io_net_write(u_conn, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    flb_debug("[out_fw] PING sent: ret=%i bytes sent=%lu", ret, bytes_sent);

    msgpack_sbuffer_destroy(&mp_sbuf);

    if (ret == 0 && bytes_sent > 0) {
        return 0;
    }

    return -1;
}

static int secure_forward_pong(char *buf, int buf_size)
{
    int ret;
    char msg[32] = {};
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object o;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_ARRAY) {
        goto error;
    }

    if (root.via.array.size < 4) {
        goto error;
    }

    o = root.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_STR) {
        goto error;
    }

    if (strncmp(o.via.str.ptr, "PONG", 4) != 0 || o.via.str.size != 4) {
        goto error;
    }

    o = root.via.array.ptr[1];
    if (o.type != MSGPACK_OBJECT_BOOLEAN) {
        goto error;
    }

    if (o.via.boolean) {
        msgpack_unpacked_destroy(&result);
        return 0;
    }
    else {
        o = root.via.array.ptr[2];
        memcpy(msg, o.via.str.ptr, o.via.str.size);
        flb_error("[out_fw] failed authorization: %s", msg);
    }

 error:
    msgpack_unpacked_destroy(&result);
    return -1;
}

static int secure_forward_handshake(struct flb_upstream_conn *u_conn,
                                    struct flb_forward_config *fc,
                                    struct flb_forward *ctx)
{
    int ret;
    char buf[1024];
    size_t out_len;
    size_t off;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object o;

    /* Wait for server HELO */
    ret = secure_forward_read(u_conn, buf, sizeof(buf) - 1, &out_len);
    if (ret == -1) {
        flb_error("[out_fw] handshake error expecting HELO");
        return -1;
    }

    /* Unpack message and validate */
    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, out_len, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        print_msgpack_status(ret, "HELO");
        return -1;
    }

    /* Parse HELO message */
    root = result.data;
    if (root.via.array.size < 2) {
        flb_error("[out_fw] Invalid HELO message");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    o = root.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_STR) {
        flb_error("[out_fw] Invalid HELO type message");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    if (strncmp(o.via.str.ptr, "HELO", 4) != 0 || o.via.str.size != 4) {
        flb_error("[out_fw] Invalid HELO content message");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    flb_debug("[out_fw] protocol: received HELO");

    /* Compose and send PING message */
    o = root.via.array.ptr[1];
    ret = secure_forward_ping(u_conn, o, fc, ctx);
    if (ret == -1) {
        flb_error("[out_fw] Failed PING");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* Expect a PONG */
    ret = secure_forward_read(u_conn, buf, sizeof(buf) - 1, &out_len);
    if (ret == -1) {
        flb_error("[out_fw] handshake error expecting HELO");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* Process PONG */
    ret = secure_forward_pong(buf, out_len);
    if (ret == -1) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    msgpack_unpacked_destroy(&result);
    return 0;
}

static int secure_forward_init(struct flb_forward_config *fc)
{
    int ret;

    /* Initialize mbedTLS entropy contexts */
    mbedtls_entropy_init(&fc->tls_entropy);
    mbedtls_ctr_drbg_init(&fc->tls_ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&fc->tls_ctr_drbg,
                                mbedtls_entropy_func,
                                &fc->tls_entropy,
                                (const unsigned char *) SECURED_BY,
                                sizeof(SECURED_BY) -1);
    if (ret == -1) {
        secure_forward_tls_error(ret);
        return -1;
    }

    /* Gernerate shared key salt */
    mbedtls_ctr_drbg_random(&fc->tls_ctr_drbg, fc->shared_key_salt, 16);
    return 0;
}
#endif

static int forward_config_init(struct flb_forward_config *fc,
                               struct flb_forward *ctx)
{
#ifdef FLB_HAVE_TLS
    /* Initialize Secure Forward mode */
    if (fc->secured == FLB_TRUE) {
        if (!fc->shared_key) {
            flb_error("[out_fw] secure mode requires a shared_key");
            return -1;
        }
        secure_forward_init(fc);
    }
#endif

    mk_list_add(&fc->_head, &ctx->configs);
    return 0;
}

static void forward_config_destroy(struct flb_forward_config *fc)
{
    flb_sds_destroy(fc->shared_key);
    flb_sds_destroy(fc->self_hostname);
    flb_free(fc);
}

/* Configure in HA mode */
static int forward_config_ha(char *upstream_file,
                             struct flb_forward *ctx,
                             struct flb_config *config)
{
    int ret;
    char *tmp;
    struct mk_list *head;
    struct flb_upstream_node *node;
    struct flb_forward_config *fc = NULL;

    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_error("[out_forward] cannot load Upstream file");
        return -1;
    }

    /* Iterate nodes and create a forward_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);

        /* create forward_config context */
        fc = flb_calloc(1, sizeof(struct flb_forward_config));
        if (!fc) {
            flb_errno();
            flb_error("[out_forward] failed config allocation");
            continue;
        }
        fc->secured = FLB_FALSE;

        /* Is TLS enabled ? */
        if (node->tls_enabled == FLB_TRUE) {
            fc->secured = FLB_TRUE;
        }

        /* Shared key (secure_forward) */
        tmp = flb_upstream_node_get_property("shared_key", node);
        if (tmp) {
            fc->shared_key = flb_sds_create(tmp);
        }
        else {
            fc->shared_key = NULL;
        }

        /* Self Hostname (secure_forward) */
        tmp = flb_upstream_node_get_property("self_hostname", node);
        if (tmp) {
            fc->self_hostname = flb_sds_create(tmp);
        }
        else {
            fc->self_hostname = flb_sds_create("localhost");
        }

        /* Time_as_Integer */
        tmp = flb_upstream_node_get_property("time_as_integer", node);
        if (tmp) {
            fc->time_as_integer = flb_utils_bool(tmp);
        }
        else {
            fc->time_as_integer = FLB_FALSE;
        }

        /* Initialize and validate forward_config context */
        ret = forward_config_init(fc, ctx);
        if (ret == -1) {
            if (fc) {
                forward_config_destroy(fc);
            }
            return -1;
        }

        /* Set our forward_config context into the node */
        flb_upstream_node_set_data(fc, node);
    }

    return 0;
}

static int forward_config_simple(struct flb_forward *ctx,
                                 struct flb_output_instance *ins,
                                 struct flb_config *config)
{
    int ret;
    int io_flags;
    char *tmp;
    struct flb_forward_config *fc = NULL;
    struct flb_upstream *upstream;

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 24224, ins);

    /* Configuration context */
    fc = flb_calloc(1, sizeof(struct flb_forward_config));
    if (!fc) {
        return -1;
    }
    fc->secured = FLB_FALSE;

    /* Check if TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        fc->secured = FLB_TRUE;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags, (void *) &ins->tls);
    if (!upstream) {
        flb_free(fc);
        flb_free(ctx);
        return -1;
    }
    ctx->u = upstream;

    /* Shared Key */
    tmp = flb_output_get_property("shared_key", ins);
    if (tmp) {
        fc->shared_key = flb_sds_create(tmp);
    }

    /* Self Hostname */
    tmp = flb_output_get_property("self_hostname", ins);
    if (tmp) {
        fc->self_hostname = flb_sds_create(tmp);
    }
    else {
        fc->self_hostname = flb_sds_create("localhost");
    }

    /* Backward compatible timing mode */
    fc->time_as_integer = FLB_FALSE;
    tmp = flb_output_get_property("time_as_integer", ins);
    if (tmp) {
        fc->time_as_integer = flb_utils_bool(tmp);
    }

    /* Initialize and validate forward_config context */
    ret = forward_config_init(fc, ctx);
    if (ret == -1) {
        if (fc) {
            forward_config_destroy(fc);
        }
        return -1;
    }

    return 0;
}

static int cb_forward_init(struct flb_output_instance *ins,
                           struct flb_config *config, void *data)
{
    int ret;
    char *tmp;
    struct flb_forward *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_forward));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->configs);
    flb_output_set_context(ins, ctx);

    /* Configure HA or simple mode ? */
    tmp = flb_output_get_property("upstream", ins);
    if (tmp) {
        ret = forward_config_ha(tmp, ctx, config);
    }
    else {
        ret = forward_config_simple(ctx, ins, config);
    }

    return ret;
}

static int data_compose(void *data, size_t bytes,
                        void **out_buf, size_t *out_size,
                        struct flb_forward_config *fc,
                        struct flb_forward *ctx)
{
    int entries = 0;
    size_t off = 0;
    msgpack_object   *mp_obj;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    struct flb_time tm;

    /*
     * time_as_integer means we are using backward compatible mode for
     * servers with old timestamp mode in uint64_t (e.g: Fluentd <= v0.12).
     */
    msgpack_unpacked_init(&result);
    if (fc->time_as_integer == FLB_TRUE) {
        /*
         * if the case, we need to compose a new outgoing buffer instead
         * of use the original one.
         */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            /* Gather time */
            flb_time_pop_from_msgpack(&tm, &result, &mp_obj);

            /* Append data */
            msgpack_pack_array(&mp_pck, 2);
            msgpack_pack_uint64(&mp_pck, tm.tm.tv_sec);
            msgpack_pack_object(&mp_pck, *mp_obj);
            entries++;
        }
    }
    else {
        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            entries++;
        }
    }

    /* cleanup */
    if (fc->time_as_integer == FLB_TRUE) {
        *out_buf  = mp_sbuf.data;
        *out_size = mp_sbuf.size;
    }
    else {
        *out_buf  = NULL;
        *out_size = 0;
    }
    msgpack_unpacked_destroy(&result);

    return entries;
}

static int cb_forward_exit(void *data, struct flb_config *config)
{
    struct flb_forward *ctx = data;
    struct flb_forward_config *fc;
    struct mk_list *head;
    struct mk_list *tmp;
    (void) config;

    if (!ctx) {
        return 0;
    }

    /* Destroy forward_config contexts */
    mk_list_foreach_safe(head, tmp, &ctx->configs) {
        fc = mk_list_entry(head, struct flb_forward_config, _head);
        mk_list_del(&fc->_head);
        forward_config_destroy(fc);
    }

    if (ctx->ha_mode == FLB_TRUE) {
        if (ctx->ha) {
            flb_upstream_ha_destroy(ctx->ha);
        }
    }
    else {
        flb_upstream_destroy(ctx->u);
    }
    flb_free(ctx);

    return 0;
}

static void cb_forward_flush(void *data, size_t bytes,
                             char *tag, int tag_len,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    int ret = -1;
    int entries = 0;
    size_t total;
    size_t bytes_sent;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_forward *ctx = out_context;
    struct flb_forward_config *fc = NULL;
    struct flb_upstream_conn *u_conn;
    struct flb_upstream_node *node;
    (void) i_ins;
    (void) config;

    if (ctx->ha_mode == FLB_TRUE) {
        node = flb_upstream_ha_node_get(ctx->ha);
        if (!node) {
            flb_error("[out_forward] cannot get an Upstream HA node");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        /* Get forward_config stored in node opaque data */
        fc = flb_upstream_node_get_data(node);
    }
    else {
        fc = mk_list_entry_first(&ctx->configs,
                                 struct flb_forward_config,
                                 _head);
    }

    flb_debug("[out_forward] request %lu bytes to flush", bytes);

    /* Initialize packager */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Count number of entries, is there a better way to do this ? */
    entries = data_compose(data, bytes, &out_buf, &out_size, fc, ctx);
    if (out_buf == NULL && fc->time_as_integer == FLB_FALSE) {
        out_buf = data;
        out_size = bytes;
    }

    flb_debug("[out_fw] %i entries tag='%s' tag_len=%i",
              entries, tag, tag_len);

    /* Output: root array */
    msgpack_pack_array(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, tag_len);
    msgpack_pack_str_body(&mp_pck, tag, tag_len);
    msgpack_pack_array(&mp_pck, entries);

    /* Get a TCP connection instance */
    if (ctx->ha_mode == FLB_TRUE) {
        u_conn = flb_upstream_conn_get(node->u);
    }
    else {
        u_conn = flb_upstream_conn_get(ctx->u);
    }
    if (!u_conn) {
        flb_error("[out_fw] no upstream connections available");
        msgpack_sbuffer_destroy(&mp_sbuf);
        if (fc->time_as_integer == FLB_TRUE) {
            flb_free(out_buf);
        }
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Secure Forward ? */
#ifdef FLB_HAVE_TLS
    if (fc->secured == FLB_TRUE) {
        ret = secure_forward_handshake(u_conn, fc, ctx);
        flb_debug("[out_fw] handshake status = %i", ret);
        if (ret == -1) {
            flb_upstream_conn_release(u_conn);
            msgpack_sbuffer_destroy(&mp_sbuf);
            if (fc->time_as_integer == FLB_TRUE) {
                flb_free(out_buf);
            }
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
#endif

    /* Write message header */
    ret = flb_io_net_write(u_conn, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    if (ret == -1) {
        flb_error("[out_fw] could not write chunk header");
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_upstream_conn_release(u_conn);
        if (fc->time_as_integer == FLB_TRUE) {
            flb_free(out_buf);
        }
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    total = ret;

    /* Write body (records) */
    ret = flb_io_net_write(u_conn, out_buf, out_size, &bytes_sent);
    if (ret == -1) {
        flb_error("[out_fw] error writing content body");
        if (fc->time_as_integer == FLB_TRUE) {
            flb_free(out_buf);
        }
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    total += bytes_sent;
    flb_upstream_conn_release(u_conn);

    if (fc->time_as_integer == FLB_TRUE) {
        flb_free(out_buf);
    }

    flb_trace("[out_fw] ended write()=%d bytes", total);
    FLB_OUTPUT_RETURN(FLB_OK);
}

/* Plugin reference */
struct flb_output_plugin out_forward_plugin = {
    .name         = "forward",
    .description  = "Forward (Fluentd protocol)",
    .cb_init      = cb_forward_init,
    .cb_pre_run   = NULL,
    .cb_flush     = cb_forward_flush,
    .cb_exit      = cb_forward_exit,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
