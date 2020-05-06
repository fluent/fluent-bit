/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_sha512.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include "forward.h"

struct flb_output_plugin out_forward_plugin;

#define SECURED_BY "Fluent Bit"

#ifdef FLB_HAVE_TLS

#define secure_forward_tls_error(ctx, ret)                  \
    _secure_forward_tls_error(ctx, ret, __FILE__, __LINE__)

void _secure_forward_tls_error(struct flb_forward *ctx,
                               int ret, char *file, int line)
{
    char err_buf[72];

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    flb_plg_error(ctx->ins, "flb_io_tls.c:%i %s", line, err_buf);
}

static int secure_forward_init(struct flb_forward *ctx,
                               struct flb_forward_config *fc)
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
        secure_forward_tls_error(ctx, ret);
        return -1;
    }

    /* Gernerate shared key salt */
    mbedtls_ctr_drbg_random(&fc->tls_ctr_drbg, fc->shared_key_salt, 16);
    return 0;
}
#endif

static inline void print_msgpack_status(struct flb_forward *ctx,
                                        int ret, char *context)
{
    switch (ret) {
    case MSGPACK_UNPACK_EXTRA_BYTES:
        flb_plg_error(ctx->ins, "%s MSGPACK_UNPACK_EXTRA_BYTES", context);
        break;
    case MSGPACK_UNPACK_CONTINUE:
        flb_plg_trace(ctx->ins, "%s MSGPACK_UNPACK_CONTINUE", context);
        break;
    case MSGPACK_UNPACK_PARSE_ERROR:
        flb_plg_error(ctx->ins, "%s MSGPACK_UNPACK_PARSE_ERROR", context);
        break;
    case MSGPACK_UNPACK_NOMEM_ERROR:
        flb_plg_error(ctx->ins, "%s MSGPACK_UNPACK_NOMEM_ERROR", context);
        break;
    }
}

/* Read a secure forward msgpack message */
static int secure_forward_read(struct flb_forward *ctx,
                               struct flb_upstream_conn *u_conn,
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
            print_msgpack_status(ctx, ret, "handshake");
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
    static char map[] = "0123456789abcdef";

	for (i = 0; i < len; i++) {
		out[i * 2]     = map[buf[i] >> 4];
        out[i * 2 + 1] = map[buf[i] & 0x0f];
	}
}

static void secure_forward_set_ping(struct flb_forward_ping *ping,
                                    msgpack_object *map)
{
    int i;
    msgpack_object key;
    msgpack_object val;
    const char *ptr;
    int len;

    memset(ping, 0, sizeof(struct flb_forward_ping));
    ping->keepalive = 1; /* default, as per spec */

    for (i = 0; i < map->via.map.size; i++) {
        key = map->via.map.ptr[i].key;
        val = map->via.map.ptr[i].val;

        ptr = key.via.str.ptr;
        len = key.via.str.size;

        if (len == 5 && memcmp(ptr, "nonce", len) == 0) {
            ping->nonce = val.via.bin.ptr;
            ping->nonce_len = val.via.bin.size;
        }
        else if (len == 4 && memcmp(ptr, "auth", len) == 0) {
            ping->auth = val.via.bin.ptr;
            ping->auth_len = val.via.bin.size;
        }
        else if (len == 9 && memcmp(ptr, "keepalive", len) == 0) {
            ping->keepalive = val.via.boolean;
        }
    }
}

static int secure_forward_hash_shared_key(struct flb_forward_config *fc,
                                          struct flb_forward_ping *ping,
                                          char *buf, int buflen)
{
    char *hostname = (char *) fc->self_hostname;
    char *shared_key = (char *) fc->shared_key;
    struct flb_sha512 sha512;
    uint8_t hash[64];

    if (buflen < 128) {
        return -1;
    }

    flb_sha512_init(&sha512);
    flb_sha512_update(&sha512, fc->shared_key_salt, 16);
    flb_sha512_update(&sha512, hostname, strlen(hostname));
    flb_sha512_update(&sha512, ping->nonce, ping->nonce_len);
    flb_sha512_update(&sha512, shared_key, strlen(shared_key));
    flb_sha512_sum(&sha512, hash);

    secure_forward_bin_to_hex(hash, 64, buf);
    return 0;
}

static int secure_forward_hash_password(struct flb_forward_config *fc,
                                        struct flb_forward_ping *ping,
                                        char *buf, int buflen)
{
    struct flb_sha512 sha512;
    uint8_t hash[64];

    if (buflen < 128) {
        return -1;
    }

    flb_sha512_init(&sha512);
    flb_sha512_update(&sha512, ping->auth, ping->auth_len);
    flb_sha512_update(&sha512, fc->username, strlen(fc->username));
    flb_sha512_update(&sha512, fc->password, strlen(fc->password));
    flb_sha512_sum(&sha512, hash);

    secure_forward_bin_to_hex(hash, 64, buf);
    return 0;
}

static int secure_forward_ping(struct flb_upstream_conn *u_conn,
                               msgpack_object map,
                               struct flb_forward_config *fc,
                               struct flb_forward *ctx)
{
    int ret;
    size_t bytes_sent;
    char shared_key_hexdigest[128];
    char password_hexdigest[128];
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_forward_ping ping;

    secure_forward_set_ping(&ping, &map);

    if (ping.nonce == NULL) {
        flb_plg_error(ctx->ins, "nonce not found");
        return -1;
    }

    if (secure_forward_hash_shared_key(fc, &ping, shared_key_hexdigest, 128)) {
        flb_plg_error(ctx->ins, "failed to hash shared_key");
        return -1;
    }

    if (ping.auth != NULL) {
        if (secure_forward_hash_password(fc, &ping, password_hexdigest, 128)) {
            flb_plg_error(ctx->ins, "failed to hash password");
            return -1;
        }
    }

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

    /* [4] Username and password (optional) */
    if (ping.auth != NULL) {
        msgpack_pack_str(&mp_pck, strlen(fc->username));
        msgpack_pack_str_body(&mp_pck, fc->username, strlen(fc->username));
        msgpack_pack_str(&mp_pck, 128);
        msgpack_pack_str_body(&mp_pck, password_hexdigest, 128);
    } else {
        msgpack_pack_str(&mp_pck, 0);
        msgpack_pack_str_body(&mp_pck, "", 0);
        msgpack_pack_str(&mp_pck, 0);
        msgpack_pack_str_body(&mp_pck, "", 0);
    }

    ret = flb_io_net_write(u_conn, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    flb_plg_debug(ctx->ins, "PING sent: ret=%i bytes sent=%lu", ret, bytes_sent);

    msgpack_sbuffer_destroy(&mp_sbuf);

    if (ret > -1 && bytes_sent > 0) {
        return 0;
    }

    return -1;
}

static int secure_forward_pong(struct flb_forward *ctx, char *buf, int buf_size)
{
    int ret;
    char msg[32] = {0};
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
        flb_plg_error(ctx->ins, "failed authorization: %s", msg);
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
    ret = secure_forward_read(ctx, u_conn, buf, sizeof(buf) - 1, &out_len);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "handshake error expecting HELO");
        return -1;
    }

    /* Unpack message and validate */
    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, out_len, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        print_msgpack_status(ctx, ret, "HELO");
        return -1;
    }

    /* Parse HELO message */
    root = result.data;
    if (root.via.array.size < 2) {
        flb_plg_error(ctx->ins, "Invalid HELO message");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    o = root.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_STR) {
        flb_plg_error(ctx->ins, "Invalid HELO type message");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    if (strncmp(o.via.str.ptr, "HELO", 4) != 0 || o.via.str.size != 4) {
        flb_plg_error(ctx->ins, "Invalid HELO content message");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    flb_plg_debug(ctx->ins, "protocol: received HELO");

    /* Compose and send PING message */
    o = root.via.array.ptr[1];
    ret = secure_forward_ping(u_conn, o, fc, ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed PING");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* Expect a PONG */
    ret = secure_forward_read(ctx, u_conn, buf, sizeof(buf) - 1, &out_len);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "handshake error expecting HELO");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* Process PONG */
    ret = secure_forward_pong(ctx, buf, out_len);
    if (ret == -1) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    msgpack_unpacked_destroy(&result);
    return 0;
}

static int secure_forward_write_options(struct flb_upstream_conn *u_conn,
                                        struct flb_forward_config *fc,
                                        struct flb_forward *ctx,
                                        size_t size,
                                        char *chunk,
                                        size_t *bytes_sent_ptr)
{
    int ret;
    int opt_count = 1;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    size_t bytes_sent = 0;
    size_t chunk_size = 0;

    if(chunk) {
        chunk_size = strlen(chunk);
        if(chunk_size > 0) {
            opt_count++;
        }
    }
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    // options is map
    msgpack_pack_map(&mp_pck,opt_count);

    // "chunk": '<checksum-base-64>'
    if(chunk && chunk_size > 0) {
        msgpack_pack_str(&mp_pck, 5);
        msgpack_pack_str_body(&mp_pck, "chunk", 5);
        msgpack_pack_str(&mp_pck, chunk_size);
        msgpack_pack_str_body(&mp_pck, chunk, chunk_size);
    }

    // "size": entries
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "size", 4);
    msgpack_pack_int64(&mp_pck, size);

    ret = flb_io_net_write(u_conn, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    if (ret == -1) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return -1;
    }
    if(bytes_sent_ptr) *bytes_sent_ptr = bytes_sent;
    msgpack_sbuffer_destroy(&mp_sbuf);
    return 0;
}


static int secure_forward_read_ack(struct flb_upstream_conn *u_conn,
                                   struct flb_forward_config *fc,
                                   struct flb_forward *ctx,
                                   char *chunk)
{
    int ret;
    int i;
    size_t out_len;
    size_t off;
    const char *ack;
    size_t ack_len;
    int chunk_len;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object_map map;
    msgpack_object key;
    msgpack_object val;
    char buf[512];  /* ack should never be bigger */

    flb_plg_trace(ctx->ins, "wait ACK (%s)", chunk);

    chunk_len = strlen(chunk);

    /* Wait for server ACK */
    ret = secure_forward_read(ctx, u_conn, buf, sizeof(buf) - 1, &out_len);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot get ack");
        return -1;
    }

    /* Unpack message and validate */
    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, out_len, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        print_msgpack_status(ctx, ret, "ACK");
        goto error;
    }

    /* Parse ACK message */
    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "ACK response not MAP (type:%d)", root.type);
        goto error;
    }

    map = root.via.map;
    ack = NULL;
    /* Lookup ack field */
    for (i = 0; i < map.size; i++) {
        key = map.ptr[i].key;
        if (key.via.str.size == 3 && strncmp(key.via.str.ptr, "ack", 3) == 0) {
            val     = map.ptr[i].val;
            ack_len = val.via.str.size;
            ack     = val.via.str.ptr;
            break;
        }
    }

    if (!ack) {
        flb_plg_error(ctx->ins, "ack: ack not found");
        goto error;
    }

    if(ack_len != chunk_len) {
        flb_plg_error(ctx->ins,
                      "ack: ack len does not match ack(%d)(%.*s) chunk(%d)(%.*s)",
                      ack_len, ack_len, ack,
                      chunk_len, chunk_len, chunk);
        goto error;
    }

    if (strncmp(ack, chunk, ack_len) != 0) {
        flb_plg_error(ctx->ins, "ACK: mismatch (%s)", chunk);
        goto error;
    }

    flb_plg_debug(ctx->ins, "protocol: received ACK");

    msgpack_unpacked_destroy(&result);
    return 0;

 error:
    msgpack_unpacked_destroy(&result);
    return -1;

}


static int forward_config_init(struct flb_forward_config *fc,
                               struct flb_forward *ctx)
{
#ifdef FLB_HAVE_TLS
    /* Initialize Secure Forward mode */
    if (fc->secured == FLB_TRUE) {
        secure_forward_init(ctx, fc);
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
static int forward_config_ha(const char *upstream_file,
                             struct flb_forward *ctx,
                             struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct mk_list *head;
    struct flb_upstream_node *node;
    struct flb_forward_config *fc = NULL;

    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_plg_error(ctx->ins, "cannot load Upstream file");
        return -1;
    }

    /* Iterate nodes and create a forward_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);

        /* create forward_config context */
        fc = flb_calloc(1, sizeof(struct flb_forward_config));
        if (!fc) {
            flb_errno();
            flb_plg_error(ctx->ins, "failed config allocation");
            continue;
        }
        fc->secured = FLB_FALSE;

        /* Is TLS enabled ? */
        if (node->tls_enabled == FLB_TRUE) {
            fc->secured = FLB_TRUE;
        }

        /* Shared key */
        tmp = flb_upstream_node_get_property("empty_shared_key", node);
        if (tmp && flb_utils_bool(tmp)) {
            fc->empty_shared_key = FLB_TRUE;
        }
        else {
            fc->empty_shared_key = FLB_FALSE;
        }

        tmp = flb_upstream_node_get_property("shared_key", node);
        if (fc->empty_shared_key == FLB_TRUE) {
            fc->shared_key = flb_sds_create("");
        }
        else if (tmp) {
            fc->shared_key = flb_sds_create(tmp);
        }
        else {
            fc->shared_key = NULL;
        }

        tmp = flb_upstream_node_get_property("username", node);
        if (tmp) {
            fc->username = tmp;
        }
        else {
            fc->username = "";
        }

        tmp = flb_upstream_node_get_property("password", node);
        if (tmp) {
            fc->password = tmp;
        }
        else {
            fc->password = "";
        }

        /* Self Hostname (Shared key) */
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

        fc->require_ack_response = FLB_FALSE;
        fc->send_options = FLB_FALSE;

        /* send always options (with size) */
        tmp = flb_upstream_node_get_property("send_options", node);
        if (tmp) {
            fc->send_options = flb_utils_bool(tmp);
        }

        /* require ack response  (implies send_options) */
        tmp = flb_upstream_node_get_property("require_ack_response", node);
        if (tmp) {
            fc->require_ack_response = flb_utils_bool(tmp);
            if(fc->require_ack_response) {
                fc->send_options = FLB_TRUE;
            }
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
    const char *tmp;
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

    /* Set default values */
    ret = flb_output_config_map_set(ins, fc);
    if (ret == -1) {
        flb_free(fc);
        return -1;
    }

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
    flb_output_upstream_set(ctx->u, ins);

    /* Shared Key */
    tmp = flb_output_get_property("empty_shared_key", ins);
    if (tmp && flb_utils_bool(tmp)) {
        fc->empty_shared_key = FLB_TRUE;
    }

    tmp = flb_output_get_property("shared_key", ins);
    if (fc->empty_shared_key) {
        fc->shared_key = flb_sds_create("");
    }
    else if (tmp) {
        fc->shared_key = flb_sds_create(tmp);
    }
    else {
        fc->shared_key = NULL;
    }

    tmp = flb_output_get_property("username", ins);
    if (tmp) {
        fc->username = tmp;
    }

    tmp = flb_output_get_property("password", ins);
    if (tmp) {
        fc->password = tmp;
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
    tmp = flb_output_get_property("time_as_integer", ins);
    if (tmp) {
        fc->time_as_integer = flb_utils_bool(tmp);
    }

    /* send always options (with size) */
    tmp = flb_output_get_property("send_options", ins);
    if (tmp) {
        fc->send_options = flb_utils_bool(tmp);
    }

    /* require ack response  (implies send_options) */
    tmp = flb_output_get_property("require_ack_response", ins);
    if (tmp) {
        fc->require_ack_response = flb_utils_bool(tmp);
        if(fc->require_ack_response) {
            fc->send_options = FLB_TRUE;
        }
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
    const char *tmp;
    struct flb_forward *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_forward));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
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

static int data_compose(const void *data, size_t bytes,
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

static void cb_forward_flush(const void *data, size_t bytes,
                             const char *tag, int tag_len,
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
    void *tmp_buf = NULL;
    const void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_forward *ctx = out_context;
    struct flb_forward_config *fc = NULL;
    struct flb_upstream_conn *u_conn;
    struct flb_upstream_node *node;
    (void) i_ins;
    (void) config;
    char *chunkptr;
    struct flb_sha512 sha512;
    uint8_t checksum[64];
    char checksum_hex[33];

    if (ctx->ha_mode == FLB_TRUE) {
        node = flb_upstream_ha_node_get(ctx->ha);
        if (!node) {
            flb_plg_error(ctx->ins, "cannot get an Upstream HA node");
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

    flb_plg_debug(ctx->ins, "request %lu bytes to flush", bytes);

    /* Initialize packager */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Count number of entries, is there a better way to do this ? */
    entries = data_compose(data, bytes, &tmp_buf, &out_size, fc, ctx);
    out_buf = tmp_buf;
    if (out_buf == NULL && fc->time_as_integer == FLB_FALSE) {
        out_buf = data;
        out_size = bytes;
    }

    flb_plg_debug(ctx->ins, "%i entries tag='%s' tag_len=%i",
                  entries, tag, tag_len);

    /* Output: root array */
    msgpack_pack_array(&mp_pck, fc->send_options ? 3 : 2);
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
        flb_plg_error(ctx->ins, "no upstream connections available");
        msgpack_sbuffer_destroy(&mp_sbuf);
        if (fc->time_as_integer == FLB_TRUE) {
            flb_free(tmp_buf);
        }
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Shared Key
     * if ka_count > 0 it means the handshake has already been done lately */
    if (fc->shared_key && u_conn->ka_count == 0) {
        ret = secure_forward_handshake(u_conn, fc, ctx);
        flb_plg_debug(ctx->ins, "handshake status = %i", ret);
        if (ret == -1) {
            flb_upstream_conn_release(u_conn);
            msgpack_sbuffer_destroy(&mp_sbuf);
            if (fc->time_as_integer == FLB_TRUE) {
                flb_free(tmp_buf);
            }
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    /* Write message header */
    ret = flb_io_net_write(u_conn, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not write chunk header");
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_upstream_conn_release(u_conn);
        if (fc->time_as_integer == FLB_TRUE) {
            flb_free(tmp_buf);
        }
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    total = ret;

    /* Write body (records) */
    ret = flb_io_net_write(u_conn, out_buf, out_size, &bytes_sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error writing content body");
        if (fc->time_as_integer == FLB_TRUE) {
            flb_free(tmp_buf);
        }
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    total += bytes_sent;

    if (fc->time_as_integer == FLB_TRUE) {
        flb_free(tmp_buf);
    }

    if (fc->send_options) {
        chunkptr = NULL;
        if (fc->require_ack_response) {
            /* for ack we calculate  sha512 of context, take 16 bytes,  make 32 byte hex string of it */
            flb_sha512_init(&sha512);
            flb_sha512_update(&sha512,data,bytes);
            flb_sha512_sum(&sha512,checksum); // => 65 bytes
            secure_forward_bin_to_hex(checksum, 16, checksum_hex);
            checksum_hex[32] = '\0';
            chunkptr = (char*) checksum_hex;
        }

        flb_plg_debug(ctx->ins,
                      "send options entries=%d chunk='%s'",
                      entries, chunkptr ? chunkptr : "NULL");

        ret = secure_forward_write_options(u_conn, fc, ctx, entries, chunkptr, &bytes_sent);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "error writing option");
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        total += bytes_sent;

        if(chunkptr) {
            ret = secure_forward_read_ack(u_conn, fc, ctx, chunkptr);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "error wait ACK");
                flb_upstream_conn_release(u_conn);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
        }
    }

    flb_upstream_conn_release(u_conn);

    flb_plg_trace(ctx->ins, "ended write()=%d bytes", total);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "time_as_integer", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, time_as_integer),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "shared_key", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "self_hostname", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "empty_shared_key", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, empty_shared_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "send_options", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, send_options),
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "require_ack_response", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, require_ack_response),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "username", "",
     0, FLB_TRUE, offsetof(struct flb_forward_config, username),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "password", "",
     0, FLB_TRUE, offsetof(struct flb_forward_config, password),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "upstream", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_forward_plugin = {
    .name         = "forward",
    .description  = "Forward (Fluentd protocol)",
    .cb_init      = cb_forward_init,
    .cb_pre_run   = NULL,
    .cb_flush     = cb_forward_flush,
    .cb_exit      = cb_forward_exit,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
