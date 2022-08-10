/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_gzip.h>
#include <msgpack.h>

#include "forward.h"
#include "forward_format.h"

#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/socket.h>
#include <sys/un.h>
#endif

#define SECURED_BY "Fluent Bit"

#ifdef FLB_HAVE_TLS

static int io_net_write(struct flb_upstream_conn *conn, int unused_fd,
                        const void* data, size_t len, size_t *out_len)
{
    return flb_io_net_write(conn, data, len, out_len);
}

static int io_net_read(struct flb_upstream_conn *conn, int unused_fd,
                       void* buf, size_t len)
{
    return flb_io_net_read(conn, buf, len);
}

static int secure_forward_init(struct flb_forward *ctx,
                               struct flb_forward_config *fc)
{
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
                               struct flb_forward_config *fc,
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
        ret = fc->io_read(u_conn, fc->unix_fd, buf + buf_off, size - buf_off);
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
    size_t             length_entries[4];
    unsigned char     *data_entries[4];
    uint8_t            hash[64];
    int                result;

    if (buflen < 128) {
        return -1;
    }

    data_entries[0]   = (unsigned char *) fc->shared_key_salt;
    length_entries[0] = 16;

    data_entries[1]   = (unsigned char *) fc->self_hostname;
    length_entries[1] = strlen(fc->self_hostname);

    data_entries[2]   = (unsigned char *) ping->nonce;
    length_entries[2] = ping->nonce_len;

    data_entries[3]   = (unsigned char *) fc->shared_key;
    length_entries[3] = strlen(fc->shared_key);

    result = flb_hash_simple_batch(FLB_HASH_SHA512,
                                   4,
                                   data_entries,
                                   length_entries,
                                   hash,
                                   sizeof(hash));

    if (result != FLB_CRYPTO_SUCCESS) {
        return -1;
    }

    flb_forward_format_bin_to_hex(hash, 64, buf);

    return 0;
}

static int secure_forward_hash_password(struct flb_forward_config *fc,
                                        struct flb_forward_ping *ping,
                                        char *buf, int buflen)
{
    size_t             length_entries[3];
    unsigned char     *data_entries[3];
    uint8_t            hash[64];
    int                result;

    if (buflen < 128) {
        return -1;
    }

    data_entries[0]   = (unsigned char *) ping->auth;
    length_entries[0] = ping->auth_len;

    data_entries[1]   = (unsigned char *) fc->username;
    length_entries[1] = strlen(fc->username);

    data_entries[2]   = (unsigned char *) fc->password;
    length_entries[2] = strlen(fc->password);

    result = flb_hash_simple_batch(FLB_HASH_SHA512,
                                   3,
                                   data_entries,
                                   length_entries,
                                   hash,
                                   sizeof(hash));

    if (result != FLB_CRYPTO_SUCCESS) {
        return -1;
    }

    flb_forward_format_bin_to_hex(hash, 64, buf);

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
    }
    else {
        msgpack_pack_str(&mp_pck, 0);
        msgpack_pack_str_body(&mp_pck, "", 0);
        msgpack_pack_str(&mp_pck, 0);
        msgpack_pack_str_body(&mp_pck, "", 0);
    }

    ret = fc->io_write(u_conn, fc->unix_fd, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
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
    ret = secure_forward_read(ctx, u_conn, fc, buf, sizeof(buf) - 1, &out_len);
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
    ret = secure_forward_read(ctx, u_conn, fc, buf, sizeof(buf) - 1, &out_len);
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

static int forward_read_ack(struct flb_forward *ctx,
                            struct flb_forward_config *fc,
                            struct flb_upstream_conn *u_conn,
                            char *chunk, int chunk_len)
{
    int ret;
    int i;
    size_t out_len;
    size_t off;
    const char *ack;
    size_t ack_len;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object_map map;
    msgpack_object key;
    msgpack_object val;
    char buf[512];  /* ack should never be bigger */

    flb_plg_trace(ctx->ins, "wait ACK (%.*s)", chunk_len, chunk);

    /* Wait for server ACK */
    ret = secure_forward_read(ctx, u_conn, fc, buf, sizeof(buf) - 1, &out_len);
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

    if (ack_len != chunk_len) {
        flb_plg_error(ctx->ins,
                      "ack: ack len does not match ack(%ld)(%.*s) chunk(%d)(%.*s)",
                      ack_len, (int) ack_len, ack,
                      chunk_len, (int) chunk_len, chunk);
        goto error;
    }

    if (strncmp(ack, chunk, ack_len) != 0) {
        flb_plg_error(ctx->ins, "ACK: mismatch received=%s, expected=(%.*s)",
                      ack, chunk_len, chunk);
        goto error;
    }

    flb_plg_debug(ctx->ins, "protocol: received ACK %s", ack);
    msgpack_unpacked_destroy(&result);
    return 0;

 error:
    msgpack_unpacked_destroy(&result);
    return -1;
}


static int forward_config_init(struct flb_forward_config *fc,
                               struct flb_forward *ctx)
{
    if (fc->io_read == NULL || fc->io_write == NULL) {
        flb_plg_error(ctx->ins, "io_read/io_write is NULL");
        return -1;
    }

#ifdef FLB_HAVE_TLS
    /* Initialize Secure Forward mode */
    if (fc->secured == FLB_TRUE) {
        secure_forward_init(ctx, fc);
    }
#endif

    /* Generate the shared key salt */
    if (flb_random_bytes(fc->shared_key_salt, 16)) {
        flb_plg_error(ctx->ins, "cannot generate shared key salt");
        return -1;
    }

    mk_list_add(&fc->_head, &ctx->configs);
    return 0;
}

static flb_sds_t config_get_property(char *prop,
                                     struct flb_upstream_node *node,
                                     struct flb_forward *ctx)
{
    if (node) {
        return (flb_sds_t) flb_upstream_node_get_property(prop, node);
    }
    else {
        return (flb_sds_t) flb_output_get_property(prop, ctx->ins);
    }
}

static int config_set_properties(struct flb_upstream_node *node,
                                 struct flb_forward_config *fc,
                                 struct flb_forward *ctx)
{
    flb_sds_t tmp;

    /* Shared Key */
    tmp = config_get_property("empty_shared_key", node, ctx);
    if (tmp && flb_utils_bool(tmp)) {
        fc->empty_shared_key = FLB_TRUE;
    }
    else {
        fc->empty_shared_key = FLB_FALSE;
    }

    tmp = config_get_property("shared_key", node, ctx);
    if (fc->empty_shared_key) {
        fc->shared_key = flb_sds_create("");
    }
    else if (tmp) {
        fc->shared_key = flb_sds_create(tmp);
    }
    else {
        fc->shared_key = NULL;
    }

    tmp = config_get_property("username", node, ctx);
    if (tmp) {
        fc->username = tmp;
    }
    else {
        fc->username = "";
    }

    tmp = config_get_property("password", node, ctx);
    if (tmp) {
        fc->password = tmp;
    }
    else {
        fc->password = "";
    }

    /* Self Hostname */
    tmp = config_get_property("self_hostname", node, ctx);
    if (tmp) {
        fc->self_hostname = flb_sds_create(tmp);
    }
    else {
        fc->self_hostname = flb_sds_create("localhost");
    }

    /* Backward compatible timing mode */
    tmp = config_get_property("time_as_integer", node, ctx);
    if (tmp) {
        fc->time_as_integer = flb_utils_bool(tmp);
    }
    else {
        fc->time_as_integer = FLB_FALSE;
    }

    /* send always options (with size) */
    tmp = config_get_property("send_options", node, ctx);
    if (tmp) {
        fc->send_options = flb_utils_bool(tmp);
    }

    /* require ack response  (implies send_options) */
    tmp = config_get_property("require_ack_response", node, ctx);
    if (tmp) {
        fc->require_ack_response = flb_utils_bool(tmp);
        if (fc->require_ack_response) {
            fc->send_options = FLB_TRUE;
        }
    }

    /* Tag Overwrite */
    tmp = config_get_property("tag", node, ctx);
    if (tmp) {
        /* Set the tag */
        fc->tag = flb_sds_create(tmp);
        if (!fc->tag) {
            flb_plg_error(ctx->ins, "cannot allocate tag");
            return -1;
        }

#ifdef FLB_HAVE_RECORD_ACCESSOR
        /* Record Accessor */
        fc->ra_tag = flb_ra_create(fc->tag, FLB_TRUE);
        if (!fc->ra_tag) {
            flb_plg_error(ctx->ins, "cannot create record accessor for tag: %s",
                          fc->tag);
            return -1;
        }

        /* Static record accessor ? (no dynamic values from map) */
        fc->ra_static = flb_ra_is_static(fc->ra_tag);
#endif
    }
    else {
        fc->tag = NULL;

    }

    /* compress (implies send_options) */
    tmp = config_get_property("compress", node, ctx);
    if (tmp) {
        if (!strcasecmp(tmp, "text")) {
            fc->compress = COMPRESS_NONE;
        }
        else if (!strcasecmp(tmp, "gzip")) {
            fc->compress = COMPRESS_GZIP;
            fc->send_options = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "invalid compress mode: %s", tmp);
            return -1;
        }
    }
    else {
        fc->compress = COMPRESS_NONE;
    }

    if (fc->compress != COMPRESS_NONE && fc->time_as_integer == FLB_TRUE) {
        flb_plg_error(ctx->ins, "compress mode %s is incompatible with "
                      "time_as_integer", tmp);
        return -1;
    }

#ifdef FLB_HAVE_RECORD_ACCESSOR
    if (fc->compress != COMPRESS_NONE &&
        (fc->ra_tag && fc->ra_static == FLB_FALSE) ) {
        flb_plg_error(ctx->ins, "compress mode %s is incompatible with dynamic "
                      "tags", tmp);
        return -1;
    }
#endif

    return 0;
}

static void forward_config_destroy(struct flb_forward_config *fc)
{
    flb_sds_destroy(fc->shared_key);
    flb_sds_destroy(fc->self_hostname);
    flb_sds_destroy(fc->tag);

#ifdef FLB_HAVE_RECORD_ACCESSOR
    if (fc->ra_tag) {
        flb_ra_destroy(fc->ra_tag);
    }
#endif

    flb_free(fc);
}

/* Configure in HA mode */
static int forward_config_ha(const char *upstream_file,
                             struct flb_forward *ctx,
                             struct flb_config *config)
{
    int ret;
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
        fc->unix_fd = -1;
        fc->secured = FLB_FALSE;
        fc->io_write = io_net_write;
        fc->io_read  = io_net_read;

        /* Is TLS enabled ? */
        if (node->tls_enabled == FLB_TRUE) {
            fc->secured = FLB_TRUE;
        }

        /* Read properties into 'fc' context */
        config_set_properties(node, fc, ctx);

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

    flb_output_upstream_ha_set(ctx->ha, ctx->ins);

    return 0;
}
#ifdef FLB_HAVE_UNIX_SOCKET
static int forward_unix_create(struct flb_forward_config *config,
                               struct flb_forward *ctx)
{
    flb_sockfd_t fd = -1;
    struct sockaddr_un address;

    if (sizeof(address.sun_path) <= flb_sds_len(config->unix_path)) {
        flb_plg_error(ctx->ins, "unix_path is too long");
        return -1;
    }

    memset(&address, 0, sizeof(struct sockaddr_un));

    fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);
    if (fd < 0) {
        flb_plg_error(ctx->ins, "flb_net_socket_create error");
        return -1;
    }
    config->unix_fd = fd;

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, config->unix_path, flb_sds_len(config->unix_path));

    if(connect(fd, (const struct sockaddr*) &address, sizeof(address)) < 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    flb_net_socket_nonblocking(config->unix_fd);

    return 0;
}

static int io_unix_write(struct flb_upstream_conn *unused, int fd, const void* data,
                         size_t len, size_t *out_len)
{
    return flb_io_fd_write(fd, data, len, out_len);
}

static int io_unix_read(struct flb_upstream_conn *unused, int fd, void* buf,size_t len)
{
    return flb_io_fd_read(fd, buf, len);
}

#endif

static int forward_config_simple(struct flb_forward *ctx,
                                 struct flb_output_instance *ins,
                                 struct flb_config *config)
{
    int ret;
    int io_flags;
    struct flb_forward_config *fc = NULL;
    struct flb_upstream *upstream;

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 24224, ins);

    /* Configuration context */
    fc = flb_calloc(1, sizeof(struct flb_forward_config));
    if (!fc) {
        flb_errno();
        return -1;
    }
    fc->unix_fd = -1;
    fc->secured = FLB_FALSE;
    fc->io_write = NULL;
    fc->io_read  = NULL;

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

    if (fc->unix_path) {
#ifdef FLB_HAVE_UNIX_SOCKET
        if(forward_unix_create(fc, ctx) < 0) {
            flb_free(fc);
            flb_free(ctx);
            return -1;
        }
        fc->io_write = io_unix_write;
        fc->io_read  = io_unix_read;
#else
        flb_plg_error(ctx->ins, "unix_path is not supported");
        flb_free(fc);
        flb_free(ctx);
        return -1;
#endif /* FLB_HAVE_UNIX_SOCKET */
    }
    else {
        /* Prepare an upstream handler */
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       io_flags, ins->tls);
        if (!upstream) {
            flb_free(fc);
            flb_free(ctx);
            return -1;
        }
        fc->io_write = io_net_write;
        fc->io_read  = io_net_read;
        ctx->u = upstream;
        flb_output_upstream_set(ctx->u, ins);
    }
    /* Read properties into 'fc' context */
    config_set_properties(NULL, fc, ctx);

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

struct flb_forward_config *flb_forward_target(struct flb_forward *ctx,
                                              struct flb_upstream_node **node)
{
    struct flb_forward_config *fc = NULL;
    struct flb_upstream_node *f_node;

    if (ctx->ha_mode == FLB_TRUE) {
        f_node = flb_upstream_ha_node_get(ctx->ha);
        if (!f_node) {
            return NULL;
        }

        /* Get forward_config stored in node opaque data */
        fc = flb_upstream_node_get_data(f_node);
        *node = f_node;
    }
    else {
        fc = mk_list_entry_first(&ctx->configs,
                                 struct flb_forward_config,
                                 _head);
        *node = NULL;
    }
    return fc;
}

static int flush_message_mode(struct flb_forward *ctx,
                              struct flb_forward_config *fc,
                              struct flb_upstream_conn *u_conn,
                              char *buf, size_t size)
{
    int ret;
    int ok = MSGPACK_UNPACK_SUCCESS;
    size_t sent = 0;
    size_t rec_size;
    size_t pre = 0;
    size_t off = 0;
    msgpack_object root;
    msgpack_object options;
    msgpack_object chunk;
    msgpack_unpacked result;

    /* If the sender requires 'ack' from the remote end-point */
    if (fc->require_ack_response) {
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, buf, size, &off) == ok) {
            /* get the record size */
            rec_size = off - pre;

            /* write single message */
            ret = fc->io_write(u_conn,fc->unix_fd,
                                   buf + pre, rec_size, &sent);
            pre = off;

            if (ret == -1) {
                /*
                 * FIXME: we might take advantage of 'flush_ctx' and store the
                 * message that failed it delivery, we could have retries but with
                 * the flush context.
                 */
                flb_plg_error(ctx->ins, "message_mode: error sending message");
                msgpack_unpacked_destroy(&result);
                return FLB_RETRY;
            }

            /* Sucessful delivery, now get message 'chunk' and wait for it */
            root = result.data;
            options = root.via.array.ptr[3];
            chunk = options.via.map.ptr[0].val;

            /* Read ACK */
            ret = forward_read_ack(ctx, fc, u_conn,
                                   (char *) chunk.via.str.ptr, chunk.via.str.size);
            if (ret == -1) {
                msgpack_unpacked_destroy(&result);
                return FLB_RETRY;
            }
        }

        /* All good */
        msgpack_unpacked_destroy(&result);
        return FLB_OK;
    }

    /* Normal data write */
    ret = fc->io_write(u_conn, fc->unix_fd, buf, size, &sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "message_mode: error sending data");
        return FLB_RETRY;
    }

    return FLB_OK;
}

/*
 * Forward Mode: this is the generic mechanism used in Fluent Bit, it takes
 * advantage of the internal data representation and avoid re-formatting data,
 * it only sends a msgpack header, pre-existent 'data' records and options.
 *
 * note: if the user has enabled time_as_integer (compat mode for Fluentd <= 0.12),
 * the 'flush_forward_compat_mode' is used instead.
 */
static int flush_forward_mode(struct flb_forward *ctx,
                              struct flb_forward_config *fc,
                              struct flb_upstream_conn *u_conn,
                              const char *tag, int tag_len,
                              const void *data, size_t bytes,
                              char *opts_buf, size_t opts_size)
{
    int ret;
    int entries;
    size_t off = 0;
    size_t bytes_sent;
    msgpack_object root;
    msgpack_object chunk;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    void *final_data;
    size_t final_bytes;

    /* Pack message header */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, fc->send_options ? 3 : 2);

    /* Tag */
    flb_forward_format_append_tag(ctx, fc, &mp_pck, NULL, tag, tag_len);

    if (fc->compress == COMPRESS_GZIP) {
        /* When compress is set, we switch from using Forward mode to using
         * CompressedPackedForward mode.
         */
        ret = flb_gzip_compress((void *) data, bytes, &final_data, &final_bytes);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not compress entries");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return FLB_RETRY;
        }

        msgpack_pack_bin(&mp_pck, final_bytes);

    } else {
        final_data = (void *) data;
        final_bytes = bytes;

        entries = flb_mp_count(data, bytes);
        msgpack_pack_array(&mp_pck, entries);
    }

    /* Write message header */
    ret = fc->io_write(u_conn, fc->unix_fd, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not write forward header");
        msgpack_sbuffer_destroy(&mp_sbuf);
        if (fc->compress == COMPRESS_GZIP) {
            flb_free(final_data);
        }
        return FLB_RETRY;
    }
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* Write entries */
    ret = fc->io_write(u_conn, fc->unix_fd, final_data, final_bytes, &bytes_sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not write forward entries");
        if (fc->compress == COMPRESS_GZIP) {
            flb_free(final_data);
        }
        return FLB_RETRY;
    }

    if (fc->compress == COMPRESS_GZIP) {
        flb_free(final_data);
    }

    /* Write options */
    if (fc->send_options == FLB_TRUE) {
        ret = fc->io_write(u_conn, fc->unix_fd, opts_buf, opts_size, &bytes_sent);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not write forward options");
            return FLB_RETRY;
        }
    }

    /* If the sender requires 'ack' from the remote end-point */
    if (fc->require_ack_response) {
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, opts_buf, opts_size, &off);
        if (ret != MSGPACK_UNPACK_SUCCESS) {
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        /* Sucessful delivery, now get message 'chunk' and wait for it */
        root = result.data;

        /* 'chunk' is always in the first key of the map */
        chunk = root.via.map.ptr[0].val;

        /* Read ACK */
        ret = forward_read_ack(ctx, fc, u_conn,
                               (char *) chunk.via.str.ptr, chunk.via.str.size);
        if (ret == -1) {
            msgpack_unpacked_destroy(&result);
            return FLB_RETRY;
        }

        /* All good */
        msgpack_unpacked_destroy(&result);
        return FLB_OK;
    }

    return FLB_OK;
}

/*
 * Forward Mode Compat: data is packaged in Forward mode but the timestamps are
 * integers (compat mode for Fluentd <= 0.12).
 */
static int flush_forward_compat_mode(struct flb_forward *ctx,
                                     struct flb_forward_config *fc,
                                     struct flb_upstream_conn *u_conn,
                                     const char *tag, int tag_len,
                                     const void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    size_t bytes_sent;
    msgpack_object root;
    msgpack_object chunk;
    msgpack_object map; /* dummy parameter */
    msgpack_unpacked result;

    /* Write message header */
    ret = fc->io_write(u_conn, fc->unix_fd, data, bytes, &bytes_sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not write forward compat mode records");
        return FLB_RETRY;
    }

    /* If the sender requires 'ack' from the remote end-point */
    if (fc->require_ack_response) {
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, data, bytes, &off);
        if (ret != MSGPACK_UNPACK_SUCCESS) {
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        /* Sucessful delivery, now get message 'chunk' and wait for it */
        root = result.data;

        map = root.via.array.ptr[2];

        /* 'chunk' is always in the first key of the map */
        chunk = map.via.map.ptr[0].val;

        /* Read ACK */
        ret = forward_read_ack(ctx, fc, u_conn,
                               (char *) chunk.via.str.ptr, chunk.via.str.size);
        if (ret == -1) {
            msgpack_unpacked_destroy(&result);
            return FLB_RETRY;
        }

        /* All good */
        msgpack_unpacked_destroy(&result);
        return FLB_OK;
    }

    return FLB_OK;
}

static void cb_forward_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    int ret = -1;
    int mode;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    void *tmp_buf = NULL;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_forward *ctx = out_context;
    struct flb_forward_config *fc = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    struct flb_upstream_node *node = NULL;
    struct flb_forward_flush *flush_ctx;
    (void) i_ins;
    (void) config;

    fc = flb_forward_target(ctx, &node);
    if (!fc) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_plg_debug(ctx->ins, "request %lu bytes to flush",
                  event_chunk->size);

    /* Initialize packager */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Flush context: structure used to pass custom information to the
     * formatter function.
     */
    flush_ctx = flb_calloc(1, sizeof(struct flb_forward_flush));
    if (!flush_ctx) {
        flb_errno();
        msgpack_sbuffer_destroy(&mp_sbuf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    flush_ctx->fc = fc;

    /* Format the right payload and retrieve the 'forward mode' used */
    mode = flb_forward_format(config, i_ins, ctx, flush_ctx,
                              event_chunk->tag, flb_sds_len(event_chunk->tag),
                              event_chunk->data, event_chunk->size,
                              &out_buf, &out_size);

    /* Get a TCP connection instance */
    if (fc->unix_path == NULL) {
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
            flb_free(flush_ctx);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    /*
     * Shared Key: if ka_count > 0 it means the handshake has already been done lately
     */
    if (fc->shared_key && u_conn->ka_count == 0) {
        ret = secure_forward_handshake(u_conn, fc, ctx);
        flb_plg_debug(ctx->ins, "handshake status = %i", ret);
        if (ret == -1) {
            if (u_conn) {
                flb_upstream_conn_release(u_conn);
            }
            msgpack_sbuffer_destroy(&mp_sbuf);
            if (fc->time_as_integer == FLB_TRUE) {
                flb_free(tmp_buf);
            }
            flb_free(flush_ctx);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    if (mode == MODE_MESSAGE) {
        ret = flush_message_mode(ctx, fc, u_conn, out_buf, out_size);
        flb_free(out_buf);
    }
    else if (mode == MODE_FORWARD) {
        ret = flush_forward_mode(ctx, fc, u_conn,
                                 event_chunk->tag, flb_sds_len(event_chunk->tag),
                                 event_chunk->data, event_chunk->size,
                                 out_buf, out_size);
        flb_free(out_buf);
    }
    else if (mode == MODE_FORWARD_COMPAT) {
        ret = flush_forward_compat_mode(ctx, fc, u_conn,
                                        event_chunk->tag,
                                        flb_sds_len(event_chunk->tag),
                                        out_buf, out_size);
        flb_free(out_buf);
    }

    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    flb_free(flush_ctx);
    FLB_OUTPUT_RETURN(ret);
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
        if (fc->unix_path && fc->unix_fd > 0) {
            close(fc->unix_fd);
        }
        mk_list_del(&fc->_head);
        forward_config_destroy(fc);
    }

    if (ctx->ha_mode == FLB_TRUE) {
        if (ctx->ha) {
            flb_upstream_ha_destroy(ctx->ha);
        }
    }
    else {
        if (ctx->u) {
            flb_upstream_destroy(ctx->u);
        }
    }

    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "time_as_integer", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, time_as_integer),
     "Set timestamp in integer format (compat mode for old Fluentd v0.12)"
    },
    {
     FLB_CONFIG_MAP_STR, "shared_key", NULL,
     0, FLB_FALSE, 0,
     "Shared key for authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "self_hostname", NULL,
     0, FLB_FALSE, 0,
     "Hostname"
    },
    {
     FLB_CONFIG_MAP_BOOL, "empty_shared_key", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, empty_shared_key),
     "Set an empty shared key for authentication"
    },
    {
     FLB_CONFIG_MAP_BOOL, "send_options", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, send_options),
     "Send 'forward protocol options' to remote endpoint"
    },
    {
     FLB_CONFIG_MAP_BOOL, "require_ack_response", "false",
     0, FLB_TRUE, offsetof(struct flb_forward_config, require_ack_response),
     "Require that remote endpoint confirms data reception"
    },
    {
     FLB_CONFIG_MAP_STR, "username", "",
     0, FLB_TRUE, offsetof(struct flb_forward_config, username),
     "Username for authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "password", "",
     0, FLB_TRUE, offsetof(struct flb_forward_config, password),
     "Password for authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "unix_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_forward_config, unix_path),
     "Path to unix socket. It is ignored when 'upstream' property is set"
    },
    {
     FLB_CONFIG_MAP_STR, "upstream", NULL,
     0, FLB_FALSE, 0,
     "Path to 'upstream' configuration file (define multiple nodes)"
    },
    {
     FLB_CONFIG_MAP_STR, "tag", NULL,
     0, FLB_FALSE, 0,
     "Set a custom Tag for the outgoing records"
    },
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Compression mode"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_forward_plugin = {
    .name         = "forward",
    .description  = "Forward (Fluentd protocol)",

    /* Callbacks */
    .cb_init      = cb_forward_init,
    .cb_pre_run   = NULL,
    .cb_flush     = cb_forward_flush,
    .cb_exit      = cb_forward_exit,
    .workers      = 2,

    /* Config map validator */
    .config_map   = config_map,

    /* Test */
    .test_formatter.callback = flb_forward_format,

    /* Flags */
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,

    /* Event types */
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS
};
