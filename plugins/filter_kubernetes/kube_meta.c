/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <msgpack.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_property.h"

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
static int get_local_pod_info(struct flb_kube *ctx)
{
    int ret;
    char *ns;
    size_t ns_size;
    char *tk = NULL;
    size_t tk_size = 0;
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
    ret = file_to_buffer(ctx->token_file, &tk, &tk_size);
    if (ret == -1) {
        flb_warn("[filter_kube] cannot open %s", FLB_KUBE_TOKEN);
    }

    /* Namespace */
    ctx->namespace = ns;
    ctx->namespace_len = ns_size;

    /* POD Name */
    hostname = getenv("HOSTNAME");
    if (hostname) {
        ctx->podname = flb_strdup(hostname);
        ctx->podname_len = strlen(ctx->podname);
    }
    else {
        char tmp[256];
        gethostname(tmp, 256);
        ctx->podname = flb_strdup(tmp);
        ctx->podname_len = strlen(ctx->podname);
    }

    /* Token */
    ctx->token = tk;
    ctx->token_len = tk_size;

    /* HTTP Auth Header */
    ctx->auth = flb_malloc(tk_size + 32);
    if (!ctx->auth) {
        return FLB_FALSE;
    }
    ctx->auth_len = snprintf(ctx->auth, tk_size + 32,
                             "Bearer %s",
                             tk);
    return FLB_TRUE;
}

/* Gather metadata from API Server */
static int get_api_server_info(struct flb_kube *ctx,
                               char *namespace, char *podname,
                               char **out_buf, size_t *out_size)
{
    int ret;
    int packed = -1;
    int root_type;
    size_t b_sent;
    char uri[1024];
    char *buf;
    size_t size;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;

    /*
     * If a file exists called namespace-podname.meta, load it and use it.
     * If not, fall back to API. This is primarily for diagnostic purposes,
     * e.g. debugging new parsers.
     */
    if (ctx->meta_preload_cache_dir && namespace && podname) {
        int fd;
        char *payload = NULL;
        size_t payload_size = 0;
        struct stat sb;

        ret = snprintf(uri, sizeof(uri) - 1, "%s/%s-%s.meta", ctx->meta_preload_cache_dir, namespace, podname);
        if (ret > 0) {
            fd = open(uri, O_RDONLY, 0);
            if (fd > 0) {
                if (fstat(fd, &sb) == 0) {
                    payload = flb_malloc(sb.st_size);
                    if (payload) {
                        ret = read(fd, payload, sb.st_size);
                        if (ret == sb.st_size) {
                            payload_size = ret;
                        }
                    }
                }
                close(fd);
            }
        }
        if (payload_size) {
            packed = flb_pack_json(payload, payload_size,
                                   &buf, &size, &root_type);
        }

        if (payload) {
            flb_free(payload);
        }
    }

    if (packed == -1) {
        if (!ctx->upstream) {
            return -1;
        }

        u_conn = flb_upstream_conn_get(ctx->upstream);
        if (!u_conn) {
            flb_error("[filter_kube] upstream connection error");
            return -1;
        }

        ret = snprintf(uri, sizeof(uri) - 1,
                       FLB_KUBE_API_FMT,
                       namespace, podname);
        if (ret == -1) {
            flb_upstream_conn_release(u_conn);
            return -1;
        }

        /* Compose HTTP Client request */
        c = flb_http_client(u_conn, FLB_HTTP_GET,
                            uri,
                            NULL, 0, NULL, 0, NULL, 0);
        flb_http_buffer_size(c, ctx->buffer_size);

        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
        flb_http_add_header(c, "Connection", 10, "close", 5);
        if (ctx->auth_len > 0) {
            flb_http_add_header(c, "Authorization", 13, ctx->auth, ctx->auth_len);
        }

        /* Perform request */
        ret = flb_http_do(c, &b_sent);
        flb_debug("[filter_kube] API Server (ns=%s, pod=%s) http_do=%i, HTTP Status: %i",
                  namespace, podname, ret, c->resp.status);

        if (ret != 0 || c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_debug("[filter_kube] API Server response\n%s",
                          c->resp.payload);
            }
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            return -1;
        }
        packed = flb_pack_json(c->resp.payload, c->resp.payload_size,
                               &buf, &size, &root_type);

        /* release resources */
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
    }

    /* validate pack */
    if (packed == -1) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;

    return 0;
}

static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    struct flb_kube_meta *meta = data;

    if (meta->podname == NULL && strcmp((char *) name, "pod_name") == 0) {
        meta->podname = flb_strndup((char *) value, vlen);
        meta->podname_len = vlen;
        meta->fields++;
    }
    else if (meta->namespace == NULL &&
             strcmp((char *) name, "namespace_name") == 0) {
        meta->namespace = flb_strndup((char *) value, vlen);
        meta->namespace_len = vlen;
        meta->fields++;
    }
    else if (meta->container_name == NULL &&
             strcmp((char *) name, "container_name") == 0) {
        meta->container_name = flb_strndup((char *) value, vlen);
        meta->container_name_len = vlen;
        meta->skip++;
    }
    else if (meta->docker_id == NULL &&
             strcmp((char *) name, "docker_id") == 0) {
        meta->docker_id = flb_strndup((char *) value, vlen);
        meta->docker_id_len = vlen;
        meta->skip++;
    }
    else if (meta->container_hash == NULL &&
             strcmp((char *) name, "container_hash") == 0) {
        meta->container_hash = flb_strndup((char *) value, vlen);
        meta->container_hash_len = vlen;
        meta->skip++;
    }

    return;
}

static int merge_meta(struct flb_kube_meta *meta, struct flb_kube *ctx,
                      char *api_buf, size_t api_size,
                      char **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int map_size;
    int meta_found = FLB_FALSE;
    int spec_found = FLB_FALSE;
    int have_uid = -1;
    int have_labels = -1;
    int have_annotations = -1;
    int have_nodename = -1;
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_unpacked api_result;
    msgpack_unpacked meta_result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object meta_val;
    msgpack_object spec_val;
    msgpack_object api_map;
    msgpack_object ann_map;
    struct flb_kube_props props = {0};

    /*
     * - reg_buf: is a msgpack Map containing meta captured using Regex
     *
     * - api_buf: metadata associated to namespace and POD Name coming from
     *            the API server.
     *
     * When merging data we aim to add the following keys from the API server:
     *
     * - pod_id
     * - labels
     * - annotations
     */

    /* Initialize output msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Set map size: current + pod_id, labels and annotations */
    map_size = meta->fields;

    /* Iterate API server msgpack and lookup specific fields */
    off = 0;
    msgpack_unpacked_init(&api_result);
    ret = msgpack_unpack_next(&api_result, api_buf, api_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        msgpack_unpacked_destroy(&api_result);
        return -1;
    }

    api_map = api_result.data;

    /* At this point map points to the ROOT map, eg:
     *
     * {
     *  "kind": "Pod",
     *  "apiVersion": "v1",
     *  "metadata": {
     *    "name": "fluent-bit-rz47v",
     *    "generateName": "fluent-bit-",
     *    "namespace": "kube-system",
     *    "selfLink": "/api/v1/namespaces/kube-system/pods/fluent-bit-rz47v",
     *  ....
     * }
     *
     * We are interested into the 'metadata' map value.
     */
    for (i = 0; i < api_map.via.map.size; i++) {
        k = api_map.via.map.ptr[i].key;
        if (k.via.str.size == 8 && strncmp(k.via.str.ptr, "metadata", 8) == 0) {
            meta_val = api_map.via.map.ptr[i].val;
            meta_found = FLB_TRUE;
            break;
        }
    }

    /* We are also interested in the nodeName from 'spec' map value. */
    for (i = 0; i < api_map.via.map.size; i++) {
       k = api_map.via.map.ptr[i].key;
       if (k.via.str.size == 4 && strncmp(k.via.str.ptr, "spec", 4) == 0) {
           spec_val = api_map.via.map.ptr[i].val;
           spec_found = FLB_TRUE;
           break;
       }
    }

    if (meta_found == FLB_FALSE) {
        msgpack_unpacked_destroy(&api_result);
        msgpack_sbuffer_destroy(&mp_sbuf);
        return -1;
    }

    /* Process metadata map value */
    msgpack_unpacked_init(&meta_result);
    for (i = 0; i < meta_val.via.map.size; i++) {
        k = meta_val.via.map.ptr[i].key;

        char *ptr = (char *) k.via.str.ptr;
        size_t size = k.via.str.size;

        if (size == 3 && strncmp(ptr, "uid", 3) == 0) {
            have_uid = i;
            map_size++;
        }
        else if (size == 6 && strncmp(ptr, "labels", 6) == 0) {
            have_labels = i;
            map_size++;
        }

        else if (size == 11 && strncmp(ptr, "annotations", 11) == 0) {
            have_annotations = i;
            if (ctx->annotations == FLB_TRUE) {
                map_size++;
            }
        }

        if (have_uid >= 0 && have_labels >= 0 && have_annotations >= 0) {
            break;
        }
    }

    /* Process spec map value for nodeName */
    if (spec_found == FLB_TRUE) {
        for (i = 0; i < spec_val.via.map.size; i++) {
            k = spec_val.via.map.ptr[i].key;
            if (k.via.str.size == 8 &&
                strncmp(k.via.str.ptr, "nodeName", 8) == 0) {
                have_nodename = i;
                map_size++;
                break;
            }
        }
    }

    /* Append Regex fields */
    msgpack_pack_map(&mp_pck, map_size);
    if (meta->podname != NULL) {
        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "pod_name", 8);
        msgpack_pack_str(&mp_pck, meta->podname_len);
        msgpack_pack_str_body(&mp_pck, meta->podname, meta->podname_len);
    }
    if (meta->namespace != NULL) {
        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
        msgpack_pack_str(&mp_pck, meta->namespace_len);
        msgpack_pack_str_body(&mp_pck, meta->namespace, meta->namespace_len);
    }

    /* Append API Server content */
    if (have_uid >= 0) {
        v = meta_val.via.map.ptr[have_uid].val;

        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "pod_id", 6);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_labels >= 0) {
        k = meta_val.via.map.ptr[have_labels].key;
        v = meta_val.via.map.ptr[have_labels].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_annotations >= 0 && ctx->annotations == FLB_TRUE) {
        k = meta_val.via.map.ptr[have_annotations].key;
        v = meta_val.via.map.ptr[have_annotations].val;

        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    if (have_nodename >= 0) {
        v = spec_val.via.map.ptr[have_nodename].val;

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "host", 4);
        msgpack_pack_object(&mp_pck, v);
    }

    /* Process configuration suggested through Annotations */
    if (have_annotations >= 0) {
        ann_map = meta_val.via.map.ptr[have_annotations].val;

        /* Iterate annotations keys and look for 'logging' key */
        if (ann_map.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < ann_map.via.map.size; i++) {
                k = ann_map.via.map.ptr[i].key;
                v = ann_map.via.map.ptr[i].val;

                if (k.via.str.size > 13 && /* >= 'fluentbit.io/' */
                    strncmp(k.via.str.ptr, "fluentbit.io/", 13) == 0) {

                    /* Validate and set the property */
                    flb_kube_prop_set(ctx, meta,
                                      (char *) k.via.str.ptr + 13,
                                      k.via.str.size - 13,
                                      (char *) v.via.str.ptr,
                                      v.via.str.size,
                                      &props);
                }
            }
        }

        /* Pack Annotation properties */
        void *prop_buf;
        size_t prop_size;
        flb_kube_prop_pack(&props, &prop_buf, &prop_size);
        msgpack_sbuffer_write(&mp_sbuf, prop_buf, prop_size);
        flb_kube_prop_destroy(&props);
        flb_free(prop_buf);
    }

    msgpack_unpacked_destroy(&api_result);
    msgpack_unpacked_destroy(&meta_result);

    /* Set outgoing msgpack buffer */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static inline int extract_meta(struct flb_kube *ctx, char *tag, int tag_len,
                               char *data, size_t data_size,
                               struct flb_kube_meta *meta)
{
    int i;
    size_t off = 0;
    ssize_t n;
    char *container = NULL;
    int container_found = FLB_FALSE;
    int container_length = 0;
    struct flb_regex_search result;
    msgpack_unpacked mp_result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object key;
    msgpack_object val;

    /* Reset meta context */
    memset(meta, '\0', sizeof(struct flb_kube_meta));

    /* Journald */
    if (ctx->use_journal == FLB_TRUE) {
        off = 0;
        msgpack_unpacked_init(&mp_result);
        while (msgpack_unpack_next(&mp_result, data, data_size, &off) == MSGPACK_UNPACK_SUCCESS) {
            root = mp_result.data;
            if (root.type != MSGPACK_OBJECT_ARRAY) {
                continue;
            }

            /* Lookup the CONTAINER_NAME key/value */
            map = root.via.array.ptr[1];
            for (i = 0; i < map.via.map.size; i++) {
                key = map.via.map.ptr[i].key;
                if (key.via.str.size != 14) {
                    continue;
                }

                if (strncmp(key.via.str.ptr, "CONTAINER_NAME", 14) == 0) {
                    val = map.via.map.ptr[i].val;
                    container = (char *) val.via.str.ptr;
                    container_length = val.via.str.size;
                    container_found = FLB_TRUE;
                    break;
                }
            }

            if (container_found == FLB_TRUE) {
                break;
            }
        }

        if (container_found == FLB_FALSE) {
            msgpack_unpacked_destroy(&mp_result);
            return -1;
        }
        n = flb_regex_do(ctx->regex,
                         (unsigned char *) container, container_length,
                         &result);
        msgpack_unpacked_destroy(&mp_result);
    }
    else {
        /* Lookup using Tag string */
        n = flb_regex_do(ctx->regex, (unsigned char *) tag, tag_len, &result);
    }

    if (n <= 0) {
        flb_warn("[filter_kube] invalid pattern for given tag %s", tag);
        return -1;
    }

    /* Parse the regex results */
    flb_regex_parse(ctx->regex, &result, cb_results, meta);

    /* Compose API server cache key */
    if (meta->podname && meta->namespace) {
        /* calculate estimated buffer size */
        n = meta->namespace_len + 1 + meta->podname_len + 1;
        if (meta->container_name) {
            n += meta->container_name_len + 1;
        }
        meta->cache_key = flb_malloc(n);
        if (!meta->cache_key) {
            flb_errno();
            return -1;
        }

        /* Copy namespace */
        memcpy(meta->cache_key, meta->namespace, meta->namespace_len);
        off = meta->namespace_len;

        /* Separator */
        meta->cache_key[off++] = ':';

        /* Copy podname */
        memcpy(meta->cache_key + off, meta->podname, meta->podname_len);
        off += meta->podname_len;

        if (meta->container_name) {
            /* Separator */
            meta->cache_key[off++] = ':';
            memcpy(meta->cache_key + off, meta->container_name, meta->container_name_len);
            off += meta->container_name_len;
        }

        meta->cache_key[off] = '\0';
        meta->cache_key_len = off;
    }
    else {
        meta->cache_key = NULL;
        meta->cache_key_len = 0;
    }

    return 0;
}

/*
 * Given a fixed meta data (namespace and podname), get API server information
 * and merge buffers.
 */
static int get_and_merge_meta(struct flb_kube *ctx, struct flb_kube_meta *meta,
                              char **out_buf, size_t *out_size)
{
    int ret;
    char *api_buf;
    size_t api_size;
    char *merge_buf;
    size_t merge_size;

    ret = get_api_server_info(ctx,
                              meta->namespace, meta->podname,
                              &api_buf, &api_size);
    if (ret == -1) {
        return -1;
    }

    ret = merge_meta(meta, ctx,
                     api_buf, api_size,
                     &merge_buf, &merge_size);
    flb_free(api_buf);

    if (ret == -1) {
        return -1;
    }

    *out_buf = merge_buf;
    *out_size = merge_size;

    return 0;
}


static int flb_kube_network_init(struct flb_kube *ctx, struct flb_config *config)
{
    int io_type = FLB_IO_TCP;

    ctx->upstream = NULL;

    if (ctx->api_https == FLB_TRUE) {
        if (!ctx->tls_ca_path && !ctx->tls_ca_file) {
            ctx->tls_ca_file  = flb_strdup(FLB_KUBE_CA);
        }
        ctx->tls.context = flb_tls_context_new(ctx->tls_verify,
                                               ctx->tls_debug,
                                               ctx->tls_ca_path,
                                               ctx->tls_ca_file,
                                               NULL, NULL, NULL);
        if (!ctx->tls.context) {
            return -1;
        }
        io_type = FLB_IO_TLS;
    }

    /* Create an Upstream context */
    ctx->upstream = flb_upstream_create(config,
                                        ctx->api_host,
                                        ctx->api_port,
                                        io_type,
                                        &ctx->tls);
    if (!ctx->upstream) {
        /* note: if ctx->tls.context is set, it's destroyed upon context exit */
        return -1;
    }

    /* Remove async flag from upstream */
    ctx->upstream->flags &= ~(FLB_IO_ASYNC);

    return 0;
}

static int flb_dummy_meta(char **out_buf, size_t *out_size)
{
    int len;
    time_t t;
    char stime[32];
    struct tm result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    t = time(NULL);
    localtime_r(&t, &result);
    asctime_r(&result, stime);
    len = strlen(stime) - 1;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 5 /* dummy */ );
    msgpack_pack_str_body(&mp_pck, "dummy", 5);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, stime, len);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

/* Initialize local context */
int flb_kube_meta_init(struct flb_kube *ctx, struct flb_config *config)
{
    int ret;
    char *meta_buf;
    size_t meta_size;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_warn("[filter_kube] using Dummy Metadata");
        return 0;
    }

    /* Gather local info */
    ret = get_local_pod_info(ctx);
    if (ret == FLB_TRUE) {
        flb_info("[filter_kube] local POD info OK");
    }
    else {
        flb_info("[filter_kube] not running in a POD");
    }

    /* Init network */
    flb_kube_network_init(ctx, config);

    /* Gather info from API server */
    flb_info("[filter_kube] testing connectivity with API server...");
    ret = get_api_server_info(ctx, ctx->namespace, ctx->podname,
                              &meta_buf, &meta_size);
    if (ret == -1) {
        if (!ctx->podname) {
            flb_warn("[filter_kube] could not get meta for local POD");
        }
        else {
            flb_warn("[filter_kube] could not get meta for POD %s",
                     ctx->podname);
        }
        return -1;
    }
    flb_info("[filter_kube] API server connectivity OK");

    flb_free(meta_buf);

    return 0;
}

int flb_kube_meta_get(struct flb_kube *ctx,
                      char *tag, int tag_len,
                      char *data, size_t data_size,
                      char **out_buf, size_t *out_size,
                      struct flb_kube_meta *meta,
                      struct flb_kube_props *props)
{
    int id;
    int ret;
    char *hash_meta_buf;
    size_t off = 0;
    size_t hash_meta_size;
    msgpack_unpacked result;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_dummy_meta(out_buf, out_size);
        return 0;
    }

    /* Get metadata from tag or record (cache key is the important one) */
    ret = extract_meta(ctx, tag, tag_len, data, data_size, meta);
    if (ret != 0) {
        return -1;
    }

    /* Check if we have some data associated to the cache key */
    ret = flb_hash_get(ctx->hash_table,
                       meta->cache_key, meta->cache_key_len,
                       &hash_meta_buf, &hash_meta_size);
    if (ret == -1) {
        /* Retrieve API server meta and merge with local meta */
        ret = get_and_merge_meta(ctx, meta,
                                 &hash_meta_buf, &hash_meta_size);
        if (ret == -1) {
            return -1;
        }

        id = flb_hash_add(ctx->hash_table,
                          meta->cache_key, meta->cache_key_len,
                          hash_meta_buf, hash_meta_size);
        if (id >= 0) {
            /*
             * Release the original buffer created on extract_meta() as a new
             * copy have been generated into the hash table, then re-set
             * the outgoing buffer and size.
             */
            flb_free(hash_meta_buf);
            flb_hash_get_by_id(ctx->hash_table, id, meta->cache_key,
                               &hash_meta_buf, &hash_meta_size);
        }
    }

    /*
     * The retrieved buffer may have two serialized items:
     *
     * [0] = kubernetes metadata (annotations, labels)
     * [1] = Annotation properties
     *
     * note: annotation properties are optional.
     */
    msgpack_unpacked_init(&result);

    /* Unpack to get the offset/bytes of the first item */
    msgpack_unpack_next(&result, hash_meta_buf, hash_meta_size, &off);

    /* Set the pointer and proper size for the caller */
    *out_buf = hash_meta_buf;
    *out_size = off;

    /* A new unpack_next() call will succeed If annotation properties exists */
    ret = msgpack_unpack_next(&result, hash_meta_buf, hash_meta_size, &off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        /* Unpack the remaining data into properties structure */
        flb_kube_prop_unpack(props,
                             hash_meta_buf + *out_size,
                             hash_meta_size - *out_size);
    }
    msgpack_unpacked_destroy(&result);

    return 0;
}

int flb_kube_meta_release(struct flb_kube_meta *meta)
{
    int r = 0;

    if (meta->namespace) {
        flb_free(meta->namespace);
        r++;
    }

    if (meta->podname) {
        flb_free(meta->podname);
        r++;
    }

    if (meta->container_name) {
        flb_free(meta->container_name);
        r++;
    }

    if (meta->docker_id) {
        flb_free(meta->docker_id);
        r++;
    }

    if (meta->container_hash) {
        flb_free(meta->container_hash);
        r++;
    }

    if (meta->cache_key) {
        flb_free(meta->cache_key);
    }

    return r;
}
