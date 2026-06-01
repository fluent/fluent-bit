/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_kubernetes.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_utils.h>

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) && !defined(FLB_HAVE_KUBE_TOKEN_COMMAND)
#define FLB_HAVE_KUBE_TOKEN_COMMAND
#endif

#define FLB_KUBE_TOKEN_BUF_SIZE 8192
#define FLB_KUBE_TOKEN_MAX_SIZE (1024 * 1024)

static int file_to_buffer(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    char *buf;
    size_t bytes;
    FILE *fp;
    struct stat st;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, st.st_size + 1);
    if (buf == NULL) {
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

#ifdef FLB_HAVE_KUBE_TOKEN_COMMAND
static int get_token_with_command(const char *command,
                                  char **out_buf, size_t *out_size)
{
    FILE *fp;
    char buf[FLB_KUBE_TOKEN_BUF_SIZE];
    char *tmp;
    char *res;
    size_t capacity = FLB_KUBE_TOKEN_BUF_SIZE;
    size_t required_size;
    size_t new_capacity;
    size_t size = 0;
    size_t len = 0;

    fp = popen(command, "r");
    if (fp == NULL) {
        return -1;
    }

    res = flb_calloc(1, capacity);
    if (res == NULL) {
        flb_errno();
        pclose(fp);
        return -1;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        len = strlen(buf);
        if (len > FLB_KUBE_TOKEN_MAX_SIZE - size - 1) {
            flb_free(res);
            pclose(fp);
            return -1;
        }

        required_size = size + len + 1;
        if (required_size > capacity) {
            new_capacity = capacity;
            while (new_capacity < required_size) {
                new_capacity *= 2;
            }

            tmp = flb_realloc(res, new_capacity);
            if (tmp == NULL) {
                flb_errno();
                flb_free(res);
                pclose(fp);
                return -1;
            }

            res = tmp;
            capacity = new_capacity;
        }

        memcpy(res + size, buf, len);
        size += len;
        res[size] = '\0';
    }

    if (size < 1) {
        flb_free(res);
        pclose(fp);
        return -1;
    }

    pclose(fp);

    *out_buf = res;
    *out_size = size;

    return 0;
}
#endif

static flb_sds_t sds_from_config(const char *value, const char *default_value)
{
    if (value != NULL) {
        return flb_sds_create(value);
    }

    if (default_value != NULL) {
        return flb_sds_create(default_value);
    }

    return NULL;
}

static int init_tls(struct flb_kube_client *client,
                    struct flb_tls **out_tls,
                    int enabled)
{
    int ret;
    const char *ca_file;

    *out_tls = NULL;
    if (enabled != FLB_TRUE) {
        return FLB_IO_TCP;
    }

    ca_file = client->tls_ca_file;
    if (client->tls_ca_path == NULL && ca_file == NULL) {
        ca_file = FLB_KUBE_CA;
    }

    *out_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                              client->tls_verify,
                              client->tls_debug,
                              client->tls_vhost,
                              client->tls_ca_path,
                              ca_file,
                              NULL, NULL, NULL);
    if (*out_tls == NULL) {
        return -1;
    }

    if (client->tls_verify_hostname == FLB_TRUE) {
        ret = flb_tls_set_verify_hostname(*out_tls, FLB_TRUE);
        if (ret == -1) {
            return -1;
        }
    }

    return FLB_IO_TLS;
}

static int init_upstreams(struct flb_kube_client *client)
{
    int io_type;

    io_type = init_tls(client, &client->api_tls, client->api_https);
    if (io_type == -1) {
        return -1;
    }

    client->api_upstream = flb_upstream_create(client->config,
                                               client->api_host,
                                               client->api_port,
                                               io_type,
                                               client->api_tls);
    if (client->api_upstream == NULL) {
        return -1;
    }
    flb_stream_disable_async_mode(&client->api_upstream->base);

    if (client->use_kubelet != FLB_TRUE) {
        return 0;
    }

    io_type = init_tls(client, &client->kubelet_tls, client->kubelet_https);
    if (io_type == -1) {
        return -1;
    }

    client->kubelet_upstream = flb_upstream_create(client->config,
                                                   client->kubelet_host,
                                                   client->kubelet_port,
                                                   io_type,
                                                   client->kubelet_tls);
    if (client->kubelet_upstream == NULL) {
        return -1;
    }
    flb_stream_disable_async_mode(&client->kubelet_upstream->base);

    return 0;
}

struct flb_kube_client *flb_kube_client_create(
                                    struct flb_config *config,
                                    struct flb_kube_client_config *client_config)
{
    int ret;
    struct flb_kube_client *client;

    if (config == NULL || client_config == NULL) {
        return NULL;
    }

    client = flb_calloc(1, sizeof(struct flb_kube_client));
    if (client == NULL) {
        flb_errno();
        return NULL;
    }

    client->config = config;
    client->api_host = sds_from_config(client_config->api_host,
                                       FLB_KUBE_API_HOST);
    client->api_port = client_config->api_port;
    if (client->api_port <= 0) {
        client->api_port = FLB_KUBE_API_PORT;
    }
    client->api_https = client_config->api_https;

    client->kubelet_host = sds_from_config(client_config->kubelet_host,
                                           "127.0.0.1");
    client->kubelet_port = client_config->kubelet_port;
    client->kubelet_https = client_config->kubelet_https;
    client->use_kubelet = client_config->use_kubelet;

    client->tls_ca_path = sds_from_config(client_config->tls_ca_path, NULL);
    client->tls_ca_file = sds_from_config(client_config->tls_ca_file, NULL);
    client->tls_vhost = sds_from_config(client_config->tls_vhost, NULL);
    client->tls_debug = client_config->tls_debug;
    client->tls_verify = client_config->tls_verify;
    client->tls_verify_hostname = client_config->tls_verify_hostname;

    client->token_file = sds_from_config(client_config->token_file,
                                         FLB_KUBE_TOKEN);
    client->token_command = sds_from_config(client_config->token_command, NULL);
    client->token_ttl = client_config->token_ttl;
    client->buffer_size = client_config->buffer_size;

    if (client->api_host == NULL || client->kubelet_host == NULL ||
        client->token_file == NULL) {
        flb_kube_client_destroy(client);
        return NULL;
    }

    ret = init_upstreams(client);
    if (ret != 0) {
        flb_kube_client_destroy(client);
        return NULL;
    }

    return client;
}

void flb_kube_client_destroy(struct flb_kube_client *client)
{
    if (client == NULL) {
        return;
    }

    if (client->api_upstream != NULL) {
        flb_upstream_destroy(client->api_upstream);
    }
    if (client->kubelet_upstream != NULL) {
        flb_upstream_destroy(client->kubelet_upstream);
    }
    if (client->api_tls != NULL) {
        flb_tls_destroy(client->api_tls);
    }
    if (client->kubelet_tls != NULL) {
        flb_tls_destroy(client->kubelet_tls);
    }

    flb_sds_destroy(client->api_host);
    flb_sds_destroy(client->kubelet_host);
    flb_sds_destroy(client->tls_ca_path);
    flb_sds_destroy(client->tls_ca_file);
    flb_sds_destroy(client->tls_vhost);
    flb_sds_destroy(client->token_file);
    flb_sds_destroy(client->token_command);

    flb_free(client->token);
    flb_free(client->auth);
    flb_free(client);
}

int flb_kube_client_refresh_token(struct flb_kube_client *client)
{
    int ret;
    int expired = FLB_FALSE;
    char *tmp;
    char *token = NULL;
    size_t token_size = 0;
    size_t auth_size;

    if (client == NULL) {
        return -1;
    }

    if (client->token_create > 0 &&
        time(NULL) > client->token_create + client->token_ttl) {
        expired = FLB_TRUE;
    }

    if (expired != FLB_TRUE && client->token_create > 0) {
        return 0;
    }

    if (client->token_command != NULL) {
#ifdef FLB_HAVE_KUBE_TOKEN_COMMAND
        ret = get_token_with_command(client->token_command,
                                     &token, &token_size);
#else
        ret = -1;
#endif
        if (ret == -1) {
            flb_warn("[kube client] failed to run command %s",
                     client->token_command);
        }
    }
    else {
        ret = file_to_buffer(client->token_file, &token, &token_size);
        if (ret == -1) {
            flb_warn("[kube client] cannot open %s", client->token_file);
        }
    }

    if (ret == -1 || token == NULL) {
        return -1;
    }

    auth_size = token_size + 32;
    if (client->auth == NULL) {
        client->auth = flb_malloc(auth_size);
        if (client->auth == NULL) {
            flb_free(token);
            return -1;
        }
        client->auth_size = auth_size;
    }
    else if (client->auth_size < auth_size) {
        tmp = flb_realloc(client->auth, auth_size);
        if (tmp == NULL) {
            flb_free(token);
            return -1;
        }
        client->auth = tmp;
        client->auth_size = auth_size;
    }

    ret = snprintf(client->auth, auth_size, "Bearer %s", token);
    if (ret < 0 || (size_t) ret >= auth_size) {
        flb_free(token);
        return -1;
    }
    client->auth_len = ret;

    flb_free(client->token);
    client->token = token;
    client->token_len = token_size;
    client->token_create = time(NULL);

    return 0;
}

int flb_kube_client_load_local_pod_info(struct flb_kube_client *client,
                                        char **namespace, size_t *namespace_len,
                                        char **podname, size_t *podname_len)
{
    int ret;
    char tmp[256];
    char *ns = NULL;
    char *hostname;
    size_t ns_size = 0;

    if (client == NULL || namespace == NULL || namespace_len == NULL ||
        podname == NULL || podname_len == NULL) {
        return FLB_FALSE;
    }

    ret = file_to_buffer(FLB_KUBE_NAMESPACE, &ns, &ns_size);
    if (ret == -1) {
        return FLB_FALSE;
    }

    ret = flb_kube_client_refresh_token(client);
    if (ret == -1) {
        flb_free(ns);
        return FLB_FALSE;
    }

    hostname = getenv("HOSTNAME");
    if (hostname != NULL) {
        *podname = flb_strdup(hostname);
    }
    else {
        gethostname(tmp, sizeof(tmp));
        tmp[sizeof(tmp) - 1] = '\0';
        *podname = flb_strdup(tmp);
    }

    if (*podname == NULL) {
        flb_free(ns);
        return FLB_FALSE;
    }

    *namespace = ns;
    *namespace_len = ns_size;
    *podname_len = strlen(*podname);

    return FLB_TRUE;
}

int flb_kube_client_get(struct flb_kube_client *client,
                        int connection,
                        const char *uri,
                        char **out_buf, size_t *out_size,
                        int *root_type)
{
    int ret;
    int packed;
    size_t b_sent;
    struct flb_http_client *http_client;
    struct flb_connection *u_conn;
    struct flb_upstream *upstream;

    if (client == NULL || uri == NULL || out_buf == NULL || out_size == NULL) {
        return -1;
    }

    *out_buf = NULL;
    *out_size = 0;

    if (connection == FLB_KUBE_CLIENT_KUBELET) {
        upstream = client->kubelet_upstream;
    }
    else {
        upstream = client->api_upstream;
    }

    if (upstream == NULL) {
        return -1;
    }

    u_conn = flb_upstream_conn_get(upstream);
    if (u_conn == NULL) {
        return -1;
    }

    ret = flb_kube_client_refresh_token(client);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    http_client = flb_http_client(u_conn, FLB_HTTP_GET, uri,
                                  NULL, 0, NULL, 0, NULL, 0);
    if (http_client == NULL) {
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_buffer_size(http_client, client->buffer_size);
    flb_http_add_header(http_client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(http_client, "Connection", 10, "close", 5);

    if (client->auth_len > 0) {
        flb_http_add_header(http_client, "Authorization", 13,
                            client->auth, client->auth_len);
    }

    ret = flb_http_do(http_client, &b_sent);
    if (ret != 0 || http_client->resp.status != 200) {
        flb_http_client_destroy(http_client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    packed = flb_pack_json(http_client->resp.payload,
                           http_client->resp.payload_size,
                           out_buf, out_size, root_type, NULL);

    flb_http_client_destroy(http_client);
    flb_upstream_conn_release(u_conn);

    return packed;
}
