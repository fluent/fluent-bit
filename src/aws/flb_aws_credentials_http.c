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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

#include <fluent-bit/flb_jsmn.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define AWS_CREDENTIAL_RESPONSE_ACCESS_KEY   "AccessKeyId"
#define AWS_CREDENTIAL_RESPONSE_SECRET_KEY   "SecretAccessKey"
#define AWS_HTTP_RESPONSE_TOKEN              "Token"
#define AWS_CREDENTIAL_RESPONSE_EXPIRATION   "Expiration"

#define ECS_CREDENTIALS_HOST           "169.254.170.2"
#define ECS_CREDENTIALS_HOST_LEN       13
#define ECS_CREDENTIALS_PATH_ENV_VAR   "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"


/* Declarations */
struct flb_aws_provider_http;
static int http_credentials_request(struct flb_aws_provider_http
                                    *implementation);


/*
 * HTTP Credentials Provider - retrieve credentials from a local http server
 * Used to implement the ECS Credentials provider.
 * Equivalent to:
 * https://github.com/aws/aws-sdk-go/tree/master/aws/credentials/endpointcreds
 */

struct flb_aws_provider_http {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    struct flb_aws_client *client;

    /* Host and Path to request credentials */
    flb_sds_t host;
    flb_sds_t path;
};


struct flb_aws_credentials *get_credentials_fn_http(struct flb_aws_provider
                                                    *provider)
{
    struct flb_aws_credentials *creds = NULL;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_http *implementation = provider->implementation;

    flb_debug("[aws_credentials] Retrieving credentials from the "
              "HTTP provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        if (try_lock_provider(provider)) {
            http_credentials_request(implementation);
            unlock_provider(provider);
        }
    }

    if (!implementation->creds) {
        /*
         * We failed to lock the provider and creds are unset. This means that
         * another co-routine is performing the refresh.
         */
        flb_warn("[aws_credentials] No cached credentials are available and "
                 "a credential refresh is already in progress. The current "
                 "co-routine will retry.");

        return NULL;
    }

    creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        flb_errno();
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        flb_errno();
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            flb_errno();
            goto error;
        }

    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_http(struct flb_aws_provider *provider) {
    struct flb_aws_provider_http *implementation = provider->implementation;
    int ret = -1;
    flb_debug("[aws_credentials] Refresh called on the http provider");

    if (try_lock_provider(provider)) {
        ret = http_credentials_request(implementation);
        unlock_provider(provider);
    }
    return ret;
}

int init_fn_http(struct flb_aws_provider *provider) {
    struct flb_aws_provider_http *implementation = provider->implementation;
    int ret = -1;
    flb_debug("[aws_credentials] Init called on the http provider");

    implementation->client->debug_only = FLB_TRUE;

    if (try_lock_provider(provider)) {
        ret = http_credentials_request(implementation);
        unlock_provider(provider);
    }

    implementation->client->debug_only = FLB_FALSE;

    return ret;
}

void sync_fn_http(struct flb_aws_provider *provider) {
    struct flb_aws_provider_http *implementation = provider->implementation;

    flb_debug("[aws_credentials] Sync called on the http provider");
    /* remove async flag */
    flb_stream_disable_async_mode(&implementation->client->upstream->base);
}

void async_fn_http(struct flb_aws_provider *provider) {
    struct flb_aws_provider_http *implementation = provider->implementation;

    flb_debug("[aws_credentials] Async called on the http provider");
    /* add async flag */
    flb_stream_enable_async_mode(&implementation->client->upstream->base);
}

void upstream_set_fn_http(struct flb_aws_provider *provider,
                          struct flb_output_instance *ins) {
    struct flb_aws_provider_http *implementation = provider->implementation;

    flb_debug("[aws_credentials] upstream_set called on the http provider");
    /* Make sure TLS is set to false before setting upstream, then reset it */
    ins->use_tls = FLB_FALSE;
    flb_output_upstream_set(implementation->client->upstream, ins);
    ins->use_tls = FLB_TRUE;
}

void destroy_fn_http(struct flb_aws_provider *provider) {
    struct flb_aws_provider_http *implementation = provider->implementation;

    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }

        if (implementation->client) {
            flb_aws_client_destroy(implementation->client);
        }

        if (implementation->host) {
            flb_sds_destroy(implementation->host);
        }

        if (implementation->path) {
            flb_sds_destroy(implementation->path);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct flb_aws_provider_vtable http_provider_vtable = {
    .get_credentials = get_credentials_fn_http,
    .init = init_fn_http,
    .refresh = refresh_fn_http,
    .destroy = destroy_fn_http,
    .sync = sync_fn_http,
    .async = async_fn_http,
    .upstream_set = upstream_set_fn_http,
};

struct flb_aws_provider *flb_http_provider_create(struct flb_config *config,
                                                  flb_sds_t host,
                                                  flb_sds_t path,
                                                  struct
                                                  flb_aws_client_generator
                                                  *generator)
{
    struct flb_aws_provider_http *implementation = NULL;
    struct flb_aws_provider *provider = NULL;
    struct flb_upstream *upstream = NULL;

    flb_debug("[aws_credentials] Configuring HTTP provider with %s:80%s",
              host, path);

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));

    if (!provider) {
        flb_errno();
        return NULL;
    }

    pthread_mutex_init(&provider->lock, NULL);

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_http));

    if (!implementation) {
        flb_free(provider);
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &http_provider_vtable;
    provider->implementation = implementation;

    implementation->host = host;
    implementation->path = path;

    upstream = flb_upstream_create(config, host, 80, FLB_IO_TCP, NULL);

    if (!upstream) {
        flb_aws_provider_destroy(provider);
        flb_error("[aws_credentials] HTTP Provider: connection initialization "
                  "error");
        return NULL;
    }

    upstream->base.net.connect_timeout = FLB_AWS_CREDENTIAL_NET_TIMEOUT;

    implementation->client = generator->create();
    if (!implementation->client) {
        flb_aws_provider_destroy(provider);
        flb_upstream_destroy(upstream);
        flb_error("[aws_credentials] HTTP Provider: client creation error");
        return NULL;
    }
    implementation->client->name = "http_provider_client";
    implementation->client->has_auth = FLB_FALSE;
    implementation->client->provider = NULL;
    implementation->client->region = NULL;
    implementation->client->service = NULL;
    implementation->client->port = 80;
    implementation->client->flags = 0;
    implementation->client->proxy = NULL;
    implementation->client->upstream = upstream;

    return provider;
}

/*
 * ECS Provider
 * The ECS Provider is just a wrapper around the HTTP Provider
 * with the ECS credentials endpoint.
 */

 struct flb_aws_provider *flb_ecs_provider_create(struct flb_config *config,
                                                  struct
                                                  flb_aws_client_generator
                                                  *generator)
{
    flb_sds_t host = NULL;
    flb_sds_t path = NULL;
    char *path_var = NULL;

    host = flb_sds_create_len(ECS_CREDENTIALS_HOST, ECS_CREDENTIALS_HOST_LEN);
    if (!host) {
        flb_errno();
        return NULL;
    }

    path_var = getenv(ECS_CREDENTIALS_PATH_ENV_VAR);
    if (path_var && strlen(path_var) > 0) {
        path = flb_sds_create(path_var);
        if (!path) {
            flb_errno();
            flb_free(host);
            return NULL;
        }

        return flb_http_provider_create(config, host, path, generator);
    } else {
        flb_debug("[aws_credentials] Not initializing ECS Provider because"
                  " %s is not set", ECS_CREDENTIALS_PATH_ENV_VAR);
        flb_sds_destroy(host);
        return NULL;
    }

}

static int http_credentials_request(struct flb_aws_provider_http
                                    *implementation)
{
    char *response = NULL;
    size_t response_len;
    time_t expiration;
    struct flb_aws_credentials *creds = NULL;
    struct flb_aws_client *client = implementation->client;
    struct flb_http_client *c = NULL;

    c = client->client_vtable->request(client, FLB_HTTP_GET,
                                       implementation->path, NULL, 0,
                                       NULL, 0);

    if (!c || c->resp.status != 200) {
        flb_debug("[aws_credentials] http credentials request failed");
        if (c) {
            flb_http_client_destroy(c);
        }
        return -1;
    }

    response = c->resp.payload;
    response_len = c->resp.payload_size;

    creds = flb_parse_http_credentials(response, response_len, &expiration);
    if (!creds) {
        flb_http_client_destroy(c);
        return -1;
    }

    /* destroy existing credentials */
    flb_aws_credentials_destroy(implementation->creds);
    implementation->creds = NULL;

    implementation->creds = creds;
    implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
    flb_http_client_destroy(c);
    return 0;
}

/*
 * All HTTP credentials endpoints (IMDS, ECS, custom) follow the same spec:
 * {
 *   "AccessKeyId": "ACCESS_KEY_ID",
 *   "Expiration": "2019-12-18T21:27:58Z",
 *   "SecretAccessKey": "SECRET_ACCESS_KEY",
 *   "Token": "SECURITY_TOKEN_STRING"
 * }
 * (some implementations (IMDS) have additional fields)
 * Returns NULL if any part of parsing was unsuccessful.
 */
struct flb_aws_credentials *flb_parse_http_credentials(char *response,
                                                       size_t response_len,
                                                       time_t *expiration)
{
    return flb_parse_json_credentials(response, response_len, AWS_HTTP_RESPONSE_TOKEN,
                                      expiration);
}

struct flb_aws_credentials *flb_parse_json_credentials(char *response,
                                                       size_t response_len,
                                                       char* session_token_field,
                                                       time_t *expiration)
{
    jsmntok_t *tokens = NULL;
    const jsmntok_t *t = NULL;
    char *current_token = NULL;
    jsmn_parser parser;
    int tokens_size = 50;
    size_t size;
    int ret;
    struct flb_aws_credentials *creds = NULL;
    int i = 0;
    int len;
    flb_sds_t tmp;

    /*
     * Remove/reset existing value of expiration.
     * Expiration should be in the response, but it is not
     * strictly speaking needed. Fluent Bit logs a warning if it is missing.
     */
    *expiration = -1;

    jsmn_init(&parser);

    size = sizeof(jsmntok_t) * tokens_size;
    tokens = flb_calloc(1, size);
    if (!tokens) {
        goto error;
    }

    ret = jsmn_parse(&parser, response, response_len,
                     tokens, tokens_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_error("[aws_credentials] Could not parse credentials response"
                  " - invalid JSON.");
        goto error;
    }

    /* Shouldn't happen, but just in case, check for too many tokens error */
    if (ret == JSMN_ERROR_NOMEM) {
        flb_error("[aws_credentials] Could not parse credentials response"
                  " - response contained more tokens than expected.");
        goto error;
    }

    /* return value is number of tokens parsed */
    tokens_size = ret;

    creds = flb_calloc(1, sizeof(struct flb_aws_credentials));
    if (!creds) {
        flb_errno();
        goto error;
    }

    /*
     * jsmn will create an array of tokens like:
     * key, value, key, value
     */
    while (i < (tokens_size - 1)) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type == JSMN_STRING) {
            current_token = &response[t->start];
            len = t->end - t->start;

            if (strncmp(current_token, AWS_CREDENTIAL_RESPONSE_ACCESS_KEY, len) == 0)
            {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->access_key_id != NULL) {
                    flb_error("Trying to double allocate access_key_id");
                    goto error;
                }
                creds->access_key_id = flb_sds_create_len(current_token, len);
                if (!creds->access_key_id) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            if (strncmp(current_token, AWS_CREDENTIAL_RESPONSE_SECRET_KEY, len) == 0)
            {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->secret_access_key != NULL) {
                    flb_error("Trying to double allocate secret_access_key");
                    goto error;
                }
                creds->secret_access_key = flb_sds_create_len(current_token,
                                                              len);
                if (!creds->secret_access_key) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            if (strncmp(current_token, session_token_field, len) == 0) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->session_token != NULL) {
                    flb_error("Trying to double allocate session_token");
                    goto error;
                }
                creds->session_token = flb_sds_create_len(current_token, len);
                if (!creds->session_token) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            if (strncmp(current_token, AWS_CREDENTIAL_RESPONSE_EXPIRATION, len) == 0)
            {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                tmp = flb_sds_create_len(current_token, len);
                if (!tmp) {
                    flb_errno();
                    goto error;
                }
                *expiration = flb_aws_cred_expiration(tmp);
                flb_sds_destroy(tmp);
                if (*expiration < 0) {
                    flb_warn("[aws_credentials] '%s' was invalid or "
                             "could not be parsed. Disabling auto-refresh of "
                             "credentials.", AWS_CREDENTIAL_RESPONSE_EXPIRATION);
                }
            }
        }

        i++;
    }

    if (creds->access_key_id == NULL) {
        flb_error("[aws_credentials] Missing %s field in"
                  "credentials response", AWS_CREDENTIAL_RESPONSE_ACCESS_KEY);
        goto error;
    }

    if (creds->secret_access_key == NULL) {
        flb_error("[aws_credentials] Missing %s field in"
                  "credentials response", AWS_CREDENTIAL_RESPONSE_SECRET_KEY);
        goto error;
    }

    flb_free(tokens);
    return creds;

error:
    flb_aws_credentials_destroy(creds);
    flb_free(tokens);
    return NULL;
}
