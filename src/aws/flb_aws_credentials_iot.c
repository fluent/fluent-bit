/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

/* IoT Credentials Environment Variables */
#define AWS_IOT_KEY_FILE               "AWS_IOT_KEY_FILE"
#define AWS_IOT_CERT_FILE              "AWS_IOT_CERT_FILE"
#define AWS_IOT_CA_CERT_FILE           "AWS_IOT_CA_CERT_FILE"
#define AWS_IOT_CREDENTIALS_ENDPOINT   "AWS_IOT_CREDENTIALS_ENDPOINT"
#define AWS_IOT_THING_NAME             "AWS_IOT_THING_NAME"
#define AWS_IOT_ROLE_ALIAS             "AWS_IOT_ROLE_ALIAS"

/* IoT Provider */
struct flb_aws_provider_iot {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    struct flb_aws_client *client;

    /* IoT specific configuration */
    char *key_file;
    char *cert_file;
    char *ca_cert_file;
    char *credentials_endpoint;
    char *thing_name;
    char *role_alias;

    /* TLS configuration for IoT certificates */
    struct flb_tls *tls;

    /* Static header for thing name */
    struct flb_aws_header thing_name_header;
};

/* Forward declarations */
static int iot_credentials_request(struct flb_aws_provider_iot *implementation);
static struct flb_aws_credentials *flb_parse_iot_credentials(char *response, size_t response_len, time_t *expiration);

struct flb_aws_credentials *get_credentials_fn_iot(struct flb_aws_provider *provider)
{
    struct flb_aws_credentials *creds = NULL;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_iot *implementation = provider->implementation;

    flb_debug("[aws_credentials] Requesting credentials from the "
              "IoT provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        if (try_lock_provider(provider)) {
            flb_debug("[aws_credentials] IoT Provider: Refreshing credential "
                      "cache.");
            iot_credentials_request(implementation);
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
        goto error;
    }

    creds->access_key_id = flb_sds_create(implementation->creds->access_key_id);
    if (!creds->access_key_id) {
        goto error;
    }

    creds->secret_access_key = flb_sds_create(implementation->creds->
                                              secret_access_key);
    if (!creds->secret_access_key) {
        goto error;
    }

    if (implementation->creds->session_token) {
        creds->session_token = flb_sds_create(implementation->creds->
                                              session_token);
        if (!creds->session_token) {
            goto error;
        }
    } else {
        creds->session_token = NULL;
    }

    return creds;

error:
    flb_errno();
    flb_aws_credentials_destroy(creds);
    return NULL;
}

int refresh_fn_iot(struct flb_aws_provider *provider) {
    int ret = -1;
    struct flb_aws_provider_iot *implementation = provider->implementation;

    flb_debug("[aws_credentials] Refresh called on the IoT provider");

    if (try_lock_provider(provider)) {
        ret = iot_credentials_request(implementation);
        unlock_provider(provider);
    }
    return ret;
}

int init_fn_iot(struct flb_aws_provider *provider) {
    int ret = -1;
    struct flb_aws_provider_iot *implementation = provider->implementation;

    flb_debug("[aws_credentials] Init called on the IoT provider");

    implementation->client->debug_only = FLB_TRUE;

    if (try_lock_provider(provider)) {
        ret = iot_credentials_request(implementation);
        unlock_provider(provider);
    }

    implementation->client->debug_only = FLB_FALSE;
    return ret;
}

void sync_fn_iot(struct flb_aws_provider *provider) {
    struct flb_aws_provider_iot *implementation = provider->implementation;

    flb_debug("[aws_credentials] Sync called on the IoT provider");
    /* Remove async flag */
    flb_stream_disable_async_mode(&implementation->client->upstream->base);
}

void async_fn_iot(struct flb_aws_provider *provider) {
    struct flb_aws_provider_iot *implementation = provider->implementation;

    flb_debug("[aws_credentials] Async called on the IoT provider");
    /* Add async flag */
    flb_stream_enable_async_mode(&implementation->client->upstream->base);
}

void upstream_set_fn_iot(struct flb_aws_provider *provider,
                         struct flb_output_instance *ins) {
    struct flb_aws_provider_iot *implementation = provider->implementation;

    flb_debug("[aws_credentials] upstream_set called on the IoT provider");
    /* Associate output and upstream */
    flb_output_upstream_set(implementation->client->upstream, ins);
}

void destroy_fn_iot(struct flb_aws_provider *provider) {
    struct flb_aws_provider_iot *implementation = provider->implementation;

    if (implementation) {
        if (implementation->creds) {
            flb_aws_credentials_destroy(implementation->creds);
        }

        if (implementation->client) {
            flb_aws_client_destroy(implementation->client);
        }

        if (implementation->tls) {
            flb_tls_destroy(implementation->tls);
        }

        if (implementation->key_file) {
            flb_free(implementation->key_file);
        }
        if (implementation->cert_file) {
            flb_free(implementation->cert_file);
        }
        if (implementation->ca_cert_file) {
            flb_free(implementation->ca_cert_file);
        }
        if (implementation->credentials_endpoint) {
            flb_free(implementation->credentials_endpoint);
        }
        if (implementation->thing_name) {
            flb_free(implementation->thing_name);
        }
        if (implementation->role_alias) {
            flb_free(implementation->role_alias);
        }

        flb_free(implementation);
        provider->implementation = NULL;
    }

    return;
}

static struct flb_aws_provider_vtable iot_provider_vtable = {
    .get_credentials = get_credentials_fn_iot,
    .init = init_fn_iot,
    .refresh = refresh_fn_iot,
    .destroy = destroy_fn_iot,
    .sync = sync_fn_iot,
    .async = async_fn_iot,
    .upstream_set = upstream_set_fn_iot,
};

struct flb_aws_provider *flb_iot_provider_create(struct flb_config *config,
                                                 struct flb_aws_client_generator *generator)
{
    struct flb_aws_provider_iot *implementation = NULL;
    struct flb_aws_provider *provider = NULL;
    struct flb_upstream *upstream = NULL;
    char *endpoint_path = NULL;
    flb_sds_t protocol = NULL;
    flb_sds_t host = NULL;
    flb_sds_t port_sds = NULL;
    int port = 443;
    int ret;

    /* Check if IoT environment variables are set */
    char *key_file = getenv(AWS_IOT_KEY_FILE);
    char *cert_file = getenv(AWS_IOT_CERT_FILE);
    char *ca_cert_file = getenv(AWS_IOT_CA_CERT_FILE);
    char *credentials_endpoint = getenv(AWS_IOT_CREDENTIALS_ENDPOINT);
    char *thing_name = getenv(AWS_IOT_THING_NAME);
    char *role_alias = getenv(AWS_IOT_ROLE_ALIAS);

    if (!key_file || !cert_file || !ca_cert_file || !credentials_endpoint || 
        !thing_name || !role_alias) {
        flb_debug("[aws_credentials] Not initializing IoT provider because "
                  "required environment variables are not set");
        return NULL;
    }

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));
    if (!provider) {
        flb_errno();
        return NULL;
    }

    pthread_mutex_init(&provider->lock, NULL);

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_iot));
    if (!implementation) {
        flb_free(provider);
        flb_errno();
        return NULL;
    }

    provider->provider_vtable = &iot_provider_vtable;
    provider->implementation = implementation;

    /* Store IoT configuration */
    implementation->key_file = flb_strdup(key_file);
    implementation->cert_file = flb_strdup(cert_file);
    implementation->ca_cert_file = flb_strdup(ca_cert_file);
    implementation->credentials_endpoint = flb_strdup(credentials_endpoint);
    implementation->thing_name = flb_strdup(thing_name);
    implementation->role_alias = flb_strdup(role_alias);

    /* Parse the credentials endpoint URL */
    ret = flb_utils_url_split_sds(credentials_endpoint, &protocol, &host, &port_sds, &endpoint_path);
    if (ret < 0) {
        flb_error("[aws_credentials] Invalid IoT credentials endpoint URL: %s", credentials_endpoint);
        goto error;
    }

    if (port_sds != NULL) {
        port = atoi(port_sds);
        if (port == 0) {
            flb_error("[aws_credentials] Invalid port in IoT credentials endpoint: %s", port_sds);
            goto error;
        }
    }

    /* Create TLS configuration for IoT certificates */
    flb_debug("[aws_credentials] Creating TLS instance with cert: %s, key: %s, ca: %s", 
              implementation->cert_file, implementation->key_file, implementation->ca_cert_file);
    
    implementation->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                        FLB_TRUE,
                                        FLB_TRUE, /* debug - enable TLS debug */
                                        NULL, /* vhost */
                                        NULL, /* ca_path */
                                        implementation->ca_cert_file,
                                        implementation->cert_file,
                                        implementation->key_file,
                                        NULL); /* key_passwd */
    if (!implementation->tls) {
        flb_error("[aws_credentials] Failed to create TLS instance for IoT Provider");
        goto error;
    }
    
    flb_debug("[aws_credentials] TLS instance created successfully");

    /* Create upstream connection */
    flb_debug("[aws_credentials] Creating upstream connection to %s:%d", host, port);
    upstream = flb_upstream_create(config, host, port, FLB_IO_TLS, implementation->tls);
    if (!upstream) {
        flb_error("[aws_credentials] IoT Provider: connection initialization error");
        goto error;
    }
    
    flb_debug("[aws_credentials] Upstream connection created successfully");

    upstream->base.net.connect_timeout = FLB_AWS_CREDENTIAL_NET_TIMEOUT;

    implementation->client = generator->create();
    if (!implementation->client) {
        flb_aws_provider_destroy(provider);
        flb_upstream_destroy(upstream);
        flb_error("[aws_credentials] IoT Provider: client creation error");
        return NULL;
    }

    implementation->client->name = "iot_provider_client";
    implementation->client->has_auth = FLB_FALSE;
    implementation->client->provider = NULL;
    implementation->client->region = NULL;
    implementation->client->service = NULL;
    implementation->client->port = port;
    implementation->client->flags = 0;
    implementation->client->proxy = NULL;
    implementation->client->upstream = upstream;
    
    flb_debug("[aws_credentials] IoT client configured: name=%s, port=%d, has_auth=%d", 
              implementation->client->name, implementation->client->port, implementation->client->has_auth);

    /* Set up the thing name header */
    implementation->thing_name_header.key = "x-amzn-iot-thingname";
    implementation->thing_name_header.key_len = 22;
    implementation->thing_name_header.val = implementation->thing_name;
    implementation->thing_name_header.val_len = strlen(implementation->thing_name);

    flb_debug("[aws_credentials] Setting IoT thing name header: %s = %s", 
              implementation->thing_name_header.key, implementation->thing_name_header.val);

    /* Set the static headers for the client */
    implementation->client->static_headers = &implementation->thing_name_header;
    implementation->client->static_headers_len = 1;

    /* Clean up temporary variables */
    flb_sds_destroy(protocol);
    flb_sds_destroy(host);
    flb_sds_destroy(port_sds);
    flb_sds_destroy(endpoint_path);

    return provider;

error:
    flb_aws_provider_destroy(provider);
    flb_sds_destroy(protocol);
    flb_sds_destroy(host);
    flb_sds_destroy(port_sds);
    flb_sds_destroy(endpoint_path);
    return NULL;
}

static int iot_credentials_request(struct flb_aws_provider_iot *implementation)
{
    struct flb_aws_credentials *creds = NULL;
    struct flb_http_client *c = NULL;
    time_t expiration;
    flb_sds_t uri = NULL;
    int ret;

    flb_debug("[aws_credentials] Calling IoT credentials endpoint..");

    /* Construct the URI for the IoT credentials request */
    uri = flb_sds_create_size(256);
    if (!uri) {
        flb_errno();
        return -1;
    }

    uri = flb_sds_printf(&uri, "/role-aliases/%s/credentials", implementation->role_alias);
    if (!uri) {
        return -1;
    }

    /* Make the HTTP request */
    flb_debug("[aws_credentials] Making IoT credentials request to: %s", uri);
    flb_debug("[aws_credentials] Client headers count: %d", implementation->client->static_headers_len);
    if (implementation->client->static_headers_len > 0) {
        flb_debug("[aws_credentials] Client header: %s = %s", 
                  implementation->client->static_headers[0].key,
                  implementation->client->static_headers[0].val);
    }
    
    c = implementation->client->client_vtable->request(implementation->client, FLB_HTTP_GET,
                                                      uri, NULL, 0, NULL, 0);

    flb_sds_destroy(uri);

    if (!c) {
        flb_error("[aws_credentials] IoT credentials request failed - no response");
        return -1;
    }

    flb_debug("[aws_credentials] IoT credentials response status: %d", c->resp.status);
    flb_debug("[aws_credentials] IoT credentials response size: %zu", c->resp.payload_size);

    if (c->resp.status != 200) {
        flb_error("[aws_credentials] IoT credentials request failed with status: %d", c->resp.status);
        if (c->resp.payload_size > 0) {
            flb_aws_print_error_code(c->resp.payload, c->resp.payload_size,
                                     "IoTCredentialsProvider");
        }
        flb_http_client_destroy(c);
        return -1;
    }

    /* Debug: Log the actual response from IoT credentials endpoint */
    flb_debug("[aws_credentials] IoT credentials response (size: %zu): %.*s", 
              c->resp.payload_size, (int)c->resp.payload_size, c->resp.payload);

    /* Parse the credentials response - IoT endpoint may have different format */
    creds = flb_parse_iot_credentials(c->resp.payload, c->resp.payload_size, &expiration);
    if (!creds) {
        flb_debug("[aws_credentials] Failed to parse IoT credentials response");
        flb_http_client_destroy(c);
        return -1;
    }

    /* Destroy existing credentials */
    flb_aws_credentials_destroy(implementation->creds);
    implementation->creds = NULL;

    implementation->creds = creds;
    implementation->next_refresh = expiration - FLB_AWS_REFRESH_WINDOW;
    flb_http_client_destroy(c);

    return 0;
}

/*
 * Parse IoT credentials response.
 * AWS IoT credentials endpoint returns a JSON response with credentials.
 * The format may be different from standard AWS credentials endpoints.
 */
static struct flb_aws_credentials *flb_parse_iot_credentials(char *response, size_t response_len, time_t *expiration)
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

    ret = jsmn_parse(&parser, response, response_len, tokens, tokens_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_error("[aws_credentials] Could not parse IoT credentials response - invalid JSON.");
        goto error;
    }

    /* Shouldn't happen, but just in case, check for too many tokens error */
    if (ret == JSMN_ERROR_NOMEM) {
        flb_error("[aws_credentials] Could not parse IoT credentials response - response contained more tokens than expected.");
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
     * For IoT credentials, the structure is:
     * {"credentials": {"accessKeyId": "...", "secretAccessKey": "...", ...}}
     */
    while (i < (tokens_size - 1)) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type == JSMN_STRING) {
            current_token = &response[t->start];
            len = t->end - t->start;

            /* Check for credentials wrapper object */
            if (strncmp(current_token, "credentials", len) == 0) {
                /* Skip the credentials object - we'll process its contents */
                i++;
                continue;
            }

            /* Check for AccessKeyId field (case insensitive) */
            if (strncmp(current_token, "accessKeyId", len) == 0 || 
                strncmp(current_token, "AccessKeyId", len) == 0) {
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
            /* Check for SecretAccessKey field (case insensitive) */
            if (strncmp(current_token, "secretAccessKey", len) == 0 || 
                strncmp(current_token, "SecretAccessKey", len) == 0) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->secret_access_key != NULL) {
                    flb_error("Trying to double allocate secret_access_key");
                    goto error;
                }
                creds->secret_access_key = flb_sds_create_len(current_token, len);
                if (!creds->secret_access_key) {
                    flb_errno();
                    goto error;
                }
                continue;
            }
            /* Check for Token field (session token) - case insensitive */
            if (strncmp(current_token, "sessionToken", len) == 0 || 
                strncmp(current_token, "Token", len) == 0) {
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
            /* Check for Expiration field (case insensitive) */
            if (strncmp(current_token, "expiration", len) == 0 || 
                strncmp(current_token, "Expiration", len) == 0) {
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
                if (*expiration < 0) {
                    flb_warn("[aws_credentials] '%s' was invalid or could not be parsed. Disabling auto-refresh of credentials.", tmp);
                }
                flb_sds_destroy(tmp);
            }
        }

        i++;
    }

    if (creds->access_key_id == NULL) {
        flb_error("[aws_credentials] Missing AccessKeyId field in IoT credentials response");
        goto error;
    }

    if (creds->secret_access_key == NULL) {
        flb_error("[aws_credentials] Missing SecretAccessKey field in IoT credentials response");
        goto error;
    }

    flb_debug("[aws_credentials] Successfully parsed IoT credentials - AccessKeyId: %s, Expiration: %ld", 
              creds->access_key_id, *expiration);

    flb_free(tokens);
    return creds;

error:
    flb_aws_credentials_destroy(creds);
    flb_free(tokens);
    return NULL;
} 