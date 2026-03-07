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

#include "flb_aws_credentials_log.h"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>

#ifdef FLB_HAVE_LIBYAML
#include <yaml.h>
#endif

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

struct gg_config {
    char *cert_file;
    char *key_file;
    char *ca_cert_file;
    char *thing_name;
    char *cred_endpoint;
    char *role_alias;
};

#ifdef FLB_HAVE_LIBYAML
static void free_gg_config(struct gg_config *config)
{
    if (config) {
        if (config->cert_file) {
            flb_free(config->cert_file);
        }
        if (config->key_file) {
            flb_free(config->key_file);
        }
        if (config->ca_cert_file) {
            flb_free(config->ca_cert_file);
        }
        if (config->thing_name) {
            flb_free(config->thing_name);
        }
        if (config->cred_endpoint) {
            flb_free(config->cred_endpoint);
        }
        if (config->role_alias) {
            flb_free(config->role_alias);
        }
    }
}

/*
 * Parse Greengrass V2 config.yaml to extract IoT configuration.
 * The config.yaml has the following relevant structure:
 *
 * system:
 *   certificateFilePath: "/path/to/cert"
 *   privateKeyPath: "/path/to/key"
 *   rootCaPath: "/path/to/ca"
 *   thingName: "thing-name"
 * services:
 *   aws.greengrass.Nucleus:
 *     configuration:
 *       iotCredEndpoint: "xxx.credentials.iot.region.amazonaws.com"
 *       iotRoleAlias: "role-alias-name"
 *
 * Returns 0 on success, -1 on failure.
 */
static int parse_greengrass_config(const char *config_path,
                                   struct gg_config *config)
{
    FILE *fh = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    int ret = -1;
    int depth = 0;
    int in_system = 0;
    int in_services = 0;
    int in_nucleus = 0;
    int in_configuration = 0;
    char *last_key = NULL;
    char *value = NULL;

    if (!config_path || !config) {
        return -1;
    }

    memset(config, 0, sizeof(struct gg_config));

    fh = fopen(config_path, "r");
    if (!fh) {
        AWS_CREDS_DEBUG("Could not open Greengrass config file: %s", config_path);
        return -1;
    }

    if (!yaml_parser_initialize(&parser)) {
        AWS_CREDS_DEBUG("Failed to initialize YAML parser");
        fclose(fh);
        return -1;
    }

    yaml_parser_set_input_file(&parser, fh);

    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            AWS_CREDS_DEBUG("YAML parsing error in Greengrass config");
            yaml_event_delete(&event);
            goto cleanup;
        }

        switch (event.type) {
        case YAML_STREAM_END_EVENT:
            done = 1;
            break;

        case YAML_MAPPING_START_EVENT:
            depth++;
            break;

        case YAML_MAPPING_END_EVENT:
            depth--;
            if (depth == 1) {
                in_system = 0;
                in_services = 0;
            }
            if (depth == 2 && in_services) {
                in_nucleus = 0;
            }
            if (depth == 3 && in_nucleus) {
                in_configuration = 0;
            }
            break;

        case YAML_SCALAR_EVENT:
            value = (char *)event.data.scalar.value;

            if (depth == 1) {
                /* Top level keys */
                if (strcmp(value, "system") == 0) {
                    in_system = 1;
                    in_services = 0;
                }
                else if (strcmp(value, "services") == 0) {
                    in_services = 1;
                    in_system = 0;
                }
                if (last_key) {
                    flb_free(last_key);
                }
                last_key = flb_strdup(value);
            }
            else if (depth == 2 && in_system) {
                /* Inside system section */
                if (last_key) {
                    if (strcmp(last_key, "certificateFilePath") == 0) {
                        if (config->cert_file) {
                            flb_free(config->cert_file);
                        }
                        config->cert_file = flb_strdup(value);
                    }
                    else if (strcmp(last_key, "privateKeyPath") == 0) {
                        if (config->key_file) {
                            flb_free(config->key_file);
                        }
                        config->key_file = flb_strdup(value);
                    }
                    else if (strcmp(last_key, "rootCaPath") == 0) {
                        if (config->ca_cert_file) {
                            flb_free(config->ca_cert_file);
                        }
                        config->ca_cert_file = flb_strdup(value);
                    }
                    else if (strcmp(last_key, "thingName") == 0) {
                        if (config->thing_name) {
                            flb_free(config->thing_name);
                        }
                        config->thing_name = flb_strdup(value);
                    }
                    flb_free(last_key);
                }
                last_key = flb_strdup(value);
            }
            else if (depth == 2 && in_services) {
                /* Service name */
                if (strcmp(value, "aws.greengrass.Nucleus") == 0) {
                    in_nucleus = 1;
                }
                if (last_key) {
                    flb_free(last_key);
                }
                last_key = flb_strdup(value);
            }
            else if (depth == 3 && in_nucleus) {
                /* Inside Nucleus service */
                if (strcmp(value, "configuration") == 0) {
                    in_configuration = 1;
                }
                if (last_key) {
                    flb_free(last_key);
                }
                last_key = flb_strdup(value);
            }
            else if (depth == 4 && in_configuration) {
                /* Inside configuration */
                if (last_key) {
                    if (strcmp(last_key, "iotCredEndpoint") == 0) {
                        if (config->cred_endpoint) {
                            flb_free(config->cred_endpoint);
                        }
                        config->cred_endpoint = flb_strdup(value);
                    }
                    else if (strcmp(last_key, "iotRoleAlias") == 0) {
                        if (config->role_alias) {
                            flb_free(config->role_alias);
                        }
                        config->role_alias = flb_strdup(value);
                    }
                    flb_free(last_key);
                }
                last_key = flb_strdup(value);
            }
            else {
                /* Track keys at any other level */
                if (last_key) {
                    flb_free(last_key);
                }
                last_key = flb_strdup(value);
            }
            break;

        default:
            break;
        }

        yaml_event_delete(&event);
    }

    ret = 0;

cleanup:
    if (ret != 0) {
        free_gg_config(config);
    }
    if (last_key) {
        flb_free(last_key);
    }
    yaml_parser_delete(&parser);
    fclose(fh);
    return ret;
}
#endif /* FLB_HAVE_LIBYAML */

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
static struct flb_aws_credentials *flb_parse_iot_credentials(char *response,
                                                             size_t response_len,
                                                             time_t *expiration);

struct flb_aws_credentials *get_credentials_fn_iot(struct flb_aws_provider *provider)
{
    struct flb_aws_credentials *creds = NULL;
    int refresh = FLB_FALSE;
    struct flb_aws_provider_iot *implementation = provider->implementation;

    AWS_CREDS_DEBUG("Requesting credentials from the IoT provider..");

    /* a negative next_refresh means that auto-refresh is disabled */
    if (implementation->next_refresh > 0
        && time(NULL) > implementation->next_refresh) {
        refresh = FLB_TRUE;
    }
    if (!implementation->creds || refresh == FLB_TRUE) {
        if (try_lock_provider(provider)) {
            AWS_CREDS_DEBUG("IoT Provider: Refreshing credential cache.");
            if (iot_credentials_request(implementation) < 0) {
              AWS_CREDS_WARN("IoT Provider: failed to refresh credentials.");  
            }
            unlock_provider(provider);
        }
    }

    if (!implementation->creds) {
        /*
         * We failed to lock the provider and creds are unset. This means that
         * another co-routine is performing the refresh.
         */
        AWS_CREDS_WARN("No cached credentials are available and "
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

int refresh_fn_iot(struct flb_aws_provider *provider)
{
    int ret = -1;
    struct flb_aws_provider_iot *implementation = provider->implementation;

    AWS_CREDS_DEBUG("Refresh called on the IoT provider");

    if (try_lock_provider(provider)) {
        ret = iot_credentials_request(implementation);
        unlock_provider(provider);
    }
    return ret;
}

int init_fn_iot(struct flb_aws_provider *provider)
{
    int ret = -1;
    struct flb_aws_provider_iot *implementation = provider->implementation;

    AWS_CREDS_DEBUG("Init called on the IoT provider");

    implementation->client->debug_only = FLB_TRUE;

    if (try_lock_provider(provider)) {
        ret = iot_credentials_request(implementation);
        unlock_provider(provider);
    }

    implementation->client->debug_only = FLB_FALSE;
    return ret;
}

void sync_fn_iot(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_iot *implementation = provider->implementation;

    AWS_CREDS_DEBUG("Sync called on the IoT provider");
    /* Remove async flag */
    flb_stream_disable_async_mode(&implementation->client->upstream->base);
}

void async_fn_iot(struct flb_aws_provider *provider)
{
    struct flb_aws_provider_iot *implementation = provider->implementation;

    AWS_CREDS_DEBUG("Async called on the IoT provider");
    /* Add async flag */
    flb_stream_enable_async_mode(&implementation->client->upstream->base);
}

void upstream_set_fn_iot(struct flb_aws_provider *provider,
                         struct flb_output_instance *ins)
{
    struct flb_aws_provider_iot *implementation = provider->implementation;

    AWS_CREDS_DEBUG("upstream_set called on the IoT provider");
    /* Associate output and upstream */
    flb_output_upstream_set(implementation->client->upstream, ins);
}

void destroy_fn_iot(struct flb_aws_provider *provider)
{
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
                                                 struct flb_aws_client_generator
                                                 *generator)
{
    struct flb_aws_provider_iot *implementation = NULL;
    struct flb_aws_provider *provider = NULL;
    struct flb_upstream *upstream = NULL;
    flb_sds_t endpoint_path = NULL;
    flb_sds_t protocol = NULL;
    flb_sds_t host = NULL;
    flb_sds_t port_sds = NULL;
    int port = 443;
    int ret;
#ifdef FLB_HAVE_LIBYAML
    struct gg_config gg_cfg;
    char *gg_config_path = NULL;
    int gg_parsed = 0;
#endif

    /*
     * Configuration priority (highest to lowest):
     * 1. Explicit environment variables (AWS_IOT_*)
     * 2. Greengrass V2 config.yaml (if AWS_IOT_GREENGRASS_V2_CONFIG_PATH is set)
     * 3. GG_ROOT_CA_PATH fallback for CA cert
     */
    char *key_file = getenv(AWS_IOT_KEY_FILE);
    char *cert_file = getenv(AWS_IOT_CERT_FILE);
    char *ca_cert_file = getenv(AWS_IOT_CA_CERT_FILE);
    char *credentials_endpoint = getenv(AWS_IOT_CREDENTIALS_ENDPOINT);
    char *thing_name = getenv(AWS_IOT_THING_NAME);
    char *role_alias = getenv(AWS_IOT_ROLE_ALIAS);

#ifdef FLB_HAVE_LIBYAML
    /*
     * If any required values are missing, try Greengrass V2 config.yaml
     */
    if (!key_file || !cert_file || !ca_cert_file || !credentials_endpoint ||
        !thing_name || !role_alias) {
        gg_config_path = getenv(AWS_IOT_GREENGRASS_V2_CONFIG);
        if (gg_config_path) {
            AWS_CREDS_DEBUG("Attempting to read IoT config from "
                            "Greengrass V2 config: %s", gg_config_path);
            memset(&gg_cfg, 0, sizeof(struct gg_config));
            if (parse_greengrass_config(gg_config_path, &gg_cfg) == 0) {
                gg_parsed = 1;
                /* Use Greengrass values for any missing env vars */
                if (!key_file && gg_cfg.key_file) {
                    key_file = gg_cfg.key_file;
                    AWS_CREDS_DEBUG("Using privateKeyPath from Greengrass config");
                }
                if (!cert_file && gg_cfg.cert_file) {
                    cert_file = gg_cfg.cert_file;
                    AWS_CREDS_DEBUG("Using certificateFilePath from "
                                    "Greengrass config");
                }
                if (!ca_cert_file && gg_cfg.ca_cert_file) {
                    ca_cert_file = gg_cfg.ca_cert_file;
                    AWS_CREDS_DEBUG("Using rootCaPath from Greengrass config");
                }
                if (!thing_name && gg_cfg.thing_name) {
                    thing_name = gg_cfg.thing_name;
                    AWS_CREDS_DEBUG("Using thingName from Greengrass config");
                }
                if (!credentials_endpoint && gg_cfg.cred_endpoint) {
                    credentials_endpoint = gg_cfg.cred_endpoint;
                    AWS_CREDS_DEBUG("Using iotCredEndpoint from "
                                    "Greengrass config");
                }
                if (!role_alias && gg_cfg.role_alias) {
                    role_alias = gg_cfg.role_alias;
                    AWS_CREDS_DEBUG("Using iotRoleAlias from Greengrass config");
                }
            }
        }
    }
#endif

    /* Fallback: use GG_ROOT_CA_PATH for CA cert if still missing */
    if (!ca_cert_file) {
        ca_cert_file = getenv(AWS_GG_ROOT_CA_PATH);
        if (ca_cert_file) {
            AWS_CREDS_DEBUG("Using GG_ROOT_CA_PATH as fallback for CA cert");
        }
    }

    /* Check if we have all required values now */
    if (!key_file || !cert_file || !ca_cert_file || !credentials_endpoint ||
        !thing_name || !role_alias) {
        AWS_CREDS_DEBUG("Not initializing IoT provider because "
                        "required configuration is not available");
#ifdef FLB_HAVE_LIBYAML
        if (gg_parsed) {
            free_gg_config(&gg_cfg);
        }
#endif
        return NULL;
    }

    provider = flb_calloc(1, sizeof(struct flb_aws_provider));
    if (!provider) {
        flb_errno();
        goto cleanup;
    }

    pthread_mutex_init(&provider->lock, NULL);

    implementation = flb_calloc(1, sizeof(struct flb_aws_provider_iot));
    if (!implementation) {
        flb_errno();
        pthread_mutex_destroy(&provider->lock);
        flb_free(provider);
        provider = NULL;
        goto cleanup;
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

    if (!implementation->key_file || !implementation->cert_file ||
        !implementation->ca_cert_file || !implementation->credentials_endpoint ||
        !implementation->thing_name || !implementation->role_alias) {
        flb_errno();
        goto error;
    }

    /*
     * Ensure credentials_endpoint has http or https scheme,
     * default to https:// if missing
     */
    if (strncmp(credentials_endpoint, "http://", 7) != 0 &&
        strncmp(credentials_endpoint, "https://", 8) != 0) {
        flb_sds_t tmp_orig = flb_sds_create_size(strlen(credentials_endpoint) + 8 + 1);
        flb_sds_t tmp = tmp_orig;        
        if (!tmp_orig) {
            AWS_CREDS_ERROR("Failed to allocate memory for credentials_endpoint");
            goto error;
        }
        tmp = flb_sds_cat(tmp, "https://", 8);
        if (!tmp) {
            flb_sds_destroy(tmp_orig);
            goto error;
        }
        tmp_orig = tmp;
        tmp = flb_sds_cat(tmp, credentials_endpoint, strlen(credentials_endpoint));
        if (!tmp) {
            flb_sds_destroy(tmp_orig);
            goto error;
        }
        flb_free(implementation->credentials_endpoint);
        implementation->credentials_endpoint = flb_strdup(tmp);
        flb_sds_destroy(tmp);
        if (!implementation->credentials_endpoint) {
            flb_errno();
            goto error;
        }
        credentials_endpoint = implementation->credentials_endpoint;
    }

    /* Parse the credentials endpoint URL */
    ret = flb_utils_url_split_sds(credentials_endpoint, &protocol, &host,
                                  &port_sds, &endpoint_path);
    if (ret < 0) {
        AWS_CREDS_ERROR("Invalid IoT credentials endpoint URL: %s", credentials_endpoint);
        goto error;
    }

    /*
     * Warn if the endpoint URL contains a path component.
     * The IoT credentials provider uses a fixed request path
     * (/role-aliases/<alias>/credentials) derived from the role alias,
     * so any user-supplied path in the endpoint URL is ignored.
     */
    if (endpoint_path != NULL && strlen(endpoint_path) > 0
        && strcmp(endpoint_path, "/") != 0) {
        AWS_CREDS_WARN("IoT credentials endpoint '%s' contains a path "
                        "component '%s' which will be ignored. "
                        "Only the host and port are used; the request path "
                        "is built from the role alias "
                        "(/role-aliases/<alias>/credentials).",
                        credentials_endpoint, endpoint_path);
    }

    if (port_sds != NULL) {
        char *endptr = NULL;
        long port_long;

        errno = 0;
        port_long = strtol(port_sds, &endptr, 10);

        if (errno == ERANGE || endptr == port_sds || *endptr != '\0' ||
            port_long < 1 || port_long > 65535) {
            AWS_CREDS_ERROR("Invalid port in IoT credentials endpoint: %s", port_sds);
            goto error;
        }
        port = (int) port_long;
    }

    /* Create TLS configuration for IoT certificates */
    AWS_CREDS_DEBUG("Creating TLS instance with cert: %s, key: %s, ca: %s",
                    implementation->cert_file,
                    implementation->key_file,
                    implementation->ca_cert_file);
    
    implementation->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                        FLB_TRUE,
                                        0,
                                        NULL, /* vhost */
                                        NULL, /* ca_path */
                                        implementation->ca_cert_file,
                                        implementation->cert_file,
                                        implementation->key_file,
                                        NULL); /* key_passwd */
    if (!implementation->tls) {
        AWS_CREDS_ERROR("Failed to create TLS instance for IoT Provider");
        goto error;
    }
    
    AWS_CREDS_DEBUG("TLS instance created successfully");

    /* Create upstream connection */
    AWS_CREDS_DEBUG("Creating upstream connection to %s:%d", host, port);
    upstream = flb_upstream_create(config, host, port, FLB_IO_TLS, implementation->tls);
    if (!upstream) {
        AWS_CREDS_ERROR("IoT Provider: connection initialization error");
        goto error;
    }
    
    AWS_CREDS_DEBUG("Upstream connection created successfully");

    upstream->base.net.connect_timeout = FLB_AWS_CREDENTIAL_NET_TIMEOUT;

    implementation->client = generator->create();
    if (!implementation->client) {
        flb_upstream_destroy(upstream);
        upstream = NULL;
        AWS_CREDS_ERROR("IoT Provider: client creation error");
        goto error;
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
    
    AWS_CREDS_DEBUG("IoT client configured: name=%s, port=%d, has_auth=%d",
                    implementation->client->name,
                    implementation->client->port,
                    implementation->client->has_auth);

    /* Set up the thing name header */
    implementation->thing_name_header.key = "x-amzn-iot-thingname";
    implementation->thing_name_header.key_len = 20;
    implementation->thing_name_header.val = implementation->thing_name;
    implementation->thing_name_header.val_len = strlen(implementation->thing_name);

    AWS_CREDS_DEBUG("Setting IoT thing name header: %s = %s",
                    implementation->thing_name_header.key,
                    implementation->thing_name_header.val);

    /* Set the static headers for the client */
    implementation->client->static_headers = &implementation->thing_name_header;
    implementation->client->static_headers_len = 1;

cleanup:
#ifdef FLB_HAVE_LIBYAML
    if (gg_parsed) {
        free_gg_config(&gg_cfg);
    }
#endif
    flb_sds_destroy(protocol);
    flb_sds_destroy(host);
    flb_sds_destroy(port_sds);
    flb_sds_destroy(endpoint_path);
    return provider;

error:
    flb_aws_provider_destroy(provider);
    provider = NULL;
    goto cleanup;
}

static int iot_credentials_request(struct flb_aws_provider_iot *implementation)
{
    struct flb_aws_credentials *creds = NULL;
    struct flb_http_client *c = NULL;
    time_t expiration;
    flb_sds_t uri = NULL;
    flb_sds_t tmp = NULL;
    int ret;

    AWS_CREDS_DEBUG("Calling IoT credentials endpoint..");

    /* Construct the URI for the IoT credentials request */
    uri = flb_sds_create_size(256);
    if (!uri) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&uri, "/role-aliases/%s/credentials",
                         implementation->role_alias);
    if (!tmp) {
        flb_sds_destroy(uri);
        return -1;
    }
    uri = tmp;

    /* Make the HTTP request */
    AWS_CREDS_DEBUG("Making IoT credentials request to: %s", uri);
    AWS_CREDS_DEBUG("Client headers count: %d", implementation->client->static_headers_len);
    if (implementation->client->static_headers_len > 0) {
        AWS_CREDS_DEBUG("Client header: %s = %s", 
                  implementation->client->static_headers[0].key,
                  implementation->client->static_headers[0].val);
    }
    
    c = implementation->client->client_vtable->request(implementation->client, FLB_HTTP_GET,
                                                      uri, NULL, 0, NULL, 0);

    flb_sds_destroy(uri);

    if (!c) {
        AWS_CREDS_ERROR("IoT credentials request failed - no response");
        return -1;
    }

    AWS_CREDS_DEBUG("IoT credentials response status: %d", c->resp.status);
    AWS_CREDS_DEBUG("IoT credentials response size: %zu", c->resp.payload_size);

    if (c->resp.status != 200) {
        AWS_CREDS_ERROR("IoT credentials request failed with status: %d", c->resp.status);
        if (c->resp.payload_size > 0) {
            flb_aws_print_error_code(c->resp.payload, c->resp.payload_size,
                                     "IoTCredentialsProvider");
        }
        flb_http_client_destroy(c);
        return -1;
    }

    AWS_CREDS_DEBUG("IoT credentials response received (size: %zu)",
                    c->resp.payload_size);

    /* Parse the credentials response - IoT endpoint may have different format */
    creds = flb_parse_iot_credentials(c->resp.payload, c->resp.payload_size, &expiration);
    if (!creds) {
        AWS_CREDS_DEBUG("Failed to parse IoT credentials response");
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
static struct flb_aws_credentials *flb_parse_iot_credentials(char *response,
                                                             size_t response_len,
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

    ret = jsmn_parse(&parser, response, response_len, tokens, tokens_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        AWS_CREDS_ERROR("Could not parse IoT credentials response - invalid JSON.");
        goto error;
    }

    /* Shouldn't happen, but just in case, check for too many tokens error */
    if (ret == JSMN_ERROR_NOMEM) {
        AWS_CREDS_ERROR("Could not parse IoT credentials response "
                        "- response contained more tokens than expected.");
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
            if (len == sizeof("credentials") - 1
                && strncmp(current_token, "credentials", len) == 0) {
                /* Skip the credentials object - we'll process its contents */
                i++;
                continue;
            }

            /* Check for AccessKeyId field (case insensitive) */
            if (len == sizeof("accessKeyId") - 1
                && (strncmp(current_token, "accessKeyId", len) == 0 ||
                    strncmp(current_token, "AccessKeyId", len) == 0)) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->access_key_id != NULL) {
                    AWS_CREDS_ERROR("Trying to double allocate access_key_id");
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
            if (len == sizeof("secretAccessKey") - 1
                && (strncmp(current_token, "secretAccessKey", len) == 0 ||
                    strncmp(current_token, "SecretAccessKey", len) == 0)) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->secret_access_key != NULL) {
                    AWS_CREDS_ERROR("Trying to double allocate secret_access_key");
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
            if ((len == sizeof("sessionToken") - 1
                 && strncmp(current_token, "sessionToken", len) == 0) ||
                (len == sizeof("Token") - 1
                 && strncmp(current_token, "Token", len) == 0)) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                if (creds->session_token != NULL) {
                    AWS_CREDS_ERROR("Trying to double allocate session_token");
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
            if (len == sizeof("expiration") - 1
                && (strncmp(current_token, "expiration", len) == 0 ||
                    strncmp(current_token, "Expiration", len) == 0)) {
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
                    AWS_CREDS_WARN("'%s' was invalid or could not be parsed. "
                                   "Disabling auto-refresh of credentials.", tmp);
                }
                flb_sds_destroy(tmp);
            }
        }

        i++;
    }

    if (creds->access_key_id == NULL) {
        AWS_CREDS_ERROR("Missing AccessKeyId field in IoT credentials response");
        goto error;
    }

    if (creds->secret_access_key == NULL) {
        AWS_CREDS_ERROR("Missing SecretAccessKey field in IoT credentials response");
        goto error;
    }

    AWS_CREDS_DEBUG("Successfully parsed IoT credentials "
                    "- AccessKeyId: %s, Expiration: %ld",
                    creds->access_key_id, *expiration);

    flb_free(tokens);
    return creds;

error:
    flb_aws_credentials_destroy(creds);
    flb_free(tokens);
    return NULL;
}
