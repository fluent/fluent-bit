/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_output_plugin.h>

#include <jsmn/jsmn.h>
#include <stdlib.h>

struct flb_http_client *request_do(struct flb_aws_client *aws_client,
                                   int method, const char *uri,
                                   const char *body, size_t body_len,
                                   struct flb_aws_header *dynamic_headers,
                                   size_t dynamic_headers_len);

/*
 * https://service.region.amazonaws.com(.cn)
 */
char *flb_aws_endpoint(char* service, char* region)
{
    char *endpoint = NULL;
    size_t len = AWS_SERVICE_ENDPOINT_BASE_LEN;
    int is_cn = FLB_FALSE;


    /* In the China regions, ".cn" is appended to the URL */
    if (strcmp("cn-north-1", region) == 0) {
        len += 3;
        is_cn = FLB_TRUE;
    }
    if (strcmp("cn-northwest-1", region) == 0) {
        len += 3;
        is_cn = FLB_TRUE;
    }

    len += strlen(service);
    len += strlen(region);
    len ++; /* null byte */

    endpoint = flb_malloc(sizeof(char) * len);
    if (!endpoint) {
        flb_errno();
        return NULL;
    }

    snprintf(endpoint, len, AWS_SERVICE_ENDPOINT_FORMAT, service, region);

    if (is_cn) {
        strncat(endpoint, ".cn", 3);
    }

    return endpoint;

}

struct flb_http_client *flb_aws_client_request(struct flb_aws_client *aws_client,
                                               int method, const char *uri,
                                               const char *body, size_t body_len,
                                               struct flb_aws_header
                                               *dynamic_headers,
                                               size_t dynamic_headers_len)
{
    struct flb_http_client *c = NULL;
    flb_sds_t error = NULL;

    //TODO: Need to think more about the retry strategy.

    c = request_do(aws_client, method, uri, body, body_len,
                   dynamic_headers, dynamic_headers_len);

    /*
     * 400 or 403 could indicate an issue with credentials- so we check for auth
     * specific error messages and then force a refresh on the provider.
     * For safety a refresh can be performed only once
     * per FLB_AWS_CREDENTIAL_REFRESH_LIMIT.
     *
     */
    if (c && (c->resp.status == 400 || c->resp.status == 403)) {
        error = flb_aws_error(c->resp.payload, c->resp.payload_size);
        if (error != NULL) {
            if (strcmp(error, "ExpiredToken") == 0 ||
                strcmp(error, "AccessDeniedException") == 0 ||
                strcmp(error, "IncompleteSignature") == 0 ||
                strcmp(error, "MissingAuthenticationToken") == 0 ||
                strcmp(error, "InvalidClientTokenId") == 0 ||
                strcmp(error, "UnrecognizedClientException") == 0) {
                    if (aws_client->has_auth && time(NULL) >
                        aws_client->refresh_limit) {

                        aws_client->refresh_limit = time(NULL)
                                                    + FLB_AWS_CREDENTIAL_REFRESH_LIMIT;
                        aws_client->provider->provider_vtable->
                                              refresh(aws_client->provider);
                    }
                }
            flb_sds_destroy(error);
        }
    }

    return c;
}

static struct flb_aws_client_vtable client_vtable = {
    .request = flb_aws_client_request,
};

struct flb_aws_client *flb_aws_client_create()
{
    struct flb_aws_client *client = flb_calloc(1,
                                                sizeof(struct flb_aws_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &client_vtable;
    return client;
}

/* Generator that returns clients with the default vtable */

static struct flb_aws_client_generator default_generator = {
    .create = flb_aws_client_create,
};

struct flb_aws_client_generator *flb_aws_client_generator()
{
    return &default_generator;
}

void flb_aws_client_destroy(struct flb_aws_client *aws_client)
{
    if (aws_client) {
        if (aws_client->upstream) {
            flb_upstream_destroy(aws_client->upstream);
        }
        flb_free(aws_client);
    }
}

struct flb_http_client *request_do(struct flb_aws_client *aws_client,
                                   int method, const char *uri,
                                   const char *body, size_t body_len,
                                   struct flb_aws_header *dynamic_headers,
                                   size_t dynamic_headers_len)
{
    size_t b_sent;
    int ret;
    struct flb_upstream_conn *u_conn = NULL;
    flb_sds_t signature = NULL;
    int i;
    struct flb_aws_header header;
    struct flb_http_client *c = NULL;

    u_conn = flb_upstream_conn_get(aws_client->upstream);
    if (!u_conn) {
        flb_error("[aws_client] connection initialization error");
        return NULL;
    }

    /* Compose HTTP request */
    c = flb_http_client(u_conn, method, uri,
                        body, body_len,
                        aws_client->host, aws_client->port,
                        aws_client->proxy, aws_client->flags);

    if (!c) {
        flb_error("[aws_client] could not initialize request");
        goto error;
    }

    /* Add AWS Fluent Bit user agent */
    ret = flb_http_add_header(c, "User-Agent", 10,
                              "aws-fluent-bit-plugin", 21);
    if (ret < 0) {
        flb_error("[aws_client] failed to add header to request");
        goto error;
    }

    /* add headers */
    for (i = 0; i < aws_client->static_headers_len; i++) {
        header = aws_client->static_headers[i];
        ret =  flb_http_add_header(c,
                                   header.key, header.key_len,
                                   header.val, header.val_len);
        if (ret < 0) {
            flb_error("[aws_client] failed to add header to request");
            goto error;
        }
    }

    for (i = 0; i < dynamic_headers_len; i++) {
        header = dynamic_headers[i];
        ret =  flb_http_add_header(c,
                                   header.key, header.key_len,
                                   header.val, header.val_len);
        if (ret < 0) {
            flb_error("[aws_client] failed to add header to request");
            goto error;
        }
    }

    if (aws_client->has_auth) {
        signature = flb_signv4_do(c, FLB_TRUE, FLB_TRUE, time(NULL),
                                  aws_client->region, aws_client->service,
                                  aws_client->provider);
        if (!signature) {
            flb_error("[aws_client] could not sign request");
            goto error;
        }
    }

    /* Perform request */
    ret = flb_http_do(c, &b_sent);

    if (ret != 0 || c->resp.status != 200) {
        flb_debug("[aws_client] %s: http_do=%i, HTTP Status: %i",
                  aws_client->host, ret, c->resp.status);
    }

    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(signature);
    return c;

error:
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    if (signature) {
        flb_sds_destroy(signature);
    }
    if (c) {
        flb_http_client_destroy(c);
    }
    return NULL;
}

void flb_aws_print_error(char *response, size_t response_len,
                              char *api, struct flb_output_instance *ins)
{
    flb_sds_t error;
    flb_sds_t message;

    error = flb_json_get_val(response, response_len, "__type");
    if (!error) {
        return;
    }

    message = flb_json_get_val(response, response_len, "message");
    if (!message) {
        /* just print the error */
        flb_plg_error(ins, "%s API responded with error='%s'", api, error);
    }
    else {
        flb_plg_error(ins, "%s API responded with error='%s', message='%s'",
                      api, error, message);
        flb_sds_destroy(message);
    }

    flb_sds_destroy(error);
}

/* parses AWS API error responses and returns the value of the __type field */
flb_sds_t flb_aws_error(char *response, size_t response_len)
{
    return flb_json_get_val(response, response_len, "__type");
}

/* gets the value of a key in a json string */
flb_sds_t flb_json_get_val(char *response, size_t response_len, char *key)
{
    jsmntok_t *tokens = NULL;
    const jsmntok_t *t = NULL;
    char *current_token = NULL;
    jsmn_parser parser;
    int tokens_size = 10;
    size_t size;
    int ret;
    int i = 0;
    int len;
    flb_sds_t error_type = NULL;

    jsmn_init(&parser);

    size = sizeof(jsmntok_t) * tokens_size;
    tokens = flb_calloc(1, size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    ret = jsmn_parse(&parser, response, response_len,
                     tokens, tokens_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_free(tokens);
        flb_debug("[aws_client] Unable to parse API response- response is not"
                  "not valid JSON.");
        return NULL;
    }

    /* return value is number of tokens parsed */
    tokens_size = ret;

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

            if (strncmp(current_token, key, strlen(key)) == 0) {
                i++;
                t = &tokens[i];
                current_token = &response[t->start];
                len = t->end - t->start;
                error_type = flb_sds_create_len(current_token, len);
                if (!error_type) {
                    flb_errno();
                    flb_free(tokens);
                    return NULL;
                }
                break;
            }
        }

        i++;
    }
    flb_free(tokens);
    return error_type;
}

int flb_imds_request(struct flb_aws_client *client, char *metadata_path,
                     flb_sds_t *metadata, size_t *metadata_len)
{
    struct flb_http_client *c = NULL;
    flb_sds_t ec2_metadata;

    flb_debug("[imds] Using instance metadata V1");
    c = client->client_vtable->request(client, FLB_HTTP_GET,
                                       metadata_path, NULL, 0,
                                       NULL, 0);

    if (!c) {
        return -1;
    }

    if (c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_debug("[ecs_imds] IMDS metadata response\n%s",
                      c->resp.payload);
        }

        flb_http_client_destroy(c);
        return -1;
    }

    if (c->resp.payload_size > 0) {
        ec2_metadata = flb_sds_create_len(c->resp.payload,
                                          c->resp.payload_size);

        if (!ec2_metadata) {
            flb_errno();
            return -1;
        }
        *metadata = ec2_metadata;
        *metadata_len = c->resp.payload_size;

        flb_http_client_destroy(c);
        return 0;
    }
    else {
        flb_debug("[ecs_imds] IMDS metadata response was empty");
        flb_http_client_destroy(c);
        return -1;
    }
}
