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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_http_client_debug.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_env.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define AWS_SERVICE_ENDPOINT_FORMAT            "%s.%s%s"
#define AWS_SERVICE_ENDPOINT_SUFFIX_COM        ".amazonaws.com"
#define AWS_SERVICE_ENDPOINT_SUFFIX_COM_CN     ".amazonaws.com.cn"
#define AWS_SERVICE_ENDPOINT_SUFFIX_EU         ".amazonaws.eu"

#define TAG_PART_DESCRIPTOR "$TAG[%d]"
#define TAG_DESCRIPTOR "$TAG"
#define MAX_TAG_PARTS 10
#define S3_KEY_SIZE 1024
#define RANDOM_STRING "$UUID"
#define INDEX_STRING "$INDEX"
#define AWS_USER_AGENT_NONE "none"
#define AWS_USER_AGENT_ECS "ecs"
#define AWS_USER_AGENT_K8S "k8s"
#define AWS_ECS_METADATA_URI "ECS_CONTAINER_METADATA_URI_V4"
#define FLB_MAX_AWS_RESP_BUFFER_SIZE 0 /* 0 means unlimited capacity as per requirement */

#ifdef FLB_SYSTEM_WINDOWS
#define FLB_AWS_BASE_USER_AGENT        "aws-fluent-bit-plugin-windows"
#define FLB_AWS_BASE_USER_AGENT_FORMAT "aws-fluent-bit-plugin-windows-%s"
#define FLB_AWS_BASE_USER_AGENT_LEN    29
#else
#define FLB_AWS_BASE_USER_AGENT        "aws-fluent-bit-plugin"
#define FLB_AWS_BASE_USER_AGENT_FORMAT "aws-fluent-bit-plugin-%s"
#define FLB_AWS_BASE_USER_AGENT_LEN    21
#endif

#define FLB_AWS_MILLISECOND_FORMATTER_LENGTH 3
#define FLB_AWS_NANOSECOND_FORMATTER_LENGTH 9
#define FLB_AWS_MILLISECOND_FORMATTER "%3N"
#define FLB_AWS_NANOSECOND_FORMATTER_N "%9N"
#define FLB_AWS_NANOSECOND_FORMATTER_L "%L"

struct flb_http_client *request_do(struct flb_aws_client *aws_client,
                                   int method, const char *uri,
                                   const char *body, size_t body_len,
                                   struct flb_aws_header *dynamic_headers,
                                   size_t dynamic_headers_len);

/*
 * https://service.region.amazonaws.[com(.cn)|eu]
 */
char *flb_aws_endpoint(char* service, char* region)
{
    char *endpoint = NULL;
    const char *domain_suffix = AWS_SERVICE_ENDPOINT_SUFFIX_COM;
    size_t len;
    int bytes;


    /* China regions end with amazonaws.com.cn */
    if (strcmp("cn-north-1", region) == 0 ||
        strcmp("cn-northwest-1", region) == 0) {
        domain_suffix = AWS_SERVICE_ENDPOINT_SUFFIX_COM_CN;
    }
    else if (strcmp("eusc-de-east-1", region) == 0) {
        domain_suffix = AWS_SERVICE_ENDPOINT_SUFFIX_EU;
    }

    len = strlen(service);
    len += 1; /* dot between service and region */
    len += strlen(region);
    len += strlen(domain_suffix);
    len += 1; /* null byte */

    endpoint = flb_calloc(len, sizeof(char));
    if (!endpoint) {
        flb_errno();
        return NULL;
    }

    bytes = snprintf(endpoint, len, AWS_SERVICE_ENDPOINT_FORMAT, service, region, domain_suffix);
    if (bytes < 0) {
        flb_errno();
        flb_free(endpoint);
        return NULL;
    }

    return endpoint;

}

int flb_read_file(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf = NULL;
    struct stat st;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ret = fstat(fd, &st);
    if (ret == -1) {
        flb_errno();
        close(fd);
        return -1;
    }

    buf = flb_calloc(st.st_size + 1, sizeof(char));
    if (!buf) {
        flb_errno();
        close(fd);
        return -1;
    }

    bytes = read(fd, buf, st.st_size);
    if (bytes < 0) {
        flb_errno();
        flb_free(buf);
        close(fd);
        return -1;
    }

    /* fread does not add null byte */
    buf[st.st_size] = '\0';

    close(fd);
    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}


char *removeProtocol (char *endpoint, char *protocol) {
    if (strncmp(protocol, endpoint, strlen(protocol)) == 0){
        endpoint = endpoint + strlen(protocol);
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

    c = request_do(aws_client, method, uri, body, body_len,
                   dynamic_headers, dynamic_headers_len);

    // Auto retry if request fails
    if (c == NULL && aws_client->retry_requests) {
        flb_debug("[aws_client] auto-retrying");
        c = request_do(aws_client, method, uri, body, body_len,
                       dynamic_headers, dynamic_headers_len);
    }

    /*
     * 400 or 403 could indicate an issue with credentials- so we check for auth
     * specific error messages and then force a refresh on the provider.
     * For safety a refresh can be performed only once
     * per FLB_AWS_CREDENTIAL_REFRESH_LIMIT.
     *
     */
    if (c && (c->resp.status >= 400 && c->resp.status < 500)) {
        if (aws_client->has_auth && time(NULL) > aws_client->refresh_limit) {
            if (flb_aws_is_auth_error(c->resp.payload, c->resp.payload_size)
                == FLB_TRUE) {
                flb_info("[aws_client] auth error, refreshing creds");
                aws_client->refresh_limit = time(NULL) + FLB_AWS_CREDENTIAL_REFRESH_LIMIT;
                aws_client->provider->provider_vtable->refresh(aws_client->provider);
            }
        }
    }

    return c;
}

/* always frees dynamic_headers */
struct flb_http_client *flb_aws_client_request_basic_auth(
                                               struct flb_aws_client *aws_client,
                                               int method, const char *uri,
                                               const char *body, size_t body_len,
                                               struct flb_aws_header *dynamic_headers,
                                               size_t dynamic_headers_len,
                                               char *header_name,
                                               char* auth_token)
{
    struct flb_http_client *c = NULL;
    struct flb_aws_header *auth_header = NULL;
    struct flb_aws_header *headers = NULL;

    auth_header = flb_calloc(1, sizeof(struct flb_aws_header));
    if (!auth_header) {
        flb_errno();
        return NULL;
    }

    auth_header->key = header_name;
    auth_header->key_len = strlen(header_name);
    auth_header->val = auth_token;
    auth_header->val_len = strlen(auth_token);

    if (dynamic_headers_len == 0) {
        c = aws_client->client_vtable->request(aws_client, method, uri, body, body_len,
                                               auth_header, 1);
    } else {
        headers = flb_realloc(dynamic_headers, (dynamic_headers_len + 1) * sizeof(struct flb_aws_header));
        if (!headers) {
            flb_free(auth_header);
            flb_errno();
            return NULL;
        }
        *(headers + dynamic_headers_len) = *auth_header;
        c = aws_client->client_vtable->request(aws_client, method, uri, body, body_len,
                                               headers, dynamic_headers_len + 1);
        flb_free(headers);
    }
    flb_free(auth_header);
    return c;
}

static struct flb_aws_client_vtable client_vtable = {
    .request = flb_aws_client_request,
};

struct flb_aws_client *flb_aws_client_create()
{
    struct flb_aws_client *client = flb_calloc(1, sizeof(struct flb_aws_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &client_vtable;
    client->retry_requests = FLB_FALSE;
    client->debug_only = FLB_FALSE;
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    client->http_cb_ctx = flb_callback_create("aws client");
    if (!client->http_cb_ctx) {
        flb_errno();
        flb_free(client);
        return NULL;
    }
#endif
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
        if (aws_client->extra_user_agent) {
            flb_sds_destroy(aws_client->extra_user_agent);
        }
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
        if (aws_client->http_cb_ctx) {
            flb_callback_destroy(aws_client->http_cb_ctx);
        }
#endif
        flb_free(aws_client);
    }
}

int flb_aws_is_auth_error(char *payload, size_t payload_size)
{
    flb_sds_t error = NULL;

    if (payload_size == 0) {
        return FLB_FALSE;
    }

    /* Fluent Bit calls the STS API which returns XML */
    if (strcasestr(payload, "InvalidClientTokenId") != NULL) {
        return FLB_TRUE;
    }

    if (strcasestr(payload, "AccessDenied") != NULL) {
        return FLB_TRUE;
    }

    if (strcasestr(payload, "Expired") != NULL) {
        return FLB_TRUE;
    }

    /* Most APIs we use return JSON */
    error = flb_aws_error(payload, payload_size);
    if (error != NULL) {
        if (strcmp(error, "ExpiredToken") == 0 ||
            strcmp(error, "ExpiredTokenException") == 0 ||
            strcmp(error, "AccessDeniedException") == 0 ||
            strcmp(error, "AccessDenied") == 0 ||
            strcmp(error, "IncompleteSignature") == 0 ||
            strcmp(error, "SignatureDoesNotMatch") == 0 ||
            strcmp(error, "MissingAuthenticationToken") == 0 ||
            strcmp(error, "InvalidClientTokenId") == 0 ||
            strcmp(error, "InvalidToken") == 0 ||
            strcmp(error, "InvalidAccessKeyId") == 0 ||
            strcmp(error, "UnrecognizedClientException") == 0) {
                flb_sds_destroy(error);
            return FLB_TRUE;
        }
        flb_sds_destroy(error);
    }

    return FLB_FALSE;
}

struct flb_http_client *request_do(struct flb_aws_client *aws_client,
                                   int method, const char *uri,
                                   const char *body, size_t body_len,
                                   struct flb_aws_header *dynamic_headers,
                                   size_t dynamic_headers_len)
{
    size_t b_sent;
    int ret;
    struct flb_connection *u_conn = NULL;
    flb_sds_t signature = NULL;
    int i;
    int normalize_uri;
    struct flb_aws_header header;
    struct flb_http_client *c = NULL;
    flb_sds_t tmp;
    flb_sds_t user_agent_prefix;
    flb_sds_t user_agent = NULL;
    char *buf;
    struct flb_env *env;

    u_conn = flb_upstream_conn_get(aws_client->upstream);
    if (!u_conn) {
        if (aws_client->debug_only == FLB_TRUE) {
            flb_debug("[aws_client] connection initialization error");
        }
        else {
            flb_error("[aws_client] connection initialization error");
        }
        return NULL;
    }

    /* Compose HTTP request */
    c = flb_http_client(u_conn, method, uri,
                        body, body_len,
                        aws_client->host, aws_client->port,
                        aws_client->proxy, aws_client->flags);

    if (!c) {
        if (aws_client->debug_only == FLB_TRUE) {
            flb_debug("[aws_client] could not initialize request");
        }
        else {
            flb_error("[aws_client] could not initialize request");
        }
        goto error;
    }

#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    flb_http_client_debug_enable(c, aws_client->http_cb_ctx);
#endif

    /* Increase the maximum HTTP response buffer size to fit large responses from AWS services */
    ret = flb_http_buffer_size(c, FLB_MAX_AWS_RESP_BUFFER_SIZE);
    if (ret != 0) {
        flb_warn("[aws_http_client] failed to increase max response buffer size");
    }

    /* Set AWS Fluent Bit user agent */
    env = aws_client->upstream->base.config->env;
    buf = (char *) flb_env_get(env, "FLB_AWS_USER_AGENT");
    if (buf == NULL) {
        if (getenv(AWS_ECS_METADATA_URI) != NULL) {
            user_agent = AWS_USER_AGENT_ECS;
        }
        else {
            buf = (char *) flb_env_get(env, AWS_USER_AGENT_K8S);
            if (buf && strcasecmp(buf, "enabled") == 0) {
                user_agent = AWS_USER_AGENT_K8S;
            }
        }

        if (user_agent == NULL) {
            user_agent = AWS_USER_AGENT_NONE;
        }

        flb_env_set(env, "FLB_AWS_USER_AGENT", user_agent);
    }
    if (aws_client->extra_user_agent == NULL) {
        buf = (char *) flb_env_get(env, "FLB_AWS_USER_AGENT");
        tmp = flb_sds_create(buf);
        if (!tmp) {
            flb_errno();
            goto error;
        }
        aws_client->extra_user_agent = tmp;
        tmp = NULL;
    }

    /* Add AWS Fluent Bit user agent header */
    if (strcasecmp(aws_client->extra_user_agent, AWS_USER_AGENT_NONE) == 0) {
        ret = flb_http_add_header(c, "User-Agent", 10,
                                  FLB_AWS_BASE_USER_AGENT, FLB_AWS_BASE_USER_AGENT_LEN);
    }
    else {
        user_agent_prefix = flb_sds_create_size(64);
        if (!user_agent_prefix) {
            flb_errno();
            flb_error("[aws_client] failed to create user agent");
            goto error;
        }
        tmp = flb_sds_printf(&user_agent_prefix, FLB_AWS_BASE_USER_AGENT_FORMAT,
                             aws_client->extra_user_agent);
        if (!tmp) {
            flb_errno();
            flb_sds_destroy(user_agent_prefix);
            flb_error("[aws_client] failed to create user agent");
            goto error;
        }
        user_agent_prefix = tmp;

        ret = flb_http_add_header(c, "User-Agent", 10, user_agent_prefix,
                                  flb_sds_len(user_agent_prefix));
        flb_sds_destroy(user_agent_prefix);
    }

    if (ret < 0) {
        if (aws_client->debug_only == FLB_TRUE) {
            flb_debug("[aws_client] failed to add header to request");
        }
        else {
            flb_error("[aws_client] failed to add header to request");
        }
        goto error;
    }

    /* add headers */
    for (i = 0; i < aws_client->static_headers_len; i++) {
        header = aws_client->static_headers[i];
        ret =  flb_http_add_header(c,
                                   header.key, header.key_len,
                                   header.val, header.val_len);
        if (ret < 0) {
            if (aws_client->debug_only == FLB_TRUE) {
                flb_debug("[aws_client] failed to add header to request");
            }
            else {
                flb_error("[aws_client] failed to add header to request");
            }
            goto error;
        }
    }

    for (i = 0; i < dynamic_headers_len; i++) {
        header = dynamic_headers[i];
        ret =  flb_http_add_header(c,
                                   header.key, header.key_len,
                                   header.val, header.val_len);
        if (ret < 0) {
            if (aws_client->debug_only == FLB_TRUE) {
                flb_debug("[aws_client] failed to add header to request");
            }
            else {
                flb_error("[aws_client] failed to add header to request");
            }
            goto error;
        }
    }

    if (aws_client->has_auth) {
        if (aws_client->s3_mode == S3_MODE_NONE) {
            normalize_uri = FLB_TRUE;
        }
        else {
            normalize_uri = FLB_FALSE;
        }
        signature = flb_signv4_do(c, normalize_uri, FLB_TRUE, time(NULL),
                                  aws_client->region, aws_client->service,
                                  aws_client->s3_mode, NULL,
                                  aws_client->provider);
        if (!signature) {
            if (aws_client->debug_only == FLB_TRUE) {
                flb_debug("[aws_client] could not sign request");
            }
            else {
                flb_error("[aws_client] could not sign request");
            }
            goto error;
        }
    }

    /* Perform request */
    ret = flb_http_do(c, &b_sent);

    if (ret != 0 || c->resp.status != 200) {
        flb_debug("[aws_client] %s: http_do=%i, HTTP Status: %i",
                  aws_client->host, ret, c->resp.status);
    }

    if (ret != 0 && c != NULL) {
        flb_http_client_destroy(c);
        c = NULL;
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

void flb_aws_print_xml_error(char *response, size_t response_len,
                             char *api, struct flb_output_instance *ins)
{
    flb_sds_t error;
    flb_sds_t message;

    error = flb_aws_xml_get_val(response, response_len, "<Code>", "</Code>");
    if (!error) {
        flb_plg_error(ins, "%s: Could not parse response", api);
        return;
    }

    message = flb_aws_xml_get_val(response, response_len, "<Message>", "</Message>");
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

/* Parses AWS XML API Error responses and returns the value of the <code> tag */
flb_sds_t flb_aws_xml_error(char *response, size_t response_len)
{
    return flb_aws_xml_get_val(response, response_len, "<Code>", "</Code>");
}

/*
 * Parses an XML document and returns the value of the given tag
 * Param `tag` should include angle brackets; ex "<code>"
 * And param `end` should include end brackets: "</code>"
 */
flb_sds_t flb_aws_xml_get_val(char *response, size_t response_len, char *tag, char *tag_end)
{
    flb_sds_t val = NULL;
    char *node = NULL;
    char *end;
    int len;

    if (response_len == 0) {
        return NULL;
    }
    node = strstr(response, tag);
    if (!node) {
        flb_debug("[aws] Could not find '%s' tag in API response", tag);
        return NULL;
    }

    /* advance to end of tag */
    node += strlen(tag);

    end = strstr(node, tag_end);
    if (!end) {
        flb_error("[aws] Could not find end of '%s' node in xml", tag);
        return NULL;
    }
    len = end - node;
    val = flb_sds_create_len(node, len);
    if (!val) {
        flb_errno();
        return NULL;
    }

    return val;
}

/*
 * Error parsing for json APIs that respond with an
 * __type and message fields for error responses.
 */
void flb_aws_print_error(char *response, size_t response_len,
                              char *api, struct flb_output_instance *ins)
{
    flb_sds_t error;
    flb_sds_t message;

    error = flb_json_get_val(response, response_len, "__type");
    if (!error) {
        /* error can not be parsed, print raw response */
        flb_plg_warn(ins, "%s: Raw response: %s", api, response);
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

/*
 * Error parsing for json APIs that respond with a
 * Code and Message fields for error responses.
 */
void flb_aws_print_error_code(char *response, size_t response_len,
                              char *api)
{
    flb_sds_t error;
    flb_sds_t message;

    error = flb_json_get_val(response, response_len, "Code");
    if (!error) {
        /* error can not be parsed, print raw response */
        flb_warn("%s: Raw response: %s", api, response);
        return;
    }

    message = flb_json_get_val(response, response_len, "Message");
    if (!message) {
        /* just print the error */
        flb_error("%s API responded with code='%s'", api, error);
    }
    else {
        flb_error("%s API responded with code='%s', message='%s'",
                      api, error, message);
        flb_sds_destroy(message);
    }

    flb_sds_destroy(error);
}

/* parses AWS JSON API error responses and returns the value of the __type field */
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
    int tokens_size = 50;
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
                  " valid JSON.");
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

/* Generic replace function for strings. */
static char* replace_uri_tokens(const char* original_string, const char* current_word,
                         const char* new_word)
{
    char *result;
    int i = 0;
    int count = 0;
    int new_word_len = strlen(new_word);
    int old_word_len = strlen(current_word);

    for (i = 0; original_string[i] != '\0'; i++) {
        if (strstr(&original_string[i], current_word) == &original_string[i]) {
            count++;
            i += old_word_len - 1;
        }
    }

    result = flb_sds_create_size(i + count * (new_word_len - old_word_len) + 1);
    if (!result) {
        flb_errno();
        return NULL;
    }

    i = 0;
    while (*original_string) {
        if (strstr(original_string, current_word) == original_string) {
            strncpy(&result[i], new_word, new_word_len);
            i += new_word_len;
            original_string += old_word_len;
        }
        else
            result[i++] = *original_string++;
    }

    result[i] = '\0';
    return result;
}

/*
 * Linux has strtok_r as the concurrent safe version
 * Windows has strtok_s
 */
char* strtok_concurrent(
    char* str,
    char* delimiters,
    char** context
)
{
#ifdef FLB_SYSTEM_WINDOWS
    return strtok_s(str, delimiters, context);
#else
    return strtok_r(str, delimiters, context);
#endif
}

/* Constructs S3 object key as per the blob format. */
flb_sds_t flb_get_s3_blob_key(const char *format,
                              const char *tag,
                              char *tag_delimiter,
                              const char *blob_path)
{
    int i = 0;
    int ret = 0;
    char *tag_token = NULL;
    char *random_alphanumeric;
    /* concurrent safe strtok_r requires a tracking ptr */
    char *strtok_saveptr;
    flb_sds_t tmp = NULL;
    flb_sds_t buf = NULL;
    flb_sds_t s3_key = NULL;
    flb_sds_t tmp_key = NULL;
    flb_sds_t tmp_tag = NULL;
    flb_sds_t sds_result = NULL;
    char *valid_blob_path = NULL;

    if (strlen(format) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    tmp_tag = flb_sds_create_len(tag, strlen(tag));
    if(!tmp_tag){
        goto error;
    }

    s3_key = flb_sds_create_len(format, strlen(format));
    if (!s3_key) {
        goto error;
    }

    /* Check if delimiter(s) specifed exists in the tag. */
    for (i = 0; i < strlen(tag_delimiter); i++){
        if (strchr(tag, tag_delimiter[i])){
            ret = 1;
            break;
        }
    }

    tmp = flb_sds_create_len(TAG_PART_DESCRIPTOR, 5);
    if (!tmp) {
        goto error;
    }
    if (strstr(s3_key, tmp)){
        if(ret == 0){
            flb_warn("[s3_key] Invalid Tag delimiter: does not exist in tag. "
                    "tag=%s, format=%s", tag, format);
        }
    }

    flb_sds_destroy(tmp);
    tmp = NULL;

    /* Split the string on the delimiters */
    tag_token = strtok_concurrent(tmp_tag, tag_delimiter, &strtok_saveptr);

    /* Find all occurences of $TAG[*] and
     * replaces it with the right token from tag.
     */
    i = 0;
    while(tag_token != NULL && i < MAX_TAG_PARTS) {
        buf = flb_sds_create_size(10);
        if (!buf) {
            goto error;
        }
        tmp = flb_sds_printf(&buf, TAG_PART_DESCRIPTOR, i);
        if (!tmp) {
            goto error;
        }

        tmp_key = replace_uri_tokens(s3_key, tmp, tag_token);
        if (!tmp_key) {
            goto error;
        }

        if(strlen(tmp_key) > S3_KEY_SIZE){
            flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
        }

        if (buf != tmp) {
            flb_sds_destroy(buf);
        }
        flb_sds_destroy(tmp);
        tmp = NULL;
        buf = NULL;
        flb_sds_destroy(s3_key);
        s3_key = tmp_key;
        tmp_key = NULL;

        tag_token = strtok_concurrent(NULL, tag_delimiter, &strtok_saveptr);
        i++;
    }

    tmp = flb_sds_create_len(TAG_PART_DESCRIPTOR, 5);
    if (!tmp) {
        goto error;
    }

    /* A match against "$TAG[" indicates an invalid or out of bounds tag part. */
    if (strstr(s3_key, tmp)){
        flb_warn("[s3_key] Invalid / Out of bounds tag part: At most 10 tag parts "
                 "($TAG[0] - $TAG[9]) can be processed. tag=%s, format=%s, delimiters=%s",
                 tag, format, tag_delimiter);
    }

    /* Find all occurences of $TAG and replace with the entire tag. */
    tmp_key = replace_uri_tokens(s3_key, TAG_DESCRIPTOR, tag);
    if (!tmp_key) {
        goto error;
    }

    if(strlen(tmp_key) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    flb_sds_destroy(s3_key);
    s3_key = tmp_key;
    tmp_key = NULL;

    flb_sds_len_set(s3_key, strlen(s3_key));

    valid_blob_path = (char *) blob_path;

    while (*valid_blob_path == '.' ||
           *valid_blob_path == '/') {
            valid_blob_path++;
    }

    /* Append the blob path. */
    sds_result = flb_sds_cat(s3_key, valid_blob_path, strlen(valid_blob_path));

    if (!sds_result) {
        goto error;
    }

    s3_key = sds_result;

    if(strlen(s3_key) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    /* Find all occurences of $UUID and replace with a random string. */
    random_alphanumeric = flb_sts_session_name();
    if (!random_alphanumeric) {
        goto error;
    }
    /* only use 8 chars of the random string */
    random_alphanumeric[8] = '\0';
    tmp_key = replace_uri_tokens(s3_key, RANDOM_STRING, random_alphanumeric);
    if (!tmp_key) {
        flb_free(random_alphanumeric);
        goto error;
    }

    if(strlen(tmp_key) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    flb_sds_destroy(s3_key);
    s3_key = tmp_key;
    tmp_key = NULL;

    flb_free(random_alphanumeric);

    flb_sds_destroy(tmp);
    tmp = NULL;

    flb_sds_destroy(tmp_tag);
    tmp_tag = NULL;

    return s3_key;

    error:
        flb_errno();

        if (tmp_tag){
            flb_sds_destroy(tmp_tag);
        }

        if (s3_key){
            flb_sds_destroy(s3_key);
        }

        if (buf && buf != tmp){
            flb_sds_destroy(buf);
        }

        if (tmp){
            flb_sds_destroy(tmp);
        }

        return NULL;
}

/* Constructs S3 object key as per the format. */
flb_sds_t flb_get_s3_key(const char *format, time_t time, const char *tag,
                         char *tag_delimiter, uint64_t seq_index)
{
    int i = 0;
    int ret = 0;
    int seq_index_len;
    char *tag_token = NULL;
    char *key;
    char *random_alphanumeric;
    char *seq_index_str;
    /* concurrent safe strtok_r requires a tracking ptr */
    char *strtok_saveptr;
    int len;
    flb_sds_t tmp = NULL;
    flb_sds_t buf = NULL;
    flb_sds_t s3_key = NULL;
    flb_sds_t tmp_key = NULL;
    flb_sds_t tmp_tag = NULL;
    struct tm gmt = {0};

    if (strlen(format) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    tmp_tag = flb_sds_create_len(tag, strlen(tag));
    if(!tmp_tag){
        goto error;
    }

    s3_key = flb_sds_create_len(format, strlen(format));
    if (!s3_key) {
        goto error;
    }

    /* Check if delimiter(s) specifed exists in the tag. */
    for (i = 0; i < strlen(tag_delimiter); i++){
        if (strchr(tag, tag_delimiter[i])){
            ret = 1;
            break;
        }
    }

    tmp = flb_sds_create_len(TAG_PART_DESCRIPTOR, 5);
    if (!tmp) {
        goto error;
    }
    if (strstr(s3_key, tmp)){
        if(ret == 0){
            flb_warn("[s3_key] Invalid Tag delimiter: does not exist in tag. "
                    "tag=%s, format=%s", tag, format);
        }
    }

    flb_sds_destroy(tmp);
    tmp = NULL;

    /* Split the string on the delimiters */
    tag_token = strtok_concurrent(tmp_tag, tag_delimiter, &strtok_saveptr);

    /* Find all occurences of $TAG[*] and
     * replaces it with the right token from tag.
     */
    i = 0;
    while(tag_token != NULL && i < MAX_TAG_PARTS) {
        buf = flb_sds_create_size(10);
        if (!buf) {
            goto error;
        }
        tmp = flb_sds_printf(&buf, TAG_PART_DESCRIPTOR, i);
        if (!tmp) {
            goto error;
        }

        tmp_key = replace_uri_tokens(s3_key, tmp, tag_token);
        if (!tmp_key) {
            goto error;
        }

        if(strlen(tmp_key) > S3_KEY_SIZE){
            flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
        }

        if (buf != tmp) {
            flb_sds_destroy(buf);
        }
        flb_sds_destroy(tmp);
        tmp = NULL;
        buf = NULL;
        flb_sds_destroy(s3_key);
        s3_key = tmp_key;
        tmp_key = NULL;

        tag_token = strtok_concurrent(NULL, tag_delimiter, &strtok_saveptr);
        i++;
    }

    tmp = flb_sds_create_len(TAG_PART_DESCRIPTOR, 5);
    if (!tmp) {
        goto error;
    }

    /* A match against "$TAG[" indicates an invalid or out of bounds tag part. */
    if (strstr(s3_key, tmp)){
        flb_warn("[s3_key] Invalid / Out of bounds tag part: At most 10 tag parts "
                 "($TAG[0] - $TAG[9]) can be processed. tag=%s, format=%s, delimiters=%s",
                 tag, format, tag_delimiter);
    }

    /* Find all occurences of $TAG and replace with the entire tag. */
    tmp_key = replace_uri_tokens(s3_key, TAG_DESCRIPTOR, tag);
    if (!tmp_key) {
        goto error;
    }

    if(strlen(tmp_key) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    flb_sds_destroy(s3_key);
    s3_key = tmp_key;
    tmp_key = NULL;

    /* Find all occurences of $INDEX and replace with the appropriate index. */
    if (strstr((char *) format, INDEX_STRING)) {
        seq_index_len = snprintf(NULL, 0, "%"PRIu64, seq_index);
        seq_index_str = flb_calloc(seq_index_len + 1, sizeof(char));
        if (seq_index_str == NULL) {
            goto error;
        }

        sprintf(seq_index_str, "%"PRIu64, seq_index);
        seq_index_str[seq_index_len] = '\0';
        tmp_key = replace_uri_tokens(s3_key, INDEX_STRING, seq_index_str);
        if (tmp_key == NULL) {
            flb_free(seq_index_str);
            goto error;
        }
        if (strlen(tmp_key) > S3_KEY_SIZE) {
            flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
        }

        flb_sds_destroy(s3_key);
        s3_key = tmp_key;
        tmp_key = NULL;
        flb_free(seq_index_str);
    }

    /* Find all occurences of $UUID and replace with a random string. */
    random_alphanumeric = flb_sts_session_name();
    if (!random_alphanumeric) {
        goto error;
    }
    /* only use 8 chars of the random string */
    random_alphanumeric[8] = '\0';
    tmp_key = replace_uri_tokens(s3_key, RANDOM_STRING, random_alphanumeric);
    if (!tmp_key) {
        flb_free(random_alphanumeric);
        goto error;
    }

    if(strlen(tmp_key) > S3_KEY_SIZE){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    flb_sds_destroy(s3_key);
    s3_key = tmp_key;
    tmp_key = NULL;
    flb_free(random_alphanumeric);

    if (!gmtime_r(&time, &gmt)) {
        flb_error("[s3_key] Failed to create timestamp.");
        goto error;
    }

    flb_sds_destroy(tmp);
    tmp = NULL;

    /* A string no longer than S3_KEY_SIZE + 1 is created to store the formatted timestamp. */
    key = flb_calloc(1, (S3_KEY_SIZE + 1) * sizeof(char));
    if (!key) {
        goto error;
    }

    ret = strftime(key, S3_KEY_SIZE, s3_key, &gmt);
    if(ret == 0){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }
    flb_sds_destroy(s3_key);

    len = strlen(key);
    if (len > S3_KEY_SIZE) {
        len = S3_KEY_SIZE;
    }

    s3_key = flb_sds_create_len(key, len);
    flb_free(key);
    if (!s3_key) {
        goto error;
    }

    flb_sds_destroy(tmp_tag);
    tmp_tag = NULL;
    return s3_key;

    error:
        flb_errno();
        if (tmp_tag){
            flb_sds_destroy(tmp_tag);
        }
        if (s3_key){
            flb_sds_destroy(s3_key);
        }
        if (buf && buf != tmp){
            flb_sds_destroy(buf);
        }
        if (tmp){
            flb_sds_destroy(tmp);
        }
        if (tmp_key){
            flb_sds_destroy(tmp_key);
        }
        return NULL;
}

/*
 * This function is an extension to strftime which can support milliseconds with %3N,
 * support nanoseconds with %9N or %L. The return value is the length of formatted
 * time string.
 */
size_t flb_aws_strftime_precision(char **out_buf, const char *time_format,
                                  struct flb_time *tms)
{
    char millisecond_str[FLB_AWS_MILLISECOND_FORMATTER_LENGTH+1];
    char nanosecond_str[FLB_AWS_NANOSECOND_FORMATTER_LENGTH+1];
    char *tmp_parsed_time_str;
    char *buf;
    size_t out_size;
    size_t tmp_parsed_time_str_len;
    size_t time_format_len;
    struct tm timestamp;
    struct tm *tmp;
    int i;

    /*
     * Guess the max length needed for tmp_parsed_time_str and tmp_out_buf. The
     * upper bound is 12*strlen(time_format) because the worst scenario will be only
     * %c in time_format, and %c will be transfer to 24 chars long by function strftime().
     */
    time_format_len = strlen(time_format);
    tmp_parsed_time_str_len = 12*time_format_len;

    /*
     * Use tmp_parsed_time_str to buffer when replace %3N with milliseconds, replace
     * %9N and %L with nanoseconds in time_format.
     */
    tmp_parsed_time_str = (char *)flb_calloc(1, tmp_parsed_time_str_len*sizeof(char));
    if (!tmp_parsed_time_str) {
        flb_errno();
        return 0;
    }

    buf = (char *)flb_calloc(1, tmp_parsed_time_str_len*sizeof(char));
    if (!buf) {
        flb_errno();
        flb_free(tmp_parsed_time_str);
        return 0;
    }

    /* Replace %3N to millisecond, %9N and %L to nanosecond in time_format. */
    snprintf(millisecond_str, FLB_AWS_MILLISECOND_FORMATTER_LENGTH+1,
             "%03" PRIu64, (uint64_t) tms->tm.tv_nsec / 1000000);
    snprintf(nanosecond_str, FLB_AWS_NANOSECOND_FORMATTER_LENGTH+1,
             "%09" PRIu64, (uint64_t) tms->tm.tv_nsec);
    for (i = 0; i < time_format_len; i++) {
        if (strncmp(time_format+i, FLB_AWS_MILLISECOND_FORMATTER, 3) == 0) {
            strncat(tmp_parsed_time_str, millisecond_str,
                    FLB_AWS_MILLISECOND_FORMATTER_LENGTH+1);
            i += 2;
        }
        else if (strncmp(time_format+i, FLB_AWS_NANOSECOND_FORMATTER_N, 3) == 0) {
            strncat(tmp_parsed_time_str, nanosecond_str,
                    FLB_AWS_NANOSECOND_FORMATTER_LENGTH+1);
            i += 2;
        }
        else if (strncmp(time_format+i, FLB_AWS_NANOSECOND_FORMATTER_L, 2) == 0) {
            strncat(tmp_parsed_time_str, nanosecond_str,
                    FLB_AWS_NANOSECOND_FORMATTER_LENGTH+1);
            i += 1;
        }
        else {
            strncat(tmp_parsed_time_str,time_format+i,1);
        }
    }

    tmp = gmtime_r(&tms->tm.tv_sec, &timestamp);
    if (!tmp) {
        flb_free(tmp_parsed_time_str);
        flb_free(buf);
        return 0;
    }

    out_size = strftime(buf, tmp_parsed_time_str_len,
                        tmp_parsed_time_str, &timestamp);

    /* Check whether tmp_parsed_time_str_len is enough for tmp_out_buff */
    if (out_size == 0) {
        flb_free(tmp_parsed_time_str);
        flb_free(buf);
        return 0;
    }

    *out_buf = buf;
    flb_free(tmp_parsed_time_str);

    return out_size;
}
