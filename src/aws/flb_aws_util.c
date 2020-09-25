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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define AWS_SERVICE_ENDPOINT_FORMAT            "%s.%s.amazonaws.com"
#define AWS_SERVICE_ENDPOINT_BASE_LEN          15

#define S3_SERVICE_GLOBAL_ENDPOINT_FORMAT             "%s.s3.amazonaws.com"
#define S3_SERVICE_GLOBAL_ENDPOINT_BASE_LEN           17

#define S3_SERVICE_ENDPOINT_FORMAT             "%s.s3.%s.amazonaws.com"
#define S3_SERVICE_ENDPOINT_BASE_LEN           18

#define TAG_PART_DESCRIPTOR "$TAG[%d]"
#define TAG_DESCRIPTOR "$TAG"
#define MAX_TAG_PARTS 10
#define S3_KEY_SIZE 1024

#define TAG_PART_DESCRIPTOR "$TAG[%d]"
#define TAG_DESCRIPTOR "$TAG"
#define MAX_TAG_PARTS 10
#define S3_KEY_SIZE 1024

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
    int bytes;


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
    len++; /* null byte */

    endpoint = flb_malloc(len);
    if (!endpoint) {
        flb_errno();
        return NULL;
    }

    bytes = snprintf(endpoint, len, AWS_SERVICE_ENDPOINT_FORMAT, service, region);
    if (bytes < 0) {
        flb_errno();
        flb_free(endpoint);
        return NULL;
    }

    if (is_cn) {
        memcpy(endpoint + bytes, ".cn", 3);
        endpoint[bytes + 3] = '\0';
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

    buf = flb_malloc(st.st_size + sizeof(char));
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

/*
 * https://bucket.s3.amazonaws.com(.cn)
 */
char *flb_s3_endpoint(char* bucket, char* region)
{
    char *endpoint = NULL;
    size_t len = 0;
    int is_cn = FLB_FALSE;
    int bytes;

    if (strcmp("us-east-1", region) == 0) {
        len = S3_SERVICE_GLOBAL_ENDPOINT_BASE_LEN;
    }
    else {
        len = S3_SERVICE_ENDPOINT_BASE_LEN;
        len += strlen(region);
    }


    /* In the China regions, ".cn" is appended to the URL */
    if (strcmp("cn-north-1", region) == 0) {
        len += 3;
        is_cn = FLB_TRUE;
    }
    if (strcmp("cn-northwest-1", region) == 0) {
        len += 3;
        is_cn = FLB_TRUE;
    }

    len += strlen(bucket);
    len++; /* null byte */

    endpoint = flb_malloc(len);
    if (!endpoint) {
        flb_errno();
        return NULL;
    }

    if (strcmp("us-east-1", region) == 0) {
        bytes = snprintf(endpoint, len, S3_SERVICE_GLOBAL_ENDPOINT_FORMAT, bucket);
    }
    else {
        bytes = snprintf(endpoint, len, S3_SERVICE_ENDPOINT_FORMAT, bucket, region);
    }

    if (bytes < 0) {
        flb_errno();
        flb_free(endpoint);
        return NULL;
    }

    if (is_cn) {
        memcpy(endpoint + bytes, ".cn", 3);
        endpoint[bytes + 3] = '\0';
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
        if (aws_client->has_auth && time(NULL) > aws_client->refresh_limit) {
            if (flb_aws_is_auth_error(c->resp.payload, c->resp.payload_size)
                == FLB_TRUE) {
                aws_client->refresh_limit = time(NULL)
                                            + FLB_AWS_CREDENTIAL_REFRESH_LIMIT;
                aws_client->provider->provider_vtable->
                                          refresh(aws_client->provider);
            }
        }
    }

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
    client->debug_only = FLB_FALSE;
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

    /* Most APIs we use return JSON */
    error = flb_aws_error(payload, payload_size);
    if (error != NULL) {
        if (strcmp(error, "ExpiredToken") == 0 ||
            strcmp(error, "AccessDeniedException") == 0 ||
            strcmp(error, "IncompleteSignature") == 0 ||
            strcmp(error, "MissingAuthenticationToken") == 0 ||
            strcmp(error, "InvalidClientTokenId") == 0 ||
            strcmp(error, "UnrecognizedClientException") == 0) {
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
    struct flb_upstream_conn *u_conn = NULL;
    flb_sds_t signature = NULL;
    int i;
    int normalize_uri;
    struct flb_aws_header header;
    struct flb_http_client *c = NULL;

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

    /* Add AWS Fluent Bit user agent */
    ret = flb_http_add_header(c, "User-Agent", 10,
                              "aws-fluent-bit-plugin", 21);
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
                                  aws_client->s3_mode,
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

    error = flb_xml_get_val(response, response_len, "<Code>");
    if (!error) {
        flb_plg_error(ins, "%s: Could not parse response", api);
        return;
    }

    message = flb_xml_get_val(response, response_len, "<Message>");
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
    return flb_xml_get_val(response, response_len, "<code>");
}

/*
 * Parses an XML document and returns the value of the given tag
 * Param `tag` should include angle brackets; ex "<code>"
 */
flb_sds_t flb_xml_get_val(char *response, size_t response_len, char *tag)
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

    end = strchr(node, '<');
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
            flb_http_client_destroy(c);
            return -1;
        }
        *metadata = ec2_metadata;
        *metadata_len = c->resp.payload_size;

        flb_http_client_destroy(c);
        return 0;
    }

    flb_debug("[ecs_imds] IMDS metadata response was empty");
    flb_http_client_destroy(c);
    return -1;

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
            strcpy(&result[i], new_word);
            i += new_word_len;
            original_string += old_word_len;
        }
        else
            result[i++] = *original_string++;
    }

    result[i] = '\0';
    return result;
}

/* Constructs S3 object key as per the format. */
flb_sds_t flb_get_s3_key(const char *format, time_t time, const char *tag, char *tag_delimiter)
{
    int i = 0;
    int ret = 0;
    char *tag_token = NULL;
    flb_sds_t tmp = NULL;
    flb_sds_t buf = NULL;
    flb_sds_t s3_key = NULL;
    flb_sds_t tmp_key = NULL;
    flb_sds_t tmp_tag = NULL;
    struct tm *gmt = NULL;

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

    /* Split the string on the delimiters */
    tag_token = strtok(tmp_tag, tag_delimiter);

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

        flb_sds_destroy(tmp);
        flb_sds_destroy(s3_key);
        s3_key = tmp_key;

        tag_token = strtok(NULL, tag_delimiter);
        i++;
    }

    tmp = flb_sds_create_len(TAG_PART_DESCRIPTOR, 5);
    if (!tmp) {
        goto error;
    }

    /* A match against "$TAG[" indicates an invalid or out of bounds tag part. */
    if (strstr(s3_key, tmp)){
        flb_warn("[s3_key] Invalid / Out of bounds tag part: At most 10 tag parts "
                 "($TAG[0] - $TAG[9]) can be processed. tag=%s, format=%s", tag, format);
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

    gmt = gmtime(&time);

    flb_sds_destroy(tmp);

    /* A string longer than S3_KEY_SIZE is created to store the formatted timestamp. */
    tmp = flb_sds_create_size(S3_KEY_SIZE);
    if (!tmp) {
        goto error;
    }

    ret = strftime(tmp, S3_KEY_SIZE, s3_key, gmt);
    if(ret == 0){
        flb_warn("[s3_key] Object key length is longer than the 1024 character limit.");
    }

    flb_sds_destroy(s3_key);
    s3_key = tmp;
    FLB_SDS_HEADER(s3_key)->len = strlen(s3_key);

    flb_sds_destroy(tmp_tag);
    return s3_key;

    error:
        flb_errno();
        if (tmp_tag){
            flb_sds_destroy(tmp_tag);
        }
        if (s3_key){
            flb_sds_destroy(s3_key);
        }
        if (buf){
            flb_sds_destroy(buf);
        }
        if (tmp){
            flb_sds_destroy(tmp);
        }
        if (tmp_key){
            flb_sds_destroy(tmp_key);
        }
        if (tag_token){
            flb_free(tag_token);
        }
        return NULL;
}
