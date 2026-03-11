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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include <ctype.h>

#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include "http.h"

#define HTTP_CONTENT_JSON       0
#define HTTP_CONTENT_URLENCODED 1

static int http_header_lookup(struct flb_http_request *request, char *key,
                              char **val, size_t *val_len);
static int process_pack_ng(struct flb_http *ctx, flb_sds_t tag,
                           char *buf, size_t size, void *request);

static int content_type_is_json(const char *content_type)
{
    size_t length;

    if (content_type == NULL) {
        return FLB_FALSE;
    }

    length = strlen(content_type);

    if (length == 16 &&
        strncasecmp(content_type, "application/json", 16) == 0) {
        return FLB_TRUE;
    }

    if (length > 16 &&
        (strncasecmp(content_type, "application/json;", 17) == 0 ||
         strncasecmp(content_type, "application/json ", 17) == 0)) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int content_type_is_urlencoded(const char *content_type)
{
    if (content_type == NULL) {
        return FLB_FALSE;
    }

    return strcasecmp(content_type,
                      "application/x-www-form-urlencoded") == 0;
}

static inline char hex2nibble(char c)
{
    if ((c >= 0x30) && (c <= '9')) {
        return c - 0x30;
    }

    /* 0x30-0x39 are digits, 0x41-0x46 A-F, so there is a gap at 0x40 */
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A') + 10;
    }
    if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a') + 10;
    }
    return 0;
}

static int sds_uri_decode(flb_sds_t s)
{
    char buf[1024];
    char *optr;
    char *iptr;


    for (optr = buf, iptr = s; iptr < s + flb_sds_len(s) && optr-buf < sizeof(buf); iptr++) {
        if (*iptr == '%') {
            if (iptr + 2 >= (s + flb_sds_len(s))) {
                return -1;
            }
            if (!isxdigit((unsigned char) *(iptr + 1)) ||
                !isxdigit((unsigned char) *(iptr + 2))) {
                return -1;
            }
            *optr++ = hex2nibble(*(iptr+1)) << 4 | hex2nibble(*(iptr+2));
            iptr+=2;
        }
        else if (*iptr == '+') {
            *optr++ = ' ';
        }
        else {
            *optr++ = *iptr;
        }
    }

    memcpy(s, buf, optr-buf);
    s[optr-buf] = '\0';
    flb_sds_len_set(s, (optr-buf));

    return 0;
}

static void sanitize_tag(flb_sds_t tag)
{
    size_t i;

    if (!tag) {
        return;
    }

    for (i = 0; i < flb_sds_len(tag); i++) {
        if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
            tag[i] = '_';
        }
    }
}

/* implements functionality to get tag from key in record */
static flb_sds_t tag_key(struct flb_http *ctx, msgpack_object *map)
{
    struct flb_ra_value *ra_val;
    flb_sds_t tag = NULL;

    /* If no record accessor is configured, return NULL */
    if (!ctx->ra_tag_key) {
        return NULL;
    }

    /* Use record accessor to get the value */
    ra_val = flb_ra_get_value_object(ctx->ra_tag_key, *map);
    if (!ra_val) {
        flb_plg_debug(ctx->ins, "Could not find tag_key %s in record", ctx->tag_key);
        return NULL;
    }

    /* Convert the value to string */
    if (ra_val->type == FLB_RA_STRING) {
        tag = flb_sds_create_len(ra_val->o.via.str.ptr, ra_val->o.via.str.size);
        if (tag) {
            sanitize_tag(tag);
        }
    }
    else {
        flb_plg_debug(ctx->ins, "tag_key %s value is not a string", ctx->tag_key);
    }

    /* Clean up the record accessor value */
    flb_ra_key_value_destroy(ra_val);

    return tag;
}

/* Extract the client IP address from the X-Forwarded-For header */
static flb_sds_t get_remote_addr(struct flb_http_request *request)
{
    int ret;
    char *ptr = NULL;
    size_t len = 0;
    flb_sds_t remote_addr;

    ret = http_header_lookup(request,
                             "X-Forwarded-For",
                             &ptr, &len);

    if (ret != 0) {
        return NULL;
    }

    remote_addr = flb_sds_create_len(ptr, len);
    if (!remote_addr) {
        return NULL;
    }

    ptr = strchr(remote_addr, ',');
    if (ptr) {
        *ptr = '\0';
        flb_sds_len_set(remote_addr, ptr - remote_addr);
    }

    /* need to trim spaces due to mk_http_header */
    if (flb_sds_trim(remote_addr) <= 0) {
         flb_sds_destroy(remote_addr);
         return NULL;
    }

    return remote_addr;
}

static int append_remote_addr(
    msgpack_object *obj,
    msgpack_unpacked *unpck,
    msgpack_sbuffer *sbuf,
    struct flb_http *ctx,
    char *remote_addr)
{
    msgpack_object *key;
    msgpack_packer pck;
    size_t off = 0;
    size_t key_len;
    int i;

    /* check if remote_addr_key already exists */
    key_len = strlen(ctx->remote_addr_key);
    for (i = 0; i < obj->via.map.size; i++) {
        key = &obj->via.map.ptr[i].key;
        if (key->type == MSGPACK_OBJECT_STR &&
            key->via.str.size == key_len &&
            memcmp(key->via.str.ptr, ctx->remote_addr_key, key_len) == 0) {
            flb_plg_warn(ctx->ins, "remote_addr_key already present in record, skipping injection");
            return -1;
        }
    }

    msgpack_sbuffer_clear(sbuf);
    msgpack_packer_init(&pck, sbuf, msgpack_sbuffer_write);

    /* create new map with +1 size */
    msgpack_pack_map(&pck, obj->via.map.size + 1);

    /* copy existing map entries */
    for (i = 0; i < obj->via.map.size; i++) {
        msgpack_pack_object(&pck, obj->via.map.ptr[i].key);
        msgpack_pack_object(&pck, obj->via.map.ptr[i].val);
    }

    /* append REMOTE_ADDR entry */
    msgpack_pack_str(&pck, key_len);
    msgpack_pack_str_body(&pck, ctx->remote_addr_key, key_len);
    msgpack_pack_str(&pck, strlen(remote_addr));
    msgpack_pack_str_body(&pck, remote_addr, strlen(remote_addr));

    /* unpack the new record */
    if (msgpack_unpack_next(unpck, sbuf->data, sbuf->size, &off) != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_debug(ctx->ins, "error repacking record with remote_addr");
        return -1;
    }

    return 0;
}

static int process_pack_record(struct flb_http *ctx, struct flb_time *tm,
                               flb_sds_t tag,
                               msgpack_object *record)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_timestamp(&ctx->log_encoder, tm);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_body_from_msgpack_object(
            &ctx->log_encoder,
            record);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    if (tag) {
        ret = flb_input_log_append(ctx->ins,
                                   tag,
                                   flb_sds_len(tag),
                                   ctx->log_encoder.output_buffer,
                                   ctx->log_encoder.output_length);
    }
    else {
        /* use default plugin Tag (it internal name, e.g: http.0 */
        ret = flb_input_log_append(ctx->ins, NULL, 0,
                                   ctx->log_encoder.output_buffer,
                                   ctx->log_encoder.output_length);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return 0;
}

static ssize_t parse_payload_urlencoded(struct flb_http *ctx, flb_sds_t tag,
                                        char *payload, size_t size, void *request)
{
    int i;
    int idx = 0;
    int ret = -1;
    int len;
    struct mk_list *kvs;
    struct mk_list *head = NULL;
    struct mk_list *tmp;
    struct flb_split_entry *cur = NULL;
    char **keys = NULL;
    char **vals = NULL;
    char *sep;
    char *start;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    const char *field_name;

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    kvs = flb_utils_split(payload, '&', -1 );
    if (kvs == NULL) {
        goto split_error;
    }

    keys = flb_calloc(mk_list_size(kvs), sizeof(char *));
    if (keys == NULL) {
        goto keys_calloc_error;
    }

    vals = flb_calloc(mk_list_size(kvs), sizeof(char *));
    if (vals == NULL) {
        goto vals_calloc_error;
    }

    mk_list_foreach_safe(head, tmp, kvs) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        if (cur->value[0] == '\n') {
            start = &cur->value[1];
        }
        else {
            start = cur->value;
        }

        if (!start || *start == '=' || strlen(start) == 0) {
            flb_utils_split_free_entry(cur);
            continue;
        }

        sep = strchr(start, '=');
        if (sep) {
            len = sep - start;
        }
        else {
            /* if no separator is found, just skip the content */
            flb_utils_split_free_entry(cur);
            continue;
        }

        keys[idx] = flb_sds_create_len(start, len);
        len++;

        if (start[len] == '\0') {
            vals[idx] = flb_sds_create("");
        }
        else {
            vals[idx] = flb_sds_create(start + len);
        }

        flb_sds_trim(keys[idx]);
        flb_sds_trim(vals[idx]);
        idx++;
    }

    if (mk_list_size(kvs) == 0) {
        goto decode_error;
    }

    msgpack_pack_map(&pck, mk_list_size(kvs));
    for (i = 0; i < idx; i++) {
        msgpack_pack_str(&pck, flb_sds_len(keys[i]));
        msgpack_pack_str_body(&pck, keys[i], flb_sds_len(keys[i]));

        if (sds_uri_decode(vals[i]) != 0) {
            field_name = keys[i] ? keys[i] : "";
            flb_plg_warn(ctx->ins,
                         "invalid percent-encoding for field '%s', keeping raw value",
                         field_name);
        }
        msgpack_pack_str(&pck, flb_sds_len(vals[i]));
        msgpack_pack_str_body(&pck, vals[i], flb_sds_len(vals[i]));
    }

    ret = process_pack_ng(ctx, tag, sbuf.data, sbuf.size, request);

decode_error:
    for (idx = 0; idx < mk_list_size(kvs); idx++) {
        if (keys[idx]) {
            flb_sds_destroy(keys[idx]);
        }
        if (vals[idx]) {
            flb_sds_destroy(vals[idx]);
        }
    }
    flb_free(vals);
vals_calloc_error:
    flb_free(keys);
keys_calloc_error:
    flb_utils_split_free(kvs);
split_error:
    msgpack_sbuffer_destroy(&sbuf);
    return ret;
}

static int http_header_lookup(struct flb_http_request *request, char *key,
                              char **val, size_t *val_len)
{
    char *value;

    if (request == NULL || key == NULL) {
        return -1;
    }

    value = flb_http_request_get_header(request, key);
    if (!value) {
        return -1;
    }

    *val = value;
    *val_len = strlen(value);
    return 0;
}

/* New gen HTTP server */

static int send_response_ng(struct flb_http_response *response,
                            int http_status,
                            char *message)
{
    struct mk_list            *header_iterator;
    struct flb_slist_entry    *header_value;
    struct flb_slist_entry    *header_name;
    struct flb_config_map_val *header_pair;
    struct flb_http           *context;

    context = (struct flb_http *) response->stream->user_data;

    flb_http_response_set_status(response, http_status);

    if (http_status == 201) {
        flb_http_response_set_message(response, "Created");
    }
    else if (http_status == 200) {
        flb_http_response_set_message(response, "OK");
    }
    else if (http_status == 204) {
        flb_http_response_set_message(response, "No Content");
    }
    else if (http_status == 400) {
        flb_http_response_set_message(response, "Bad Request");
    }
    else if (http_status == 401) {
        flb_http_response_set_message(response, "Unauthorized");
    }
    else if (http_status == 413) {
        flb_http_response_set_message(response, "Payload Too Large");
    }

    if (http_status == 200 ||
        http_status == 201 ||
        http_status == 204) {

        flb_config_map_foreach(header_iterator,
                               header_pair,
                               context->success_headers) {
            header_name = mk_list_entry_first(header_pair->val.list,
                                            struct flb_slist_entry,
                                            _head);

            header_value = mk_list_entry_last(header_pair->val.list,
                                            struct flb_slist_entry,
                                            _head);

            flb_http_response_set_header(response,
                                        header_name->str, 0,
                                        header_value->str, 0);
        }
    }

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int process_pack_ng(struct flb_http *ctx, flb_sds_t tag, char *buf, size_t size, void *request)
{
    int ret;
    size_t off = 0;
    msgpack_unpacked result;
    struct flb_time tm;
    int i = 0;
    msgpack_object *obj;
    msgpack_object record;
    flb_sds_t tag_from_record = NULL;

    flb_sds_t remote_addr = NULL;
    msgpack_unpacked appended_result;
    msgpack_sbuffer appended_sbuf;
    int appended_initialized = 0;

    flb_time_get(&tm);

    if (ctx->add_remote_addr == FLB_TRUE && ctx->remote_addr_key != NULL) {
        remote_addr = get_remote_addr((struct flb_http_request *) request);
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            obj = &result.data;
            if (remote_addr != NULL && flb_sds_len(remote_addr) > 0) {
                if (!appended_initialized) {
                    /* doing this only once, since it can be cleared and reused */
                    msgpack_sbuffer_init(&appended_sbuf);
                    appended_initialized = 1;
                }
                else if (appended_result.zone != NULL) {
                        msgpack_unpacked_destroy(&appended_result);
                }

                /* if we fail to append, we just continue with the original object */
                msgpack_unpacked_init(&appended_result);
                if (append_remote_addr(obj, &appended_result, &appended_sbuf, ctx, remote_addr) == 0) {
                    obj = &appended_result.data;
                }
            }

            tag_from_record = NULL;

            if (ctx->tag_key) {
                tag_from_record = tag_key(ctx, obj);
            }

            if (tag_from_record) {
                ret = process_pack_record(ctx, &tm, tag_from_record, obj);
                flb_sds_destroy(tag_from_record);
            }
            else if (tag) {
                ret = process_pack_record(ctx, &tm, tag, obj);
            }
            else {
                ret = process_pack_record(ctx, &tm, NULL, obj);
            }

            if (ret != 0) {
                goto log_event_error;
            }

            flb_log_event_encoder_reset(&ctx->log_encoder);
        }
        else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            obj = &result.data;
            for (i = 0; i < obj->via.array.size; i++)
            {
                record = obj->via.array.ptr[i];
                if (record.type == MSGPACK_OBJECT_MAP &&
                    remote_addr != NULL && flb_sds_len(remote_addr) > 0) {
                    if (!appended_initialized) {
                        /* doing this only once, since it can be cleared and reused */
                        msgpack_sbuffer_init(&appended_sbuf);
                        appended_initialized = 1;
                    }
                    else if (appended_result.zone != NULL) {
                        msgpack_unpacked_destroy(&appended_result);
                    }

                    /* if we fail to append, we just continue with the original object */
                    msgpack_unpacked_init(&appended_result);
                    if (append_remote_addr(&record, &appended_result, &appended_sbuf, ctx, remote_addr) == 0) {
                        record = appended_result.data;
                    }
                }

                tag_from_record = NULL;
                if (ctx->tag_key) {
                    tag_from_record = tag_key(ctx, &record);
                }

                if (tag_from_record) {
                    ret = process_pack_record(ctx, &tm, tag_from_record, &record);
                    flb_sds_destroy(tag_from_record);
                }
                else if (tag) {
                    ret = process_pack_record(ctx, &tm, tag, &record);
                }
                else {
                    ret = process_pack_record(ctx, &tm, NULL, &record);
                }

                if (ret != 0) {
                    goto log_event_error;
                }

                /* TODO : Optimize this
                 *
                 * This is wasteful, considering that we are emitting a series
                 * of records we should start and commit each one and then
                 * emit them all at once after the loop.
                 */

                flb_log_event_encoder_reset(&ctx->log_encoder);
            }

            break;
        }
        else {
            flb_plg_error(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);

            msgpack_unpacked_destroy(&result);
            if (remote_addr != NULL) {
                flb_sds_destroy(remote_addr);
            }

            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);
    if (appended_initialized) {
        msgpack_unpacked_destroy(&appended_result);
        msgpack_sbuffer_destroy(&appended_sbuf);
    }
    if (remote_addr != NULL) {
        flb_sds_destroy(remote_addr);
    }

    return 0;

log_event_error:
    flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
    msgpack_unpacked_destroy(&result);
    if (appended_initialized) {
        msgpack_unpacked_destroy(&appended_result);
        msgpack_sbuffer_destroy(&appended_sbuf);
    }
    if (remote_addr != NULL) {
        flb_sds_destroy(remote_addr);
    }

    return -1;
}

static ssize_t parse_payload_json_ng(flb_sds_t tag,
                                     struct flb_http_request *request)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    struct flb_http *ctx;
    char *payload;
    size_t size;

    ctx = (struct flb_http *) request->stream->user_data;
    payload = (char *) request->body;
    size = cfl_sds_len(request->body);

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    ret = process_pack_ng(ctx, tag, pack, out_size, request);
    flb_free(pack);

    return ret;
}

static int process_payload_ng(flb_sds_t tag,
                              struct flb_http_request *request,
                              struct flb_http_response *response)
{
    int type = -1;
    cfl_sds_t payload;
    struct flb_http *ctx;

    if (request->content_type == NULL) {
        send_response_ng(response, 400, "error: header 'Content-Type' is not set\n");
        return -1;
    }

    if (content_type_is_json(request->content_type)) {
        type = HTTP_CONTENT_JSON;
    }

    if (content_type_is_urlencoded(request->content_type)) {
        type = HTTP_CONTENT_URLENCODED;
    }

    if (type == -1) {
        send_response_ng(response, 400, "error: invalid 'Content-Type'\n");
        return -1;
    }

    if (request->body == NULL ||
        cfl_sds_len(request->body) == 0) {
        send_response_ng(response, 400, "error: no payload found\n");
        return -1;
    }

    if (type == HTTP_CONTENT_JSON) {
        return parse_payload_json_ng(tag, request);
    }
    else if (type == HTTP_CONTENT_URLENCODED) {
        ctx = (struct flb_http *) request->stream->user_data;
        payload = (char *) request->body;
        if (payload) {
            return parse_payload_urlencoded(ctx, tag, payload,
                                           cfl_sds_len(payload), request);
        }
    }

    return 0;
}

int http_prot_handle_ng(struct flb_http_request *request,
                        struct flb_http_response *response)
{
    int                             i;
    int                             ret;
    int                             len;
    flb_sds_t                       tag;
    const char                     *auth_header;
    size_t                          auth_len;
    struct flb_http                *ctx;

    ctx = (struct flb_http *) response->stream->user_data;
    auth_header = NULL;
    auth_len = 0;
    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    /* Compose the query string using the URI */
    len = cfl_sds_len(request->path);

    if (len == 1) {
        tag = NULL; /* use default tag */
    }
    else {
        tag = flb_sds_create(&request->path[1]);

        if (tag == NULL) {
            return -1;
        }

        /* Sanitize, only allow alphanum chars */
        for (i = 0; i < flb_sds_len(tag); i++) {
            if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
                tag[i] = '_';
            }
        }
    }

    /* ToDo: Fix me */
    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        flb_sds_destroy(tag);
        send_response_ng(response, 400, "error: missing host header\n");
        return -1;
    }

    if (ctx->oauth2_ctx) {
        auth_header = flb_http_request_get_header(request, "authorization");
        if (auth_header != NULL) {
            auth_len = strlen(auth_header);
        }

        ret = flb_oauth2_jwt_validate(ctx->oauth2_ctx, auth_header, auth_len);
        if (ret != FLB_OAUTH2_JWT_OK) {
            flb_plg_error(ctx->ins, "OAuth2 validation failed: %s (rejecting request with 401)",
                         flb_oauth2_jwt_status_message(ret));
            flb_sds_destroy(tag);
            send_response_ng(response, 401, NULL);
            return -1;
        }
    }

    if (request->method != HTTP_METHOD_POST) {
        send_response_ng(response, 400, "error: invalid HTTP method\n");
        flb_sds_destroy(tag);

        return -1;
    }

    ret = process_payload_ng(tag, request, response);
    flb_sds_destroy(tag);

    if (ret == 0) {
        send_response_ng(response, ctx->successful_response_code, NULL);
    }
    else {
        send_response_ng(response, 400, "error: unable to process records\n");
    }

    return ret;
}
