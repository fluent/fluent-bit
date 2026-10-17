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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_chunk_trace.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include <msgpack.h>
#include <ctype.h>
#include <limits.h>

#define STR_INPUTS "inputs"
#define STR_INPUTS_LEN (sizeof(STR_INPUTS)-1)

#define HTTP_FIELD_MESSAGE        "message"
#define HTTP_FIELD_MESSAGE_LEN    (sizeof(HTTP_FIELD_MESSAGE)-1)
#define HTTP_FIELD_STATUS         "status"
#define HTTP_FIELD_STATUS_LEN     (sizeof(HTTP_FIELD_STATUS)-1)
#define HTTP_FIELD_RETURNCODE     "returncode"
#define HTTP_FIELD_RETURNCODE_LEN (sizeof(HTTP_FIELD_RETURNCODE)-1)

#define HTTP_RESULT_OK                   "ok"
#define HTTP_RESULT_OK_LEN               (sizeof(HTTP_RESULT_OK)-1)
#define HTTP_RESULT_ERROR                "error"
#define HTTP_RESULT_ERROR_LEN            (sizeof(HTTP_RESULT_ERROR)-1)
#define HTTP_RESULT_FORBIDDEN            "output plugin or parameter not allowed"
#define HTTP_RESULT_FORBIDDEN_LEN        (sizeof(HTTP_RESULT_FORBIDDEN)-1)
#define HTTP_RESULT_NOTFOUND             "not found"
#define HTTP_RESULT_NOTFOUND_LEN         (sizeof(HTTP_RESULT_NOTFOUND)-1)
#define HTTP_RESULT_METHODNOTALLOWED     "method not allowed"
#define HTTP_RESULT_METHODNOTALLOWED_LEN (sizeof(HTTP_RESULT_METHODNOTALLOWED)-1)
#define HTTP_RESULT_UNKNOWNERROR         "unknown error"
#define HTTP_RESULT_UNKNOWNERROR_LEN     (sizeof(HTTP_RESULT_UNKNOWNERROR)-1)

static struct flb_input_instance *find_input(struct flb_hs *hs, const char *name, size_t nlen)
{
    struct mk_list *head;
    struct flb_input_instance *in;


    mk_list_foreach(head, &hs->config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if ((strlen(in->name) == nlen) && (strncmp(name, in->name, nlen) == 0)) {
            return in;
        }
        if (in->alias) {
            if ((strlen(in->alias) == nlen) && (strncmp(name, in->alias, nlen) == 0)) {
                return in;
            }
        }
    }
    return NULL;
}

/*
 * The trace API is served by the unauthenticated monitoring server, so it must
 * not let a remote client instantiate arbitrary output plugins: outputs such
 * as file, http or s3 can write files, open connections or run the AWS
 * credential_process. Only stdout, and the calyptia output which reuses the
 * properties of the configured instance, can be requested. The http output is
 * only accepted when the operator allowlists its destinations through the
 * chunk_trace_http_allowed_endpoints service option. Any other output can
 * still be used locally through the --trace command line option.
 */
static const char *trace_allowed_outputs[] = {
    "stdout",
    "calyptia",
    NULL
};

static const char *trace_allowed_params[] = {
    "format",
    "json_date_key",
    "json_date_format",
    NULL
};

/*
 * Only parameters that select the endpoint and encode the payload: proxy,
 * file based TLS settings, AWS and OAuth2 options could redirect the records
 * or read local files and credentials, so they are rejected.
 */
static const char *trace_http_allowed_params[] = {
    "host",
    "port",
    "uri",
    "format",
    "json_date_key",
    "json_date_format",
    "header",
    "compress",
    "tls",
    NULL
};

/*
 * Output names are matched exactly: the chunk trace pipeline only reuses the
 * configured calyptia instance properties for the exact "calyptia" name, while
 * plugin lookup is case-insensitive. Property names are case-insensitive.
 */
static int trace_name_allowed(const char **list, const char *name, int ignore_case)
{
    int i;
    int ret;

    for (i = 0; list[i] != NULL; i++) {
        if (ignore_case == FLB_TRUE) {
            ret = strcasecmp(list[i], name);
        }
        else {
            ret = strcmp(list[i], name);
        }

        if (ret == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static const char *trace_prop_get(struct mk_list *props, const char *key)
{
    struct mk_list *head;
    struct flb_kv *kv;

    if (props == NULL) {
        return NULL;
    }

    mk_list_foreach(head, props) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(kv->key, key) == 0) {
            return kv->val;
        }
    }

    return NULL;
}

static int trace_http_port_parse(const char *str, size_t len, int *port)
{
    size_t i;
    int val = 0;

    if (len == 0 || len > 5) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char) str[i])) {
            return -1;
        }
        val = (val * 10) + (str[i] - '0');
    }

    if (val < 1 || val > 65535) {
        return -1;
    }

    *port = val;
    return 0;
}

/*
 * Match an allowlist entry against the requested destination. Entries use
 * the form host:port or [ipv6]:port, optionally followed by a path, in which
 * case the requested uri must be exactly that path. Host names are compared
 * case-insensitively and are never resolved here.
 */
static int trace_http_endpoint_match(const char *entry, const char *host,
                                     int port, const char *uri)
{
    int entry_port;
    const char *p;
    const char *host_start;
    const char *host_end;
    const char *path;
    const char *port_end;

    if (entry[0] == '[') {
        host_start = entry + 1;
        host_end = strchr(host_start, ']');
        if (host_end == NULL || host_end[1] != ':') {
            return -1;
        }
        p = host_end + 2;
    }
    else {
        host_start = entry;
        host_end = strchr(entry, ':');
        if (host_end == NULL) {
            return -1;
        }
        p = host_end + 1;
    }

    if (host_end == host_start) {
        return -1;
    }

    path = strchr(p, '/');
    port_end = path != NULL ? path : p + strlen(p);
    if (trace_http_port_parse(p, port_end - p, &entry_port) != 0) {
        return -1;
    }

    if (strlen(host) != (size_t) (host_end - host_start) ||
        strncasecmp(host, host_start, host_end - host_start) != 0 ||
        port != entry_port) {
        return FLB_FALSE;
    }

    if (path != NULL && strcmp(path, uri) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int trace_http_endpoint_allowed(struct flb_config *config, struct mk_list *props)
{
    int ret;
    int port = 80;
    int allowed = FLB_FALSE;
    const char *host;
    const char *port_str;
    const char *uri;
    struct mk_list entries;
    struct mk_list *head;
    struct flb_kv *kv;
    struct flb_slist_entry *entry;

    if (config->chunk_trace_http_allowed_endpoints == NULL) {
        flb_error("trace output 'http' is disabled, allow destinations with "
                  "the '%s' service option",
                  FLB_CONF_STR_CHUNK_TRACE_HTTP_ALLOWED_ENDPOINTS);
        return FLB_FALSE;
    }

    if (props != NULL) {
        mk_list_foreach(head, props) {
            kv = mk_list_entry(head, struct flb_kv, _head);
            if (trace_name_allowed(trace_http_allowed_params, kv->key, FLB_TRUE) == FLB_FALSE) {
                flb_error("trace output parameter '%s' is not allowed", kv->key);
                return FLB_FALSE;
            }
            /* Output properties expand ${VAR}, which could leak the environment. */
            if (kv->val != NULL && strstr(kv->val, "${") != NULL) {
                flb_error("trace output parameter '%s' must not reference "
                          "environment variables", kv->key);
                return FLB_FALSE;
            }
        }
    }

    host = trace_prop_get(props, "host");
    if (host == NULL || host[0] == '\0') {
        flb_error("trace output 'http' requires the 'host' parameter");
        return FLB_FALSE;
    }

    port_str = trace_prop_get(props, "port");
    if (port_str != NULL &&
        trace_http_port_parse(port_str, strlen(port_str), &port) != 0) {
        flb_error("trace output 'http' has an invalid port '%s'", port_str);
        return FLB_FALSE;
    }

    uri = trace_prop_get(props, "uri");
    if (uri == NULL) {
        uri = "/";
    }

    flb_slist_create(&entries);
    if (flb_slist_split_string(&entries, config->chunk_trace_http_allowed_endpoints,
                               ',', -1) == -1) {
        flb_slist_destroy(&entries);
        return FLB_FALSE;
    }

    mk_list_foreach(head, &entries) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        ret = trace_http_endpoint_match(entry->str, host, port, uri);
        if (ret == -1) {
            flb_warn("invalid entry '%s' in '%s', expected host:port[/uri]",
                     entry->str, FLB_CONF_STR_CHUNK_TRACE_HTTP_ALLOWED_ENDPOINTS);
        }
        else if (ret == FLB_TRUE) {
            allowed = FLB_TRUE;
            break;
        }
    }
    flb_slist_destroy(&entries);

    if (allowed == FLB_FALSE) {
        flb_error("trace output 'http' endpoint '%s:%i%s' is not allowed",
                  host, port, uri);
    }

    return allowed;
}

static int trace_output_allowed(struct flb_config *config, const char *output_name,
                                struct mk_list *props)
{
    struct mk_list *head;
    struct flb_kv *kv;

    if (strcmp(output_name, "http") == 0) {
        return trace_http_endpoint_allowed(config, props);
    }

    if (trace_name_allowed(trace_allowed_outputs, output_name, FLB_FALSE) == FLB_FALSE) {
        flb_error("trace output '%s' is not allowed", output_name);
        return FLB_FALSE;
    }

    if (props == NULL) {
        return FLB_TRUE;
    }

    mk_list_foreach(head, props) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (trace_name_allowed(trace_allowed_params, kv->key, FLB_TRUE) == FLB_FALSE) {
            flb_error("trace output parameter '%s' is not allowed", kv->key);
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int enable_trace_input(struct flb_hs *hs, const char *name, ssize_t nlen, const char *prefix,
                              const char *output_name, struct mk_list *props)
{
    struct flb_input_instance *in;

    if (trace_output_allowed(hs->config, output_name, props) == FLB_FALSE) {
        return 403;
    }

    in = find_input(hs, name, nlen);
    if (in == NULL) {
        flb_error("unable to find input: [%d]%.*s", (int)nlen, (int)nlen, name);
        return 404;
    }

    flb_chunk_trace_context_new(in, output_name, prefix, NULL, props);

    if (in->chunk_trace_ctxt == NULL) {
        flb_error("unable to start tracing");
        return 503;
    }

    return 0;
}

static int disable_trace_input(struct flb_hs *hs, const char *name, size_t nlen)
{
    struct flb_input_instance *in;


    in = find_input(hs, name, nlen);
    if (in == NULL) {
        return 404;
    }

    if (in->chunk_trace_ctxt != NULL) {
        flb_chunk_trace_context_destroy(in);
    }
    return 201;
}

static flb_sds_t get_input_name(struct flb_http_request *request)
{
    const char base[] = "/api/v1/trace/";


    if (request->path == NULL) {
        return NULL;
    }
    if (cfl_sds_len(request->path) < sizeof(base)-1) {
        return NULL;
    }

    return flb_sds_create_len(&request->path[sizeof(base)-1],
                              cfl_sds_len(request->path) - (sizeof(base)-1));
}

static int http_disable_trace(struct flb_http_request *request, void *data,
                              const char *input_name, size_t input_nlen,
                              msgpack_packer *mp_pck)
{
    struct flb_hs *hs = data;
    int toggled_on = 503;


    toggled_on = disable_trace_input(hs, input_name, input_nlen);
    if (toggled_on < 300) {
        msgpack_pack_map(mp_pck, 1);
        msgpack_pack_str_with_body(mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
        return 201;
    }

    return toggled_on;
}

/* Bound both temporary parsing storage and per-input trace output copies. */
#define TRACE_MAX_INPUTS 64
#define TRACE_MAX_PARAMS 64
#define TRACE_MAX_OPTION_BYTES (64 * 1024)

struct trace_options {
    flb_sds_t prefix;
    flb_sds_t output_name;
    struct mk_list props;
    struct flb_chunk_trace_limit limit;
};

static int trace_key_equals(msgpack_object *key, const char *name)
{
    size_t len = strlen(name);

    return key->type == MSGPACK_OBJECT_STR && key->via.str.size == len &&
           memcmp(key->via.str.ptr, name, len) == 0;
}

static void trace_options_destroy(struct trace_options *options)
{
    flb_sds_destroy(options->prefix);
    flb_sds_destroy(options->output_name);
    flb_kv_release(&options->props);
}

/* Account before copying; subtraction avoids overflowing on untrusted lengths. */
static int trace_option_account(size_t *bytes, msgpack_object *value)
{
    if (value->type != MSGPACK_OBJECT_STR ||
        value->via.str.size > TRACE_MAX_OPTION_BYTES - *bytes ||
        memchr(value->via.str.ptr, '\0', value->via.str.size) != NULL) {
        return -1;
    }

    *bytes += value->via.str.size;
    return 0;
}

/* The caller owns even partially populated options and must always release them. */
static int trace_options_parse(msgpack_unpacked *result, struct trace_options *options)
{
    size_t bytes = 0;
    size_t i;
    size_t x;
    unsigned int seen = 0;
    unsigned int field;
    msgpack_object *key;
    msgpack_object *val;
    msgpack_object_kv *param;
    struct mk_list *head;
    struct flb_kv *kv;

    if (result->data.type != MSGPACK_OBJECT_MAP) {
        return 400;
    }

    for (i = 0; i < result->data.via.map.size; i++) {
        key = &result->data.via.map.ptr[i].key;
        val = &result->data.via.map.ptr[i].val;
        if (key->type != MSGPACK_OBJECT_STR) {
            return 400;
        }

        field = 0;
        if (trace_key_equals(key, "prefix")) {
            field = 1;
        }
        else if (trace_key_equals(key, "output")) {
            field = 2;
        }
        else if (trace_key_equals(key, "params")) {
            field = 4;
        }
        else if (trace_key_equals(key, "limit")) {
            field = 8;
        }
        else if (trace_key_equals(key, "inputs")) {
            field = 16;
        }
        if ((seen & field) != 0) {
            return 400;
        }
        seen |= field;

        if (field == 1 || field == 2) {
            if (trace_option_account(&bytes, val) != 0) {
                return 400;
            }
            if (field == 1) {
                options->prefix = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
                if (options->prefix == NULL) {
                    return 503;
                }
            }
            else {
                options->output_name = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
                if (options->output_name == NULL) {
                    return 503;
                }
            }
        }
        else if (field == 4) {
            if (val->type != MSGPACK_OBJECT_MAP || val->via.map.size > TRACE_MAX_PARAMS) {
                return 400;
            }
            for (x = 0; x < val->via.map.size; x++) {
                param = &val->via.map.ptr[x];
                if (trace_option_account(&bytes, &param->key) != 0 ||
                    trace_option_account(&bytes, &param->val) != 0) {
                    return 400;
                }
                /* Output property names are case-insensitive. */
                mk_list_foreach(head, &options->props) {
                    kv = mk_list_entry(head, struct flb_kv, _head);
                    if (flb_sds_len(kv->key) == param->key.via.str.size &&
                        strncasecmp(kv->key, param->key.via.str.ptr, param->key.via.str.size) == 0) {
                        return 400;
                    }
                }
                if (flb_kv_item_create_len(&options->props,
                                          (char *) param->key.via.str.ptr, param->key.via.str.size,
                                          (char *) param->val.via.str.ptr, param->val.via.str.size) == NULL) {
                    return 503;
                }
            }
        }
        else if (field == 8) {
            if (val->type != MSGPACK_OBJECT_MAP || val->via.map.size != 1) {
                return 400;
            }
            param = &val->via.map.ptr[0];
            if (param->val.type != MSGPACK_OBJECT_POSITIVE_INTEGER ||
                param->val.via.u64 == 0 || param->val.via.u64 > INT_MAX) {
                return 400;
            }
            if (trace_key_equals(&param->key, "seconds")) {
                options->limit.type = FLB_CHUNK_TRACE_LIMIT_TIME;
                options->limit.seconds = param->val.via.u64;
            }
            else if (trace_key_equals(&param->key, "count")) {
                options->limit.type = FLB_CHUNK_TRACE_LIMIT_COUNT;
                options->limit.count = param->val.via.u64;
            }
            else {
                return 400;
            }
        }
    }

    if (options->output_name == NULL) {
        options->output_name = flb_sds_create("stdout");
        if (options->output_name == NULL) {
            return 503;
        }
    }
    return 0;
}

static int http_enable_trace(struct flb_http_request *request, void *data,
                             const char *input_name, ssize_t input_nlen,
                             msgpack_packer *mp_pck)
{
    char *buf = NULL;
    size_t buf_size;
    msgpack_unpacked result;
    int ret;
    int root_type;
    size_t off = 0;
    struct flb_hs *hs = data;
    struct trace_options options = {0};
    struct flb_input_instance *input_instance;

    flb_kv_init(&options.props);
    msgpack_unpacked_init(&result);
    if (request->method == HTTP_METHOD_GET) {
        ret = enable_trace_input(hs, input_name, input_nlen, "trace.", "stdout", NULL);
    }
    else {
        ret = 400;
        if (request->body == NULL) {
            goto done;
        }
        if (flb_pack_json(request->body, cfl_sds_len(request->body), &buf, &buf_size,
                          &root_type, NULL) != 0) {
            goto done;
        }
        if (msgpack_unpack_next(&result, buf, buf_size, &off) != MSGPACK_UNPACK_SUCCESS) {
            goto done;
        }
        ret = trace_options_parse(&result, &options);
        if (ret != 0) {
            goto done;
        }
        ret = enable_trace_input(hs, input_name, input_nlen, options.prefix,
                                 options.output_name, &options.props);
        if (ret == 0 && options.limit.type != 0) {
            input_instance = find_input(hs, input_name, input_nlen);
            if (options.limit.type == FLB_CHUNK_TRACE_LIMIT_TIME) {
                ret = flb_chunk_trace_context_set_limit(input_instance,
                                                       options.limit.type, options.limit.seconds);
            }
            else {
                ret = flb_chunk_trace_context_set_limit(input_instance,
                                                       options.limit.type, options.limit.count);
            }
            if (ret != 0) {
                ret = 503;
            }
        }
    }
    if (ret == 0) {
        msgpack_pack_map(mp_pck, 1);
        msgpack_pack_str_with_body(mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
        ret = 200;
    }

done:
    trace_options_destroy(&options);
    msgpack_unpacked_destroy(&result);
    flb_free(buf);
    return ret;
}

static int cb_trace(struct flb_hs *hs,
                    struct flb_http_request *request,
                    struct flb_http_response *http_response)
{
    flb_sds_t out_buf;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int http_status = 404;
    flb_sds_t input_name = NULL;


    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    input_name = get_input_name(request);
    if (input_name == NULL) {
        http_status = 404;
        goto error;
    }

    if (request->method == HTTP_METHOD_POST || request->method == HTTP_METHOD_GET) {
        http_status = http_enable_trace(request, hs, input_name, flb_sds_len(input_name), &mp_pck);
    }
    else if (request->method == HTTP_METHOD_DELETE) {
        http_status = http_disable_trace(request, hs, input_name, flb_sds_len(input_name), &mp_pck);
    }
error:
    if (http_status == 404) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_NOTFOUND, HTTP_RESULT_NOTFOUND_LEN);
    }
    else if (http_status == 403) {
        msgpack_pack_map(&mp_pck, 2);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_MESSAGE, HTTP_FIELD_MESSAGE_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_FORBIDDEN, HTTP_RESULT_FORBIDDEN_LEN);
    }
    else if (http_status == 400 || http_status == 503) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
    }

    if (input_name != NULL) {
        flb_sds_destroy(input_name);
    }

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    if (out_buf == NULL) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_http_response_set_status(http_response, 503);
        return flb_http_response_commit(http_response);
    }

    flb_hs_response_set_payload(http_response, http_status,
                                FLB_HS_CONTENT_TYPE_JSON,
                                out_buf, flb_sds_len(out_buf));

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_sds_destroy(out_buf);
    return 0;
}

static int cb_traces(struct flb_hs *hs,
                     struct flb_http_request *request,
                     struct flb_http_response *http_response)
{
    flb_sds_t out_buf;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int ret;
    char *buf = NULL;
    size_t buf_size;
    int root_type = MSGPACK_OBJECT_ARRAY;
    msgpack_unpacked result;
    flb_sds_t error_msg = NULL;
    int http_status = 200;
    const char *input_name;
    ssize_t input_nlen;
    msgpack_object_array *inputs = NULL;
    size_t off = 0;
    int i;
    int j;
    struct trace_options options = {0};
    struct flb_input_instance *instances[TRACE_MAX_INPUTS];

    flb_kv_init(&options.props);

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    if (request->body == NULL) {
        http_status = 400;
        error_msg = flb_sds_create("missing request body");
        goto unpack_error;
    }
    ret = flb_pack_json(request->body, cfl_sds_len(request->body), &buf, &buf_size,
                        &root_type, NULL);
    if (ret != 0) {
        http_status = 400;
        error_msg = flb_sds_create("invalid JSON parameters");
        goto unpack_error;
    }

    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        http_status = 400;
        error_msg = flb_sds_create("unfinished input");
        goto unpack_error;
    }

    if (result.data.type != MSGPACK_OBJECT_MAP) {
        http_status = 400;
        error_msg = flb_sds_create("input is not an object");
        goto unpack_error;
    }

    for (i = 0; i < result.data.via.map.size; i++) {
        if (!trace_key_equals(&result.data.via.map.ptr[i].key, STR_INPUTS)) {
            continue;
        }
        if (inputs != NULL || result.data.via.map.ptr[i].val.type != MSGPACK_OBJECT_ARRAY) {
            http_status = 400;
            error_msg = flb_sds_create("invalid or duplicate inputs");
            goto unpack_error;
        }
        inputs = &result.data.via.map.ptr[i].val.via.array;
    }

    if (inputs == NULL || inputs->size > TRACE_MAX_INPUTS) {
        http_status = 400;
        error_msg = flb_sds_create("missing inputs or too many inputs (maximum 64)");
        goto unpack_error;
    }

    /* Validate the entire batch before allocating options or changing any input. */
    for (i = 0; i < inputs->size; i++) {
        if (inputs->ptr[i].type != MSGPACK_OBJECT_STR ||
            inputs->ptr[i].via.str.size == 0 ||
            memchr(inputs->ptr[i].via.str.ptr, '\0', inputs->ptr[i].via.str.size) != NULL) {
            http_status = 400;
            error_msg = flb_sds_create("invalid input");
            goto unpack_error;
        }
        input_name = inputs->ptr[i].via.str.ptr;
        input_nlen = inputs->ptr[i].via.str.size;
        instances[i] = find_input(hs, input_name, input_nlen);
        for (j = 0; j < i; j++) {
            if ((instances[i] != NULL && instances[i] == instances[j]) ||
                (inputs->ptr[j].via.str.size == input_nlen &&
                 memcmp(inputs->ptr[j].via.str.ptr, input_name, input_nlen) == 0)) {
                http_status = 400;
                error_msg = flb_sds_create("duplicate input");
                goto unpack_error;
            }
        }
    }

    if (request->method == HTTP_METHOD_POST) {
        ret = trace_options_parse(&result, &options);
        if (ret != 0) {
            http_status = ret;
            error_msg = flb_sds_create("invalid trace options or allocation failure");
            goto unpack_error;
        }
    }

    msgpack_pack_map(&mp_pck, 2);
    msgpack_pack_str_with_body(&mp_pck, STR_INPUTS, STR_INPUTS_LEN);
    msgpack_pack_map(&mp_pck, inputs->size);

    for (i = 0; i < inputs->size; i++) {

        input_name = inputs->ptr[i].via.str.ptr;
        input_nlen = inputs->ptr[i].via.str.size;

        msgpack_pack_str_with_body(&mp_pck, input_name, input_nlen);

        if (request->method == HTTP_METHOD_POST) {

            if (instances[i] == NULL) {
                ret = 404;
            }
            else {
                ret = enable_trace_input(hs, input_name, input_nlen, options.prefix,
                                         options.output_name, &options.props);
            }

            if (ret != 0) {
                msgpack_pack_map(&mp_pck, 2);
                msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
                msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
                msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_RETURNCODE,
                                           HTTP_FIELD_RETURNCODE_LEN);
                msgpack_pack_int64(&mp_pck, ret);
            }
            else {
                msgpack_pack_map(&mp_pck, 1);
                msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
                msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
            }
        }
        else if (request->method == HTTP_METHOD_DELETE) {
            disable_trace_input(hs, input_name, input_nlen);
            msgpack_pack_map(&mp_pck, 1);
            msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
        }
        else {
            msgpack_pack_map(&mp_pck, 2);
            msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_MESSAGE, HTTP_FIELD_MESSAGE_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_METHODNOTALLOWED,
                                       HTTP_RESULT_METHODNOTALLOWED_LEN);
        }
    }

    msgpack_pack_str_with_body(&mp_pck, "result", strlen("result"));
unpack_error:
    trace_options_destroy(&options);
    if (buf != NULL) {
        flb_free(buf);
    }
    msgpack_unpacked_destroy(&result);
    if (http_status == 404) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_NOTFOUND, HTTP_RESULT_NOTFOUND_LEN);
    }
    else if (http_status == 400 || http_status == 503) {
        msgpack_pack_map(&mp_pck, 2);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_MESSAGE, HTTP_FIELD_MESSAGE_LEN);
        if (error_msg) {
            msgpack_pack_str_with_body(&mp_pck, error_msg, flb_sds_len(error_msg));
        }
        else {
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_UNKNOWNERROR,
                                       HTTP_RESULT_UNKNOWNERROR_LEN);
        }
    }
    else {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
    }

    flb_sds_destroy(error_msg);

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (out_buf == NULL) {
        flb_http_response_set_status(http_response, 503);
        return flb_http_response_commit(http_response);
    }

    flb_hs_response_set_payload(http_response, http_status,
                                FLB_HS_CONTENT_TYPE_JSON,
                                out_buf, flb_sds_len(out_buf));

    flb_sds_destroy(out_buf);
    return 0;
}

/* Perform registration */
int api_v1_trace(struct flb_hs *hs)
{
    int ret;

    if (hs->config->enable_chunk_trace == FLB_TRUE) {
        ret = flb_hs_register_endpoint(hs, "/api/v1/traces/",
                                       FLB_HS_ROUTE_EXACT, cb_traces);
        if (ret != 0) {
            return ret;
        }

        ret = flb_hs_register_endpoint(hs, "/api/v1/trace/",
                                       FLB_HS_ROUTE_PREFIX, cb_trace);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}
