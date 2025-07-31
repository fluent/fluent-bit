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

#define _GNU_SOURCE
#include <string.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_intermediate_metric.h>
#include <fluent-bit/flb_metrics.h>
#include "fluent-bit/flb_ra_key.h"

#include <monkey/mk_core.h>
#include <msgpack.h>
#include <stdio.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <unistd.h>
#endif

#include "cloudwatch_api.h"


#define ERR_CODE_ALREADY_EXISTS         "ResourceAlreadyExistsException"
#define ERR_CODE_NOT_FOUND              "ResourceNotFoundException"

#define AMZN_REQUEST_ID_HEADER          "x-amzn-RequestId"

#define ONE_DAY_IN_MILLISECONDS          86400000
#define FOUR_HOURS_IN_SECONDS            14400


static struct flb_aws_header create_group_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.CreateLogGroup",
    .val_len = 28,
};

static struct flb_aws_header put_retention_policy_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.PutRetentionPolicy",
    .val_len = 32,
};

static struct flb_aws_header create_stream_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.CreateLogStream",
    .val_len = 29,
};

static struct flb_aws_header put_log_events_header[] = {
    {
        .key = "X-Amz-Target",
        .key_len = 12,
        .val = "Logs_20140328.PutLogEvents",
        .val_len = 26,
    },
    {
        .key = "x-amzn-logs-format",
        .key_len = 18,
        .val = "",
        .val_len = 0,
    },
};

int plugin_under_test()
{
    if (getenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

char *mock_error_response(char *error_env_var)
{
    char *err_val = NULL;
    char *error = NULL;
    int len = 0;

    err_val = getenv(error_env_var);
    if (err_val != NULL && strlen(err_val) > 0) {
        error = flb_malloc(strlen(err_val) + sizeof(char));
        if (error == NULL) {
            flb_errno();
            return NULL;
        }

        len = strlen(err_val);
        memcpy(error, err_val, len);
        error[len] = '\0';
        return error;
    }

    return NULL;
}

struct flb_http_client *mock_http_call(char *error_env_var, char *api)
{
    /* create an http client so that we can set the response */
    struct flb_http_client *c = NULL;
    char *error = mock_error_response(error_env_var);

    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        flb_free(error);
        return NULL;
    }
    mk_list_init(&c->headers);

    if (error != NULL) {
        c->resp.status = 400;
        /* resp.data is freed on destroy, payload is supposed to reference it */
        c->resp.data = error;
        c->resp.payload = c->resp.data;
        c->resp.payload_size = strlen(error);
    }
    else {
        c->resp.status = 200;
        c->resp.payload = "";
        c->resp.payload_size = 0;
        if (strcmp(api, "PutLogEvents") == 0) {
            /* mocked success response */
            c->resp.payload = "{\"nextSequenceToken\": \""
                  "49536701251539826331025683274032969384950891766572122113\"}";
            c->resp.payload_size = strlen(c->resp.payload);
        }
        else {
            c->resp.payload = "";
            c->resp.payload_size = 0;
        }
    }

    return c;
}

int compare_events(const void *a_arg, const void *b_arg)
{
    struct cw_event *r_a = (struct cw_event *) a_arg;
    struct cw_event *r_b = (struct cw_event *) b_arg;

    if (r_a->timestamp < r_b->timestamp) {
        return -1;
    }
    else if (r_a->timestamp == r_b->timestamp) {
        return 0;
    }
    else {
        return 1;
    }
}

static inline int try_to_write(char *buf, int *off, size_t left,
                               const char *str, size_t str_len)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        return FLB_FALSE;
    }
    memcpy(buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}

static int entity_add_key_attributes(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                                     struct log_stream *stream, int *offset)
{
    char ts[KEY_ATTRIBUTES_MAX_LEN];
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"keyAttributes\":{",0)) {
        goto error;
    }
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                        "\"Type\":\"Service\"",0)) {
        goto error;
    }
    if(stream->entity->key_attributes->name != NULL &&
       strlen(stream->entity->key_attributes->name) != 0) {
        if (!snprintf(ts,KEY_ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"Name\":\"",stream->entity->key_attributes->name,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->key_attributes->environment != NULL &&
       strlen(stream->entity->key_attributes->environment) != 0) {
        if (!snprintf(ts,KEY_ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"Environment\":\"",stream->entity->key_attributes->environment,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->key_attributes->account_id != NULL &&
       strlen(stream->entity->key_attributes->account_id) != 0) {
        if (!snprintf(ts,KEY_ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"AwsAccountId\":\"",stream->entity->key_attributes->account_id,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
              "},", 2)) {
        goto error;
    }
    return 0;
error:
    return -1;
}

static int entity_add_attributes(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                                 struct log_stream *stream,int *offset)
{
    char ts[ATTRIBUTES_MAX_LEN];
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"attributes\":{",
                      0)) {
        goto error;
    }
    if (stream->entity->attributes->platform_type != NULL &&
        strlen(stream->entity->attributes->platform_type) != 0) {
        if (strcmp(stream->entity->attributes->platform_type, "eks") == 0) {
            if (!snprintf(ts,ATTRIBUTES_MAX_LEN, "%s%s%s",
                "\"PlatformType\":\"","AWS::EKS","\"")) {
                goto error;
            }
            if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
                goto error;
            }
            if(stream->entity->attributes->cluster_name != NULL &&
               strlen(stream->entity->attributes->cluster_name) != 0) {
                if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
                    "\"EKS.Cluster\":\"",stream->entity->attributes->cluster_name,"\"")) {
                    goto error;
                }
                if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
                    goto error;
                }
            }
        }
        else if (strcmp(stream->entity->attributes->platform_type, "k8s") == 0) {
            if (!snprintf(ts,ATTRIBUTES_MAX_LEN, "%s%s%s",
                "\"PlatformType\":\"","K8s","\"")) {
                goto error;
            }
            if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
                goto error;
            }
            if(stream->entity->attributes->cluster_name != NULL &&
               strlen(stream->entity->attributes->cluster_name) != 0) {
                if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
                    "\"K8s.Cluster\":\"",stream->entity->attributes->cluster_name,"\"")) {
                    goto error;
                }
                if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
                    goto error;
                }
            }
        }
    }
    else {
        if (!snprintf(ts,ATTRIBUTES_MAX_LEN, "%s%s%s",
            "\"PlatformType\":\"","Generic","\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->attributes->namespace != NULL &&
       strlen(stream->entity->attributes->namespace) != 0) {
        if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"K8s.Namespace\":\"",stream->entity->attributes->namespace,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->attributes->node != NULL &&
       strlen(stream->entity->attributes->node) != 0) {
        if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"K8s.Node\":\"",buf->current_stream->entity->attributes->node,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->attributes->workload != NULL &&
       strlen(stream->entity->attributes->workload) != 0) {
        if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"K8s.Workload\":\"",buf->current_stream->entity->attributes->workload,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->attributes->instance_id != NULL &&
       strlen(stream->entity->attributes->instance_id) != 0) {
        if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"EC2.InstanceId\":\"",buf->current_stream->entity->attributes->instance_id,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }
    if(stream->entity->attributes->name_source != NULL &&
       strlen(stream->entity->attributes->name_source) != 0) {
        if (!snprintf(ts,ATTRIBUTES_MAX_LEN, ",%s%s%s",
            "\"AWS.ServiceNameSource\":\"",buf->current_stream->entity->attributes->name_source,"\"")) {
            goto error;
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,ts,0)) {
            goto error;
        }
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                  "}", 1)) {
        goto error;
    }
    return 0;
error:
    return -1;
}

/*
 * Writes the "header" for a put log events payload
 */
static int init_put_payload(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                            struct log_stream *stream, int *offset)
{
    int ret;
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"logGroupName\":\"", 17)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      stream->group, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",\"logStreamName\":\"", 19)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      stream->name, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",", 2)) {
        goto error;
    }
    /*
     * If we are missing the service name, the entity will get rejected by the frontend
     * anyway so do not emit entity unless service name is filled. If we are missing
     * account ID, it is considered not having sufficient information for entity
     * therefore we should drop the entity.
     */
    if(ctx->add_entity && stream->entity != NULL &&
       stream->entity->key_attributes != NULL &&
       stream->entity->key_attributes->name != NULL &&
       stream->entity->key_attributes->account_id != NULL) {
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"entity\":{", 10)) {
            goto error;
        }

        if(stream->entity->key_attributes != NULL) {
            ret = entity_add_key_attributes(ctx,buf,stream,offset);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "Failed to initialize Entity KeyAttributes");
                goto error;
            }
        }
        if(stream->entity->attributes != NULL) {
            ret = entity_add_attributes(ctx,buf,stream,offset);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "Failed to initialize Entity Attributes");
                goto error;
            }
        }
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "},", 2)) {
            goto error;
        }

    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"logEvents\":[", 13)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/*
 * Writes a log event to the output buffer
 */
static int write_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                       struct cw_event *event, int *offset)
{
    char ts[50];

    if (!snprintf(ts, 50, "%llu", event->timestamp)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"timestamp\":", 13)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ts, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ",\"message\":\"", 12)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      event->json, event->len)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"}", 2)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/* Terminates a PutLogEvents payload */
static int end_put_payload(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                           int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "]}", 2)) {
        return -1;
    }
    buf->out_buf[*offset] = '\0';

    return 0;
}

static unsigned long long stream_time_span(struct log_stream *stream,
                                           struct cw_event *event)
{
    if (stream->oldest_event == 0 || stream->newest_event == 0) {
        return 0;
    }

    if (stream->oldest_event > event->timestamp) {
        return stream->newest_event - event->timestamp;
    }
    else if (stream->newest_event < event->timestamp) {
        return event->timestamp - stream->oldest_event;
    }

    return stream->newest_event - stream->oldest_event;
}

/* returns FLB_TRUE if time span is less than 24 hours, FLB_FALSE if greater */
static int check_stream_time_span(struct log_stream *stream,
                                  struct cw_event *event)
{
    unsigned long long span = stream_time_span(stream, event);

    if (span < ONE_DAY_IN_MILLISECONDS) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* sets the oldest_event and newest_event fields */
static void set_stream_time_span(struct log_stream *stream, struct cw_event *event)
{
    if (stream->oldest_event == 0 || stream->oldest_event > event->timestamp) {
        stream->oldest_event = event->timestamp;
    }

    if (stream->newest_event == 0 || stream->newest_event < event->timestamp) {
        stream->newest_event = event->timestamp;
    }
}

/*
 * Truncate log if needed. If truncated, only `written` is modified
 * returns FLB_TRUE if truncated
 */
static int truncate_log(const struct flb_cloudwatch *ctx, const char *log_buffer,
                         size_t *written) {
    size_t trailing_backslash_count = 0;

    if (*written > MAX_EVENT_LEN) {
        flb_plg_warn(ctx->ins, "[size=%zu] Truncating event which is larger than "
                        "max size allowed by CloudWatch", *written);
        *written = MAX_EVENT_LEN;

        /* remove trailing unescaped backslash if inadvertently synthesized */
        while (trailing_backslash_count < *written &&
                log_buffer[(*written - 1) - trailing_backslash_count] == '\\') {
            trailing_backslash_count++;
        }
        if (trailing_backslash_count % 2 == 1) {
            /* odd number of trailing backslashes, remove unpaired backslash */
            (*written)--;
        }
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/*
 * Helper function to remove keys prefixed with aws_entity
 * from a message pack map
 */
void remove_key_from_nested_map(msgpack_object_map *nested_map, msgpack_packer *pk,
                                int filtered_fields)
{
    const int remaining_kv_pairs = nested_map->size - filtered_fields;
    uint32_t j;

    /* Pack the updated nested map into the packer, skipping keys in the remove list */
    msgpack_pack_map(pk, remaining_kv_pairs);

    for (j = 0; j < nested_map->size; j++) {
        msgpack_object_kv nested_kv = nested_map->ptr[j];

        /* Check if the current key is in the removal list */
        if (nested_kv.key.type == MSGPACK_OBJECT_STR &&
            nested_kv.key.via.str.size > AWS_ENTITY_PREFIX_LEN &&
            strncmp(nested_kv.key.via.str.ptr,
                    AWS_ENTITY_PREFIX, AWS_ENTITY_PREFIX_LEN) == 0) {
            /* Skip the key in the remove list */
            continue;
        }

        /* Pack the remaining key-value pairs into the packer */
        msgpack_pack_object(pk, nested_kv.key);
        msgpack_pack_object(pk, nested_kv.val);
    }
}

/*
 * Main function to remove keys prefixed with aws_entity
 * from the root and nested message pack map
 */
void remove_unneeded_field(msgpack_object *root_map, const char *nested_map_key,
                           msgpack_packer *pk,int root_filtered_fields, int filtered_fields)
{
    uint32_t i;

    if (root_map->type == MSGPACK_OBJECT_MAP) {
        msgpack_object_map root = root_map->via.map;

        /* Prepare to pack the modified root map (size may be unchanged or reduced) */
        msgpack_pack_map(pk, root.size-root_filtered_fields);

        for (i = 0; i < root.size; i++) {
            msgpack_object_kv root_kv = root.ptr[i];

            /* Check if this key matches the nested map key (e.g., "kubernetes") */
            if (filtered_fields > 0 &&
                root_kv.key.type == MSGPACK_OBJECT_STR &&
                strncmp(root_kv.key.via.str.ptr,
                        nested_map_key, root_kv.key.via.str.size) == 0 &&
                root_kv.val.type == MSGPACK_OBJECT_MAP) {

                msgpack_pack_object(pk, root_kv.key);

                remove_key_from_nested_map(&root_kv.val.via.map, pk,filtered_fields);
            }
            else if (root_filtered_fields > 0 &&
                     root_kv.key.type == MSGPACK_OBJECT_STR &&
                     root_kv.key.via.str.size > AWS_ENTITY_PREFIX_LEN &&
                     strncmp(root_kv.key.via.str.ptr,
                             AWS_ENTITY_PREFIX, AWS_ENTITY_PREFIX_LEN) == 0) {
            }
            else {
                msgpack_pack_object(pk, root_kv.key);
                msgpack_pack_object(pk, root_kv.val);
            }
        }
    }
}


/*
 * Processes the msgpack object
 * -1 = failure, record not added
 * 0 = success, record added
 * 1 = we ran out of space, send and retry
 * 2 = record could not be processed, discard it
 * Returns 0 on success, -1 on general errors,
 * and 1 if we ran out of space to write the event
 * which means a send must occur
 */
int process_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                  const msgpack_object *obj, struct flb_time *tms)
{
    size_t written;
    int ret;
    size_t size;
    int offset = 0;
    struct cw_event *event;
    char *tmp_buf_ptr;

    tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
    ret = flb_msgpack_to_json(tmp_buf_ptr,
                                  buf->tmp_buf_size - buf->tmp_buf_offset,
                                  obj);
    if (ret <= 0) {
        /*
         * failure to write to buffer,
         * which means we ran out of space, and must send the logs
         */
        return 1;
    }
    written = (size_t) ret;
    /* Discard empty messages (written == 2 means '""') */
    if (written <= 2) {
        flb_plg_debug(ctx->ins, "Found empty log message");
        return 2;
    }

    /* the json string must be escaped, unless the log_key option is used */
    if (ctx->log_key == NULL) {
        /*
         * check if event_buf is initialized and big enough
         * If all chars need to be hex encoded (impossible), 6x space would be
         * needed
         */
        size = written * 6;
        if (buf->event_buf == NULL || buf->event_buf_size < size) {
            flb_free(buf->event_buf);
            buf->event_buf = flb_malloc(size);
            buf->event_buf_size = size;
            if (buf->event_buf == NULL) {
                flb_errno();
                return -1;
            }
        }
        offset = 0;
        if (!flb_utils_write_str(buf->event_buf, &offset, size,
                                 tmp_buf_ptr, written)) {
            return -1;
        }
        written = offset;

        tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
        if ((buf->tmp_buf_size - buf->tmp_buf_offset) < written) {
            /* not enough space, send logs */
            return 1;
        }

        /* truncate log, if needed */
        truncate_log(ctx, buf->event_buf, &written);

        /* copy serialized json to tmp_buf */
        if (!strncpy(tmp_buf_ptr, buf->event_buf, written)) {
            return -1;
        }
    }
    else {
        /*
         * flb_msgpack_to_json will encase the value in quotes
         * We don't want that for log_key, so we ignore the first
         * and last character
         */
        written -= 2;
        tmp_buf_ptr++; /* pass over the opening quote */
        buf->tmp_buf_offset++; /* advance tmp_buf past opening quote */

        /* truncate log, if needed */
        truncate_log(ctx, tmp_buf_ptr, &written);
    }

    /* add log to events list */
    buf->tmp_buf_offset += written;
    event = &buf->events[buf->event_index];
    event->json = tmp_buf_ptr;
    event->len = written;
    event->timestamp = (unsigned long long) (tms->tm.tv_sec * 1000ull +
                                                tms->tm.tv_nsec/1000000);

    return 0;
}

/* Resets or inits a cw_flush struct */
void reset_flush_buf(struct flb_cloudwatch *ctx, struct cw_flush *buf) {
    buf->event_index = 0;
    buf->tmp_buf_offset = 0;
    buf->event_index = 0;
    buf->data_size = PUT_LOG_EVENTS_HEADER_LEN + PUT_LOG_EVENTS_FOOTER_LEN;
    if (buf->current_stream != NULL) {
        buf->data_size += strlen(buf->current_stream->name);
        buf->data_size += strlen(buf->current_stream->group);
    }
}

/* sorts events, constructs a put payload, and then sends */
int send_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf) {
    int ret;
    int offset;
    int i;
    struct cw_event *event;

    if (buf->event_index <= 0) {
        return 0;
    }

    /* events must be sorted by timestamp in a put payload */
    qsort(buf->events, buf->event_index, sizeof(struct cw_event), compare_events);

retry:
    buf->current_stream->newest_event = 0;
    buf->current_stream->oldest_event = 0;

    offset = 0;
    ret = init_put_payload(ctx, buf, buf->current_stream, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to initialize PutLogEvents payload");
        return -1;
    }

    for (i = 0; i < buf->event_index; i++) {
        event = &buf->events[i];
        ret = write_event(ctx, buf, event, &offset);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write log event %d to "
                          "payload buffer", i);
            return -1;
        }
        if (i != (buf->event_index - 1)) {
            if (!try_to_write(buf->out_buf, &offset, buf->out_buf_size,
                              ",", 1)) {
                flb_plg_error(ctx->ins, "Could not terminate log event with ','");
                return -1;
            }
        }
    }

    ret = end_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not complete PutLogEvents payload");
        return -1;
    }

    flb_plg_debug(ctx->ins, "cloudwatch:PutLogEvents: events=%d, payload=%d bytes", i, offset);
    ret = put_log_events(ctx, buf, buf->current_stream, (size_t) offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to send log events");
        return -1;
    }
    else if (ret > 0) {
        goto retry;
    }

    return 0;
}

 /*
  * Processes the msgpack object, sends the current batch if needed
  * -1 = failure, event not added
  * 0 = success, event added
  * 1 = event been skipped
  * Returns 0 on success, -1 on general errors,
  * and 1 if we found a empty event or a large event.
  */
int add_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
              struct log_stream *stream,
              const msgpack_object *obj, struct flb_time *tms)
{
    int ret;
    struct cw_event *event;
    int retry_add = FLB_FALSE;
    int event_bytes = 0;

    if (buf->event_index > 0 && buf->current_stream != stream) {
        /* we already have events for a different stream, send them first */
        retry_add = FLB_TRUE;
        goto send;
    }

retry_add_event:
    buf->current_stream = stream;
    retry_add = FLB_FALSE;
    if (buf->event_index == 0) {
        /* init */
        reset_flush_buf(ctx, buf);
    }

    ret = process_event(ctx, buf, obj, tms);
    if (ret < 0) {
        return -1;
    }
    else if (ret == 1) {
        if (buf->event_index <= 0) {
            /* somehow the record was larger than our entire request buffer */
            flb_plg_warn(ctx->ins, "Discarding massive log record");
            return 1; /* discard this record and return to caller */
        }
        /* send logs and then retry the add */
        retry_add = FLB_TRUE;
        goto send;
    }
    else if (ret == 2) {
        /*
         * discard this record and return to caller
         * only happens for empty records in this plugin
         */
        return 1;
    }

    event = &buf->events[buf->event_index];
    event_bytes = event->len + PUT_LOG_EVENTS_PER_EVENT_LEN;

    if (check_stream_time_span(stream, event) == FLB_FALSE) {
        /* do not send this event */
        retry_add = FLB_TRUE;
        goto send;
    }

    if ((buf->data_size + event_bytes) > PUT_LOG_EVENTS_PAYLOAD_SIZE) {
        if (buf->event_index <= 0) {
            /* somehow the record was larger than our entire request buffer */
            flb_plg_warn(ctx->ins, "Discarding massive log record");
            return 0; /* discard this record and return to caller */
        }
        /* do not send this event */
        retry_add = FLB_TRUE;
        goto send;
    }

    buf->data_size += event_bytes;
    set_stream_time_span(stream, event);
    buf->event_index++;

    if (buf->event_index == MAX_EVENTS_PER_PUT) {
        goto send;
    }

    /* send is not needed yet, return to caller */
    return 0;

send:
    ret = send_log_events(ctx, buf);
    reset_flush_buf(ctx, buf);
    if (ret < 0) {
        return -1;
    }

    if (retry_add == FLB_TRUE) {
        goto retry_add_event;
    }

    return 0;
}

int should_add_to_emf(struct flb_intermediate_metric *an_item)
{
    /* Valid for cpu plugin */
    if (strncmp(an_item->key.via.str.ptr, "cpu_", 4) == 0
        || strncmp(an_item->key.via.str.ptr, "user_p", 6) == 0
        || strncmp(an_item->key.via.str.ptr, "system_p", 8) == 0) {
        return 1;
    }

    /* Valid for mem plugin */
    if (strncmp(an_item->key.via.str.ptr, "Mem.total", 9) == 0
        || strncmp(an_item->key.via.str.ptr, "Mem.used", 8) == 0
        || strncmp(an_item->key.via.str.ptr, "Mem.free", 8) == 0
        || strncmp(an_item->key.via.str.ptr, "Swap.total", 10) == 0
        || strncmp(an_item->key.via.str.ptr, "Swap.used", 9) == 0
        || strncmp(an_item->key.via.str.ptr, "Swap.free", 9) == 0) {
        return 1;
    }

    return 0;
}

int pack_emf_payload(struct flb_cloudwatch *ctx,
                                       struct mk_list *flb_intermediate_metrics,
                                       const char *input_plugin,
                                       struct flb_time tms,
                                       msgpack_sbuffer *mp_sbuf,
                                       msgpack_unpacked *mp_result,
                                       msgpack_object *emf_payload)
{
    int total_items = mk_list_size(flb_intermediate_metrics) + 1;

    struct mk_list *metric_temp;
    struct mk_list *metric_head;
    struct flb_intermediate_metric *an_item;
    msgpack_unpack_return mp_ret;

    /* Serialize values into the buffer using msgpack_sbuffer_write */
    msgpack_packer mp_pck;
    msgpack_packer_init(&mp_pck, mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&mp_pck, total_items);

    /* Pack the _aws map */
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "_aws", 4);

    msgpack_pack_map(&mp_pck, 2);

    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "Timestamp", 9);
    msgpack_pack_long_long(&mp_pck, tms.tm.tv_sec * 1000L);

    msgpack_pack_str(&mp_pck, 17);
    msgpack_pack_str_body(&mp_pck, "CloudWatchMetrics", 17);
    msgpack_pack_array(&mp_pck, 1);

    msgpack_pack_map(&mp_pck, 3);

    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "Namespace", 9);

    if (ctx->metric_namespace) {
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->metric_namespace));
        msgpack_pack_str_body(&mp_pck, ctx->metric_namespace,
                              flb_sds_len(ctx->metric_namespace));
    }
    else {
        msgpack_pack_str(&mp_pck, 18);
        msgpack_pack_str_body(&mp_pck, "fluent-bit-metrics", 18);
    }

    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "Dimensions", 10);

    struct mk_list *head, *inner_head;
    struct flb_split_entry *dimension_list, *entry;
    struct mk_list *csv_values;
    if (ctx->metric_dimensions) {
        msgpack_pack_array(&mp_pck, mk_list_size(ctx->metric_dimensions));

        mk_list_foreach(head, ctx->metric_dimensions) {
            dimension_list = mk_list_entry(head, struct flb_split_entry, _head);
            csv_values = flb_utils_split(dimension_list->value, ',', 256);
            msgpack_pack_array(&mp_pck, mk_list_size(csv_values));

            mk_list_foreach(inner_head, csv_values) {
                entry = mk_list_entry(inner_head, struct flb_split_entry, _head);
                msgpack_pack_str(&mp_pck, entry->len);
                msgpack_pack_str_body(&mp_pck, entry->value, entry->len);
            }
            flb_utils_split_free(csv_values);
        }
    }
    else {
        msgpack_pack_array(&mp_pck, 0);
    }

    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "Metrics", 7);

    if (strcmp(input_plugin, "cpu") == 0) {
        msgpack_pack_array(&mp_pck, 3);
    }
    else if (strcmp(input_plugin, "mem") == 0) {
        msgpack_pack_array(&mp_pck, 6);
    }
    else {
        msgpack_pack_array(&mp_pck, 0);
    }

    mk_list_foreach_safe(metric_head, metric_temp, flb_intermediate_metrics) {
        an_item = mk_list_entry(metric_head, struct flb_intermediate_metric, _head);
        if (should_add_to_emf(an_item) == 1) {
            msgpack_pack_map(&mp_pck, 2);
            msgpack_pack_str(&mp_pck, 4);
            msgpack_pack_str_body(&mp_pck, "Name", 4);
            msgpack_pack_object(&mp_pck, an_item->key);
            msgpack_pack_str(&mp_pck, 4);
            msgpack_pack_str_body(&mp_pck, "Unit", 4);
            msgpack_pack_str(&mp_pck, strlen(an_item->metric_unit));
            msgpack_pack_str_body(&mp_pck, an_item->metric_unit,
                                  strlen(an_item->metric_unit));
        }
    }

    /* Pack the metric values for each record */
    mk_list_foreach_safe(metric_head, metric_temp, flb_intermediate_metrics) {
        an_item = mk_list_entry(metric_head, struct flb_intermediate_metric, _head);
        msgpack_pack_object(&mp_pck, an_item->key);
        msgpack_pack_object(&mp_pck, an_item->value);
    }

    /*
     * Deserialize the buffer into msgpack_object instance.
     */

    mp_ret = msgpack_unpack_next(mp_result, mp_sbuf->data, mp_sbuf->size, NULL);

    if (mp_ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "msgpack_unpack returned non-success value %i", mp_ret);
        return -1;
    }

    *emf_payload = mp_result->data;
    return 0;
}

static char* find_fallback_environment(struct flb_cloudwatch *ctx, entity *entity)
{
    if(!ctx->add_entity || entity == NULL) {
        return NULL;
    }
    char *fallback_env = NULL;
    int ret;
    /*
     * Possible fallback environments:
     * 1. eks:cluster-name/namespace
     * 2. k8s:cluster-name/namespace
     */
    if (entity->attributes->platform_type != NULL &&
        entity->attributes->cluster_name != NULL &&
        entity->attributes->namespace != NULL) {
        /*
         * Calculate required length
         * Add 3 for ':' '/' and null terminator
         */
        size_t len = strlen(entity->attributes->platform_type) +
                    strlen(entity->attributes->cluster_name) +
                    strlen(entity->attributes->namespace) + 3;

        fallback_env = flb_malloc(len);
        if (!fallback_env) {
            return NULL;
        }

        /* Use snprintf for cross-platform compatibility */
        ret = snprintf(fallback_env, len, "%s:%s/%s",
            entity->attributes->platform_type, entity->attributes->cluster_name,
            entity->attributes->namespace);
        if (ret < 0 || ret >= len) {
            flb_free(fallback_env);
            return NULL;
        }

        return fallback_env;
    }
    return NULL;
}

/*
 * Entity fields can change during stream lifecycle due to service name
 * changes. The found_flag ensures filter_count accurately reflects
 * which fields need filtering, preventing aws_entity fields from remaining
 * in log messages when fallback values are used.
 */
static void set_entity_field(char **field, struct flb_ra_value *val,
                             int *filter_count, int *found_flag)
{
    if (!val || val->type != FLB_RA_STRING) {
        return;
    }
    
    if (found_flag && !*found_flag) {
        if (filter_count) {
            (*filter_count)++;
        }
        (*found_flag)++;
    }
    else if (!found_flag && *field == NULL && filter_count) {
        (*filter_count)++;
    }
    
    if (*field) {
        flb_free(*field);
    }
    
    if (val->storage == FLB_RA_REF) {
        *field = flb_strndup(val->val.ref.buf, val->val.ref.len);
    }
    else {
        *field = flb_strndup(val->val.string, flb_sds_len(val->val.string));
    }
}

void parse_entity(struct flb_cloudwatch *ctx, entity *entity,
                  msgpack_object map, int map_size)
{
    struct flb_record_accessor *ra;
    struct flb_ra_value *val;
    int i;

    struct {
        const char *path;
        char **field;
        int *filter_count;
        int *found_flag;
    } field_map[] = {
        {"$kubernetes['aws_entity_service_name']", &entity->key_attributes->name,
         &entity->filter_count, &entity->service_name_found},
        {"$kubernetes['aws_entity_environment']", &entity->key_attributes->environment,
         &entity->filter_count, &entity->environment_found},
        {"$kubernetes['namespace_name']", &entity->attributes->namespace,
         NULL, NULL},
        {"$kubernetes['host']", &entity->attributes->node, NULL, NULL},
        {"$kubernetes['aws_entity_cluster']", &entity->attributes->cluster_name,
         &entity->filter_count, NULL},
        {"$kubernetes['aws_entity_workload']", &entity->attributes->workload,
         &entity->filter_count, NULL},
        {"$kubernetes['aws_entity_name_source']", &entity->attributes->name_source,
         &entity->filter_count, &entity->name_source_found},
        {"$kubernetes['aws_entity_platform']", &entity->attributes->platform_type,
         &entity->filter_count, NULL},
        {"$aws_entity_ec2_instance_id", &entity->attributes->instance_id,
         &entity->root_filter_count, NULL},
        {"$aws_entity_account_id", &entity->key_attributes->account_id,
         &entity->root_filter_count, NULL},
        {NULL, NULL, NULL, NULL}
    };
    
    for (i = 0; field_map[i].path; i++) {
        ra = flb_ra_create(field_map[i].path, FLB_FALSE);
        if (!ra) {
            continue;
        }
        
        val = flb_ra_get_value_object(ra, map);
        if (val) {
            set_entity_field(field_map[i].field, val, field_map[i].filter_count,
                           field_map[i].found_flag);
            flb_ra_key_value_destroy(val);
        }
        
        flb_ra_destroy(ra);
    }
    
    if (entity->key_attributes->name == NULL &&
        entity->attributes->name_source == NULL &&
        entity->attributes->workload != NULL) {
        entity->key_attributes->name = flb_strndup(entity->attributes->workload,
                                                 strlen(entity->attributes->workload));
        entity->attributes->name_source = flb_strndup("K8sWorkload", 11);
    }
    
    if (entity->key_attributes->environment == NULL) {
        entity->key_attributes->environment = find_fallback_environment(ctx, entity);
    }
}

void update_or_create_entity(struct flb_cloudwatch *ctx, struct log_stream *stream,
                             const msgpack_object map)
{
        if(stream->entity == NULL) {
            stream->entity = flb_malloc(sizeof(entity));
            if (stream->entity == NULL) {
                return;
            }
            memset(stream->entity, 0, sizeof(entity));

            stream->entity->key_attributes = flb_malloc(sizeof(entity_key_attributes));
            if (stream->entity->key_attributes == NULL) {
                flb_free(stream->entity);
                stream->entity = NULL;
                return;
            }
            memset(stream->entity->key_attributes, 0, sizeof(entity_key_attributes));

            stream->entity->attributes = flb_malloc(sizeof(entity_attributes));
            if (stream->entity->attributes == NULL) {
                flb_free(stream->entity->key_attributes);
                flb_free(stream->entity);
                stream->entity = NULL;
                return;
            }
            memset(stream->entity->attributes, 0, sizeof(entity_attributes));
            stream->entity->filter_count = 0;
            stream->entity->root_filter_count = 0;
            stream->entity->service_name_found = 0;
            stream->entity->environment_found = 0;
            stream->entity->name_source_found = 0;
        }
        parse_entity(ctx,stream->entity,map, map.via.map.size);
        if (!stream->entity) {
            flb_plg_warn(ctx->ins, "Failed to generate entity");
        }
}

static int process_log_events(struct flb_cloudwatch *ctx, const char *input_plugin,
                              struct cw_flush *buf, flb_sds_t tag,
                              const char *data, size_t bytes)
{
    int i = 0;
    size_t map_size;
    msgpack_object  map;
    msgpack_object_kv *kv;
    msgpack_object  key;
    msgpack_object  val;
    msgpack_unpacked mp_emf_result;
    msgpack_object emf_payload;
    /* msgpack::sbuffer is a simple buffer implementation. */
    msgpack_sbuffer mp_sbuf;
    /*
     * Msgpack objects used to store msgpack after filtering out fields
     * with aws entity prefix
     */
    msgpack_sbuffer filtered_sbuf;
    msgpack_unpacked modified_unpacked;

    struct log_stream *stream;

    char *key_str = NULL;
    size_t key_str_size = 0;
    int j;
    int ret;
    int check = FLB_FALSE;
    int found = FLB_FALSE;

    /* Added for EMF support */
    struct flb_intermediate_metric *metric;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_intermediate_metric *an_item;

    int intermediate_metric_type;
    char *intermediate_metric_unit;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    if (strncmp(input_plugin, "cpu", 3) == 0) {
        intermediate_metric_type = GAUGE;
        intermediate_metric_unit = PERCENT;
    }
    else if (strncmp(input_plugin, "mem", 3) == 0) {
        intermediate_metric_type = GAUGE;
        intermediate_metric_unit = BYTES;
    }

    /* unpack msgpack */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        /* Get the record/map */
        map = *log_event.body;
        map_size = map.via.map.size;

        if(ctx->kubernete_metadata_enabled && ctx->add_entity) {
            msgpack_sbuffer_init(&filtered_sbuf);
            msgpack_unpacked_init(&modified_unpacked);
        }
        stream = get_log_stream(ctx, tag, map);
        if (!stream) {
            flb_plg_debug(ctx->ins, "Couldn't determine log group & stream for record with tag %s", tag);
            goto error;
        }
        if(ctx->kubernete_metadata_enabled && ctx->add_entity) {
            update_or_create_entity(ctx,stream,map);
            if(stream->entity != NULL &&
               (stream->entity->root_filter_count > 0 ||
               stream->entity->filter_count > 0)) {
                msgpack_packer pk;
                msgpack_packer_init(&pk, &filtered_sbuf, msgpack_sbuffer_write);
                remove_unneeded_field(&map, "kubernetes",&pk,
                       stream->entity->root_filter_count, stream->entity->filter_count);

                size_t modified_offset = 0;
                if (msgpack_unpack_next(&modified_unpacked, filtered_sbuf.data,
                                        filtered_sbuf.size, &modified_offset)) {
                    map = modified_unpacked.data;
                }
            }
        }

        if (ctx->log_key) {
            key_str = NULL;
            key_str_size = 0;
            check = FLB_FALSE;
            found = FLB_FALSE;

            kv = map.via.map.ptr;

            for(j=0; j < map_size; j++) {
                key = (kv+j)->key;
                if (key.type == MSGPACK_OBJECT_BIN) {
                    key_str  = (char *) key.via.bin.ptr;
                    key_str_size = key.via.bin.size;
                    check = FLB_TRUE;
                }
                if (key.type == MSGPACK_OBJECT_STR) {
                    key_str  = (char *) key.via.str.ptr;
                    key_str_size = key.via.str.size;
                    check = FLB_TRUE;
                }

                if (check == FLB_TRUE) {
                    if (strncmp(ctx->log_key, key_str, key_str_size) == 0) {
                        found = FLB_TRUE;
                        val = (kv+j)->val;
                        ret = add_event(ctx, buf, stream, &val,
                                        &log_event.timestamp);
                        if (ret < 0 ) {
                            goto error;
                        }
                    }
                }

            }
            if (found == FLB_FALSE) {
                flb_plg_error(ctx->ins, "Could not find log_key '%s' in record",
                              ctx->log_key);
            }

            if (ret == 0) {
                i++;
            }

            continue;
        }

        if (strncmp(input_plugin, "cpu", 3) == 0
            || strncmp(input_plugin, "mem", 3) == 0) {
            /* Added for EMF support: Construct a list */
            struct mk_list flb_intermediate_metrics;
            mk_list_init(&flb_intermediate_metrics);

            kv = map.via.map.ptr;

            /*
             * Iterate through the record map, extract intermediate metric data,
             * and add to the list.
             */
            for (i = 0; i < map_size; i++) {
                metric = flb_calloc(1, sizeof(struct flb_intermediate_metric));
                if (!metric) {
                    goto error;
                }

                metric->key = (kv + i)->key;
                metric->value = (kv + i)->val;
                metric->metric_type = intermediate_metric_type;
                metric->metric_unit = intermediate_metric_unit;
                metric->timestamp = log_event.timestamp;

                mk_list_add(&metric->_head, &flb_intermediate_metrics);

            }

            /* The msgpack object is only valid during the lifetime of the
             * sbuffer & the unpacked result.
             */
            msgpack_sbuffer_init(&mp_sbuf);
            msgpack_unpacked_init(&mp_emf_result);

            ret = pack_emf_payload(ctx,
                                   &flb_intermediate_metrics,
                                   input_plugin,
                                   log_event.timestamp,
                                   &mp_sbuf,
                                   &mp_emf_result,
                                   &emf_payload);

            /* free the intermediate metric list */

            mk_list_foreach_safe(head, tmp, &flb_intermediate_metrics) {
                an_item = mk_list_entry(head, struct flb_intermediate_metric, _head);
                mk_list_del(&an_item->_head);
                flb_free(an_item);
            }

            if (ret != 0) {
                flb_plg_error(ctx->ins, "Failed to convert EMF metrics to msgpack object. ret=%i", ret);
                msgpack_unpacked_destroy(&mp_emf_result);
                msgpack_sbuffer_destroy(&mp_sbuf);
                goto error;
            }
            ret = add_event(ctx, buf, stream, &emf_payload,
                            &log_event.timestamp);

            msgpack_unpacked_destroy(&mp_emf_result);
            msgpack_sbuffer_destroy(&mp_sbuf);

        } else {
            ret = add_event(ctx, buf, stream, &map,
                            &log_event.timestamp);
        }

        if (ret < 0 ) {
            goto error;
        }

        if (ret == 0) {
            i++;
        }
        if(ctx->kubernete_metadata_enabled && ctx->add_entity) {
            msgpack_sbuffer_destroy(&filtered_sbuf);
            msgpack_unpacked_destroy(&modified_unpacked);
        }
    }
    flb_log_event_decoder_destroy(&log_decoder);

    return i;

error:
    flb_log_event_decoder_destroy(&log_decoder);
    if(ctx->kubernete_metadata_enabled && ctx->add_entity) {
        msgpack_sbuffer_destroy(&filtered_sbuf);
        msgpack_unpacked_destroy(&modified_unpacked);
    }
    return -1;
}


static int process_metric_events(struct flb_cloudwatch *ctx, const char *input_plugin,
                                 struct cw_flush *buf, flb_sds_t tag,
                                 const char *data, size_t bytes)
{
    int i = 0;
    int ret;
    msgpack_object  map;
    msgpack_unpacked mp_emf_result;

    struct log_stream *stream;

    size_t off = 0;
    struct cmt *cmt;
    char *mp_buf = NULL;
    size_t mp_size = 0;
    size_t mp_off = 0;
    struct flb_time tm;

    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) data,
                                            bytes, &off)) == CMT_DECODE_MSGPACK_SUCCESS) {
        ret = cmt_encode_cloudwatch_emf_create(cmt, &mp_buf, &mp_size, CMT_FALSE);
        if (ret < 0) {
            goto cmt_error;
        }

        msgpack_unpacked_init(&mp_emf_result);
        while (msgpack_unpack_next(&mp_emf_result, mp_buf, mp_size, &mp_off) == MSGPACK_UNPACK_SUCCESS) {
            map = mp_emf_result.data;
            if (map.type != MSGPACK_OBJECT_MAP) {
                continue;
            }

            stream = get_log_stream(ctx, tag, map);
            if (!stream) {
                flb_plg_debug(ctx->ins, "Couldn't determine log group & stream for record with tag %s", tag);
                goto cmt_error;
            }

            flb_time_get(&tm);
            ret = add_event(ctx, buf, stream, &map,
                            &tm);

            if (ret < 0 ) {
                goto cmt_error;
            }

            if (ret == 0) {
                i++;
            }
        }
        cmt_encode_cloudwatch_emf_destroy(mp_buf);
        msgpack_unpacked_destroy(&mp_emf_result);
        cmt_destroy(cmt);
    }

    return i;

cmt_error:
    cmt_destroy(cmt);

    return -1;
}

/*
 * Main routine- processes msgpack and sends in batches which ignore the empty ones
 * return value is the number of events processed and send.
 */
int process_and_send(struct flb_cloudwatch *ctx, const char *input_plugin,
                     struct cw_flush *buf, flb_sds_t tag,
                     const char *data, size_t bytes, int event_type)
{
    int ret;
    int i = 0;

    if (event_type == FLB_EVENT_TYPE_LOGS) {
        i = process_log_events(ctx, input_plugin,
                               buf, tag,
                               data, bytes);
    }
    else if (event_type == FLB_EVENT_TYPE_METRICS) {
        i = process_metric_events(ctx, input_plugin,
                                  buf, tag,
                                  data, bytes);
    }
    /* send any remaining events */
    ret = send_log_events(ctx, buf);
    reset_flush_buf(ctx, buf);
    if (ret < 0) {
        return -1;
    }

    /* return number of events */
    return i;
}

struct log_stream *get_or_create_log_stream(struct flb_cloudwatch *ctx,
                                            flb_sds_t stream_name,
                                            flb_sds_t group_name)
{
    int ret;
    struct log_stream *new_stream;
    struct log_stream *stream;
    struct mk_list *tmp;
    struct mk_list *head;
    time_t now;

    /* check if the stream already exists */
    now = time(NULL);
    mk_list_foreach_safe(head, tmp, &ctx->streams) {
        stream = mk_list_entry(head, struct log_stream, _head);
        if (strcmp(stream_name, stream->name) == 0 && strcmp(group_name, stream->group) == 0) {
            return stream;
        }
        else {
            /* check if stream is expired, if so, clean it up */
            if (stream->expiration < now) {
                mk_list_del(&stream->_head);
                log_stream_destroy(stream);
            }
        }
    }

    /* create the new stream */
    new_stream = flb_calloc(1, sizeof(struct log_stream));
    if (!new_stream) {
        flb_errno();
        return NULL;
    }
    new_stream->name = flb_sds_create(stream_name);
    if (new_stream->name == NULL) {
        flb_errno();
        flb_free(new_stream);
        return NULL;
    }
    new_stream->group = flb_sds_create(group_name);
    if (new_stream->group == NULL) {
        flb_errno();
        return NULL;
    }

    ret = create_log_stream(ctx, new_stream, FLB_TRUE);
    if (ret < 0) {
        log_stream_destroy(new_stream);
        return NULL;
    }
    new_stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;

    mk_list_add(&new_stream->_head, &ctx->streams);
    return new_stream;
}

struct log_stream *get_log_stream(struct flb_cloudwatch *ctx, flb_sds_t tag,
                                  const msgpack_object map)
{
    flb_sds_t group_name = NULL;
    flb_sds_t stream_name = NULL;
    flb_sds_t tmp_s = NULL;
    int free_group = FLB_FALSE;
    int free_stream = FLB_FALSE;
    struct log_stream *stream;

    /* templates take priority */
    if (ctx->ra_stream) {
        stream_name = flb_ra_translate_check(ctx->ra_stream, tag, flb_sds_len(tag),
                                             map, NULL, FLB_TRUE);
    }

    if (ctx->ra_group) {
        group_name = flb_ra_translate_check(ctx->ra_group, tag, flb_sds_len(tag),
                                            map, NULL, FLB_TRUE);
    }

    if (stream_name == NULL) {
        if (ctx->stream_name) {
            stream_name = ctx->stream_name;
        } else {
            free_stream = FLB_TRUE;
            /* use log_stream_prefix */
            stream_name = flb_sds_create(ctx->log_stream_prefix);
            if (!stream_name) {
                flb_errno();
                if (group_name) {
                    flb_sds_destroy(group_name);
                }
                return NULL;
            }

            tmp_s = flb_sds_cat(stream_name, tag, flb_sds_len(tag));
            if (!tmp_s) {
                flb_errno();
                flb_sds_destroy(stream_name);
                if (group_name) {
                    flb_sds_destroy(group_name);
                }
                return NULL;
            }
            stream_name = tmp_s;
        }
    } else {
        free_stream = FLB_TRUE;
    }

    if (group_name == NULL) {
        group_name = ctx->group_name;
    } else {
        free_group = FLB_TRUE;
    }

    flb_plg_debug(ctx->ins, "Using stream=%s, group=%s", stream_name, group_name);

    stream = get_or_create_log_stream(ctx, stream_name, group_name);

    if (free_group == FLB_TRUE) {
        flb_sds_destroy(group_name);
    }
    if (free_stream == FLB_TRUE) {
        flb_sds_destroy(stream_name);
    }
    return stream;
}


static int set_log_group_retention(struct flb_cloudwatch *ctx, struct log_stream *stream)
{
    if (ctx->log_retention_days <= 0) {
        /* no need to set */
        return 0;
    }

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;

    flb_plg_info(ctx->ins, "Setting retention policy on log group %s to %dd", stream->group, ctx->log_retention_days);

    body = flb_sds_create_size(68 + strlen(stream->group));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogGroup request body */
    tmp = flb_sds_printf(&body, "{\"logGroupName\":\"%s\",\"retentionInDays\":%d}", stream->group, ctx->log_retention_days);
    if (!tmp) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }
    body = tmp;

    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_PUT_RETENTION_POLICY_ERROR", "PutRetentionPolicy");
    }
    else {
        cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body),
                                              &put_retention_policy_header, 1);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "PutRetentionPolicy http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Set retention policy to %d", ctx->log_retention_days);
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            /* some error occurred; notify user */
            flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                               "PutRetentionPolicy", ctx->ins);
        }
    }

    flb_plg_error(ctx->ins, "Failed to putRetentionPolicy");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);

    return -1;
}

int create_log_group(struct flb_cloudwatch *ctx, struct log_stream *stream)
{
    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;
    int ret;

    flb_plg_info(ctx->ins, "Creating log group %s", stream->group);

    /* construct CreateLogGroup request body */
    if (ctx->log_group_class_type == LOG_CLASS_DEFAULT_TYPE) {
        body = flb_sds_create_size(30 + strlen(stream->group));
        if (!body) {
            flb_sds_destroy(body);
            flb_errno();
            return -1;
        }

        tmp = flb_sds_printf(&body, "{\"logGroupName\":\"%s\"}", stream->group);
        if (!tmp) {
            flb_sds_destroy(body);
            flb_errno();
            return -1;
        }
        body = tmp;
    } else {
        body = flb_sds_create_size(37 + strlen(stream->group) + strlen(ctx->log_group_class));
        if (!body) {
            flb_sds_destroy(body);
            flb_errno();
            return -1;
        }

        tmp = flb_sds_printf(&body, "{\"logGroupName\":\"%s\", \"logGroupClass\":\"%s\"}",
                             stream->group, ctx->log_group_class);
        if (!tmp) {
            flb_sds_destroy(body);
            flb_errno();
            return -1;
        }
        body = tmp;
    }

    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_CREATE_LOG_GROUP_ERROR", "CreateLogGroup");
    }
    else {
        cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body),
                                              &create_group_header, 1);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "CreateLogGroup http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Created log group %s with storage class %s",
                         stream->group, ctx->log_group_class);
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            ret = set_log_group_retention(ctx, stream);
            return ret;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_ALREADY_EXISTS) == 0) {
                    if (ctx->log_group_class_type == LOG_CLASS_INFREQUENT_ACCESS_TYPE) {
                        flb_plg_warn(ctx->ins, "Log Group %s already exists; "
                                     "Fluent Bit did not create this group in this execution. "
                                     "Fluent Bit therefore was unable verify or set %s storage. "
                                     "Check CloudWatch Console or API for the groups storage class status.",
                                     stream->group, LOG_CLASS_INFREQUENT_ACCESS);
                    } else {
                        flb_plg_info(ctx->ins, "Log Group %s already exists",
                                     stream->group);
                    }
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    ret = set_log_group_retention(ctx, stream);
                    return ret;
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "CreateLogGroup", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error can not be parsed, print raw response */
                flb_plg_warn(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to create log group");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

int create_log_stream(struct flb_cloudwatch *ctx, struct log_stream *stream,
                      int can_retry)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;
    int ret;

    flb_plg_info(ctx->ins, "Creating log stream %s in log group %s",
                 stream->name, stream->group);

    body = flb_sds_create_size(50 + strlen(stream->group) +
                               strlen(stream->name));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogStream request body */
    tmp = flb_sds_printf(&body,
                         "{\"logGroupName\":\"%s\",\"logStreamName\":\"%s\"}",
                         stream->group,
                         stream->name);
    if (!tmp) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }
    body = tmp;

    cw_client = ctx->cw_client;
    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_CREATE_LOG_STREAM_ERROR", "CreateLogStream");
    }
    else {
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body),
                                              &create_stream_header, 1);
    }

    if (c) {
        flb_plg_debug(ctx->ins,"CreateLogStream http status=%d",
                      c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Created log stream %s", stream->name);
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_ALREADY_EXISTS) == 0) {
                    flb_plg_info(ctx->ins, "Log Stream %s already exists",
                                 stream->name);
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    return 0;
                }

                if (strcmp(error, ERR_CODE_NOT_FOUND) == 0) {
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);

                    if (ctx->create_group == FLB_TRUE) {
                        flb_plg_info(ctx->ins, "Log Group %s not found. Will attempt to create it.",
                                     stream->group);
                        ret = create_log_group(ctx, stream);
                        if (ret < 0) {
                            return -1;
                        } else {
                            if (can_retry == FLB_TRUE) {
                                /* retry stream creation */
                                return create_log_stream(ctx, stream, FLB_FALSE);
                            } else {
                                /* we failed to create the stream */
                                return -1;
                            }
                        }
                    } else {
                        flb_plg_error(ctx->ins, "Log Group %s not found and `auto_create_group` disabled.",
                                      stream->group);
                    }
                    return -1;
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "CreateLogStream", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error can not be parsed, print raw response */
                flb_plg_warn(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to create log stream");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

/*
 * Returns -1 on failure, 0 on success
 */
int put_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                   struct log_stream *stream, size_t payload_size)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    int num_headers = 1;
    int retry = FLB_TRUE;

    flb_plg_debug(ctx->ins, "Sending log events to log stream %s", stream->name);

    /* stream is being used, update expiration */
    stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;

    if (ctx->log_format != NULL) {
        put_log_events_header[1].val = (char *) ctx->log_format;
        put_log_events_header[1].val_len = strlen(ctx->log_format);
        num_headers = 2;
    }

retry_request:
    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_PUT_LOG_EVENTS_ERROR", "PutLogEvents");
    }
    else {
        cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", buf->out_buf, payload_size,
                                              put_log_events_header, num_headers);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "PutLogEvents http status=%d", c->resp.status);
        flb_plg_debug(ctx->ins, "PutLogEvents http data=%s", c->resp.data);
        flb_plg_debug(ctx->ins, "PutLogEvents http payload=%s", c->resp.payload);

        if (c->resp.status == 200) {
            if (c->resp.data == NULL || c->resp.data_len == 0 || strcasestr(c->resp.data, AMZN_REQUEST_ID_HEADER) == NULL) {
                /* code was 200, but response is invalid, treat as failure */
                if (c->resp.data != NULL && c->resp.data_len > 0) {
                    flb_plg_debug(ctx->ins, "Invalid response: full data: `%.*s`", (int) c->resp.data_len, c->resp.data);
                }
                flb_http_client_destroy(c);

                if (retry == FLB_TRUE) {
                    flb_plg_debug(ctx->ins, "issuing immediate retry for invalid response");
                    retry = FLB_FALSE;
                    goto retry_request;
                }
                flb_plg_error(ctx->ins, "Recieved code 200 but response was invalid, %s header not found",
                                  AMZN_REQUEST_ID_HEADER);
                return -1;
            }

            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                                  "PutLogEvents", ctx->ins);
        }
    }

    flb_plg_error(ctx->ins, "Failed to send log events");
    if (c) {
        flb_http_client_destroy(c);
    }
    return -1;
}


void cw_flush_destroy(struct cw_flush *buf)
{
    if (buf) {
        flb_free(buf->tmp_buf);
        flb_free(buf->out_buf);
        flb_free(buf->events);
        flb_free(buf->event_buf);
        flb_free(buf);
    }
}
