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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <monkey/mk_core/mk_list.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/aws/flb_aws_error_reporter.h>

/* helper function to get int type environment variable*/
static int getenv_int(const char *name) {
    char *value, *end;
    long result;

    value = getenv(name);
    if (!value) {
        return 0;
    }

    result = strtol(value, &end, 10);
    if (*end != '\0') {
        return 0;
    }
    return (int) result;
}

/* create an error reporter*/
struct flb_aws_error_reporter *flb_aws_error_reporter_create()
{
    char *path_var = NULL;
    int ttl_var, status_message_length;
    struct flb_aws_error_reporter *error_reporter;
    FILE *f;
    int ret;

    error_reporter = flb_calloc(1, sizeof(struct flb_aws_error_reporter));
    if (!error_reporter) {
        flb_errno();
        return NULL;
    }

    /* setup error report file path */
    path_var = getenv(STATUS_MESSAGE_FILE_PATH_ENV);
    if (path_var == NULL) {
        flb_free(error_reporter);
        flb_errno();
        return NULL;
    }

    error_reporter->file_path = flb_sds_create(path_var);
    if (!error_reporter->file_path) {
        flb_free(error_reporter);
        flb_errno();
        return NULL;
    }

    /* clean up existing file*/
    if ((f = fopen(error_reporter->file_path, "r")) != NULL) {
        /* file exist, try delete it*/
        if (remove(error_reporter->file_path)) {
            flb_free(error_reporter);
            flb_errno();
            return NULL;
        }
    }

    /* setup error reporter message TTL */
    ttl_var = getenv_int(STATUS_MESSAGE_TTL_ENV);
    if (ttl_var <= 0) {
        ttl_var = STATUS_MESSAGE_TTL_DEFAULT;
    }
    error_reporter->ttl = ttl_var;

    /* setup error reporter file size */
    status_message_length = getenv_int(STATUS_MESSAGE_MAX_BYTE_LENGTH_ENV);
    if(status_message_length <= 0) {
        status_message_length = STATUS_MESSAGE_MAX_BYTE_LENGTH_DEFAULT;
    }
    error_reporter->max_size = status_message_length;

    /* create the message Linked Lists */
    mk_list_init(&error_reporter->messages);

    return error_reporter;
}

/* error reporter write the error message into reporting file and memory*/
int flb_aws_error_reporter_write(struct flb_aws_error_reporter *error_reporter, char *msg)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_error_message *message;
    struct flb_error_message *tmp_message;
    flb_sds_t buf;
    flb_sds_t buf_tmp;
    int deleted_message_count = 0;
    FILE *f;

    if (error_reporter == NULL) {
        return -1;
    }

    buf = flb_sds_create(msg);
    if (!buf) {
        flb_errno();
        return -1;
    }
    /* check if the message is the same with latest one in queue*/
    if (mk_list_is_empty(&error_reporter->messages) != 0) {
        tmp_message = mk_list_entry_last(&error_reporter->messages,
                                         struct flb_error_message, _head);
        if (tmp_message->len == flb_sds_len(buf) &&
                flb_sds_cmp(tmp_message->data, buf, tmp_message->len) == 0) {

            tmp_message->timestamp = time(NULL);
            flb_sds_destroy(buf);
            return 0;
        }
    }

    message = flb_malloc(sizeof(struct flb_error_message));
    if (!message) {
        flb_sds_destroy(buf);
        flb_errno();
        return -1;
    }

    /* check if new message is too large and truncate*/
    if (flb_sds_len(buf) > error_reporter->max_size) {
        // truncate message
        buf_tmp = flb_sds_copy(buf, msg, error_reporter->max_size);
        if (!buf_tmp) {
            flb_sds_destroy(buf);
            flb_free(message);
            return -1;
        }
    }

    message->data = flb_sds_create(buf);
    if (!message->data) {
        flb_sds_destroy(buf);
        flb_free(message);
        return -1;
    }

    message->len = flb_sds_len(buf);

   /* clean up old message to provide enough space for new message*/
    mk_list_foreach_safe(head, tmp, &error_reporter->messages) {
        tmp_message = mk_list_entry(head, struct flb_error_message, _head);
        if (error_reporter->file_size + flb_sds_len(buf) <= error_reporter->max_size) {
            break;
        }
        else {
            error_reporter->file_size -= tmp_message->len;
            deleted_message_count++;
            mk_list_del(&tmp_message->_head);
            flb_sds_destroy(tmp_message->data);
            flb_free(tmp_message);
        }
    }
    message->timestamp = time(NULL);

    mk_list_add(&message->_head, &error_reporter->messages);
    error_reporter->file_size += message->len;

    if (deleted_message_count == 0) {
        f = fopen(error_reporter->file_path, "a");
        fprintf(f, message->data);
    }
    else {
        f = fopen(error_reporter->file_path, "w");
        mk_list_foreach_safe(head, tmp, &error_reporter->messages) {
            tmp_message = mk_list_entry(head, struct flb_error_message, _head);
            fprintf(f, tmp_message->data);
        }
    }
    fclose(f);

    flb_sds_destroy(buf);

    return 0;

}

/* error reporter clean up the expired message based on TTL*/
void flb_aws_error_reporter_clean(struct flb_aws_error_reporter *error_reporter)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_error_message *message;
    int expired_message_count = 0;
    FILE *f;

    if (error_reporter == NULL) {
        return;
    }

    /* check the timestamp for every message and clean up expired messages*/
    mk_list_foreach_safe(head, tmp, &error_reporter->messages) {
        message = mk_list_entry(head, struct flb_error_message, _head);
        if (error_reporter->ttl > time(NULL) - message->timestamp) {
            break;
        }
        error_reporter->file_size -= message->len;
        mk_list_del(&message->_head);
        flb_sds_destroy(message->data);
        flb_free(message);
        expired_message_count++;
    }

    /* rewrite error report file if any message is cleaned up*/
    if (expired_message_count > 0) {
        f = fopen(error_reporter->file_path, "w");
        mk_list_foreach_safe(head, tmp, &error_reporter->messages) {
            message = mk_list_entry(head, struct flb_error_message, _head);
            fprintf(f, message->data);
        }
        fclose(f);
    }
}

/* error reporter clean up when fluent bit shutdown*/
void flb_aws_error_reporter_destroy(struct flb_aws_error_reporter *error_reporter)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_error_message *message;

    if (error_reporter == NULL) {
        return;
    }

    if(error_reporter->file_path) {
        flb_sds_destroy(error_reporter->file_path);
    }
    if (mk_list_is_empty(&error_reporter->messages) != 0) {

        mk_list_foreach_safe(head, tmp, &error_reporter->messages) {
           message = mk_list_entry(head, struct flb_error_message, _head);
           mk_list_del(&message->_head);
           flb_sds_destroy(message->data);
           flb_free(message);
        }
        mk_list_del(&error_reporter->messages);
    }

    flb_free(error_reporter);
}

/*check if system enable error reporting*/
int is_error_reporting_enabled()
{
    return getenv(STATUS_MESSAGE_FILE_PATH_ENV) != NULL;
}