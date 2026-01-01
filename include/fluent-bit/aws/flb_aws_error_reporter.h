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

#ifdef FLB_HAVE_AWS_ERROR_REPORTER

#ifndef FLB_AWS_ERROR_REPORTER_H
#define FLB_AWS_ERROR_REPORTER_H

#include <monkey/mk_core/mk_list.h>
#include <fluent-bit/flb_sds.h>

#include <time.h>

#define STATUS_MESSAGE_FILE_PATH_ENV "STATUS_MESSAGE_FILE_PATH"
#define STATUS_MESSAGE_TTL_ENV "STATUS_MESSAGE_TTL"
#define STATUS_MESSAGE_MAX_BYTE_LENGTH_ENV "STATUS_MESSAGE_MAX_BYTE_LENGTH"
#define STATUS_MESSAGE_TTL_DEFAULT 20
#define STATUS_MESSAGE_MAX_BYTE_LENGTH_DEFAULT 1024

/*
* error reporter
*/
struct flb_aws_error_reporter {
    flb_sds_t file_path;
    int ttl;
    int file_size;
    struct mk_list messages;
    int max_size;
};

/*
* error message which saved in memory
*/
struct flb_error_message {
    time_t timestamp;
    flb_sds_t data;
    size_t len;
    struct mk_list _head;
};

/*
* create aws error reporter
*/
struct flb_aws_error_reporter *flb_aws_error_reporter_create();

/*
* error reporter write error log to file
*/
int flb_aws_error_reporter_write(struct flb_aws_error_reporter *error_reporter,
                                 char *msg);

/*
* clean up the expired error message inside error log local file
*/
void flb_aws_error_reporter_clean(struct flb_aws_error_reporter *error_reporter);

/*
* clean up error reporter resource when fluent bit shutdown
*/
void flb_aws_error_reporter_destroy(struct flb_aws_error_reporter *error_reporter);

/*
* function used to tell if error reporting feature is enabled or not
*/
int is_error_reporting_enabled();

#endif
#endif /* FLB_HAVE_AWS_ERROR_REPORTER */