/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023 The Fluent Bit Authors
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

#include <stdint.h>
#include <string.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_mem.h>
#include "flb_fuzz_header.h"

int initialization_crutch()
{
    struct flb_config *config;
    config = flb_config_init();
    if (config == NULL) {
        return -1;
    }
    flb_config_exit(config);
    return 0;
}


void fuzz_sts(const uint8_t *data, size_t size) {
    char *sks_response = get_null_terminated(150, &data, &size);

    struct flb_aws_credentials *creds;
    time_t expiration;

    creds = flb_parse_sts_resp(sks_response, &expiration);
    if (creds != NULL) {
        flb_aws_credentials_destroy(creds);
    }

    if (size > 300) {
        char *action = get_null_terminated(50, &data, &size);
        char *role_arn = get_null_terminated(50, &data, &size);
        char *session_name = get_null_terminated(50, &data, &size);
        char *external_id = get_null_terminated(50, &data, &size);
        char *identity_token = get_null_terminated(50, &data, &size);

        flb_sds_t s1 = flb_sts_uri(action, role_arn, session_name,
                                   external_id, identity_token);
        if (s1 != NULL) {
            flb_sds_destroy(s1);
        }

        flb_free(action);
        flb_free(role_arn);
        flb_free(session_name);
        flb_free(external_id);
        flb_free(identity_token);
    }

    if (sks_response != NULL) {
        flb_free(sks_response);
    }
}


void fuzz_http(const uint8_t *data, size_t size) {
    time_t expiration;
    struct flb_aws_credentials *creds = NULL;
    size_t response_len;

    response_len = (size > 250) ? 250 : size;
    char *response = get_null_terminated(response_len, &data, &size);
    if (response != NULL) {
        creds = flb_parse_http_credentials(response, strlen(response), &expiration);
        if (creds != NULL) {
            flb_aws_credentials_destroy(creds);
        }
        flb_free(response);
    }
}


void fuzz_process(const uint8_t *data, size_t size) {
    char** tokens = NULL;
    char *input = get_null_terminated(250, &data, &size);
    tokens = parse_credential_process(input);
    if (tokens != NULL) {
        flb_free(tokens);
    }
    flb_free(input);
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 304) {
        return 0;
    }
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }
    if (initialization_crutch() == -1) {
        return 0;
    }

    const uint8_t *data_copy = data;
    size_t size_copy = size;
    fuzz_sts(data_copy, size_copy);

    data_copy = data;
    size_copy = size;
    fuzz_http(data_copy, size_copy);

    data_copy = data;
    size_copy = size;
    fuzz_process(data_copy, size_copy);

    return 0;
}
