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

#ifndef FLB_CALYPTIA_H
#define FLB_CALYPTIA_H

#include <fluent-bit/flb_utils.h>
#include <stdbool.h>

struct calyptia {
    /* config map options */
    flb_sds_t api_key;
    flb_sds_t store_path;
    flb_sds_t cloud_host;
    flb_sds_t cloud_port;
    flb_sds_t machine_id;
    int machine_id_auto_configured;

/* used for reporting chunk trace records. */
#ifdef FLB_HAVE_CHUNK_TRACE
    flb_sds_t pipeline_id;
#endif /* FLB_HAVE_CHUNK_TRACE */

    int cloud_tls;
    int cloud_tls_verify;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /* instances */
    struct flb_input_instance *i;
    struct flb_output_instance *o;
    struct flb_input_instance *fleet;
    struct flb_custom_instance *ins;

    /* Fleet configuration */
    flb_sds_t fleet_id;                   /* fleet-id  */
    flb_sds_t fleet_name;
    flb_sds_t fleet_config_dir;           /* fleet configuration directory */
    flb_sds_t fleet_max_http_buffer_size;
    flb_sds_t fleet_interval_sec;
    flb_sds_t fleet_interval_nsec;
    bool register_retry_on_flush;   /* retry registration on flush if failed */
};

int set_fleet_input_properties(struct calyptia *ctx, struct flb_input_instance *fleet);
static flb_sds_t agent_config_filename(struct calyptia *ctx, char *fname);

/* These are unique to the agent rather than the fleet */
#define machine_id_fleet_config_filename(a) agent_config_filename((a), "machine-id")

/* Function wrappers to enable mocking for unit test filesystem access */
int (*flb_access)(const char *pathname, int mode) = access;
int (*flb_open)(const char *pathname, int flags, ...) = open;
ssize_t (*flb_write)(int fd, const void *buf, size_t count) = write;
int (*flb_close)(int fd) = close;
int (*flb_utils_read_file_wrapper)(char *path, char **out_buf, size_t *out_size) = flb_utils_read_file;

#endif /* FLB_CALYPTIA_H */
