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

#ifndef FLB_IN_CALYPTIA_FLEET_H
#define FLB_IN_CALYPTIA_FLEET_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_reload.h>

struct flb_in_calyptia_fleet_config {
    /* Time interval check */
    int interval_sec;
    int interval_nsec;

    /* maximum http buffer size */
    int max_http_buffer_size;

    /* Grabbed from the cfg_path, used to check if configuration has
     * has been updated.
     */
    long config_timestamp;

    flb_sds_t api_key;

    flb_sds_t fleet_id;

    /* flag used to mark fleet_id for release when found automatically. */
    int fleet_id_found;

    flb_sds_t fleet_name;
    flb_sds_t machine_id;
    flb_sds_t config_dir;
    flb_sds_t cloud_host;
    flb_sds_t cloud_port;

    flb_sds_t fleet_url;
    flb_sds_t fleet_files_url;

    /* whether to use legacy INI/TOML or YAML format */
    int fleet_config_legacy_format;

    struct flb_input_instance *ins;       /* plugin instance */

    /* Networking */
    struct flb_upstream *u;

    int collect_fd;
};

struct reload_ctx {
    flb_ctx_t *flb;
    flb_sds_t cfg_path;
};

flb_sds_t fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx, char *fname);

#define new_fleet_config_filename(a) fleet_config_filename((a), "new")
#define cur_fleet_config_filename(a) fleet_config_filename((a), "cur")
#define old_fleet_config_filename(a) fleet_config_filename((a), "old")
#define hdr_fleet_config_filename(a) fleet_config_filename((a), "header")

int get_calyptia_fleet_config(struct flb_in_calyptia_fleet_config *ctx);

#endif /* FLB_IN_CALYPTIA_FLEET_H */
