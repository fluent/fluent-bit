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

#ifndef FLB_CALYPTIA_H
#define FLB_CALYPTIA_H

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
    int register_retry_on_flush;          /* retry registration on flush if failed */
    int fleet_config_legacy_format;       /* Fleet config format to use: INI (true) or YAML (false) */
};

int set_fleet_input_properties(struct calyptia *ctx, struct flb_input_instance *fleet);
flb_sds_t agent_config_filename(struct calyptia *ctx, char *fname);
flb_sds_t get_machine_id(struct calyptia *ctx);

/* These are unique to the agent rather than the fleet */
#define machine_id_fleet_config_filename(a) agent_config_filename((a), "machine-id")

#endif /* FLB_CALYPTIA_H */
