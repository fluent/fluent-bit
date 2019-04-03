/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include "./pulsar_config.h"

#include "../../include/fluent-bit/flb_utils.h"
#include <pulsar/c/authentication.h>

#include <ctype.h>

static pulsar_compression_type convert_compression_setting_to_pulsar_enum(char
                                                                          const
                                                                          *const
                                                                          value);

pulsar_producer_configuration_t
    *
flb_pulsar_config_producer_config_create(struct flb_output_instance *const
                                         ins)
{
    pulsar_producer_configuration_t *cfg =
        pulsar_producer_configuration_create();

    if (!cfg) {
        return NULL;
    }

    char *producer_name = flb_output_get_property("producer_name", ins);
    if (producer_name) {
        pulsar_producer_configuration_set_producer_name(cfg, producer_name);
    }

    char *send_timeout = flb_output_get_property("send_timeout", ins);
    if (send_timeout) {
        int timeout = atoi(send_timeout);
        pulsar_producer_configuration_set_send_timeout(cfg, timeout);
    }

    char *compression_type = flb_output_get_property("compression_type", ins);
    pulsar_producer_configuration_set_compression_type
        (cfg, convert_compression_setting_to_pulsar_enum(compression_type));

    char *max_pending_messages =
        flb_output_get_property("max_pending_messages", ins);
    if (max_pending_messages) {
        int value = atoi(max_pending_messages);
        pulsar_producer_configuration_set_max_pending_messages(cfg, value);
    }

    char *batching_enabled = flb_output_get_property("batching_enabled", ins);
    if (batching_enabled) {
        int value = flb_utils_bool(batching_enabled);
        pulsar_producer_configuration_set_batching_enabled(cfg, value);
    }
    else {
        // Default to batching enabled
        pulsar_producer_configuration_set_batching_enabled(cfg, 1);
    }

    char *batching_timeout =
        flb_output_get_property("batching_max_publish_delay_ms", ins);
    if (batching_timeout) {
        int value = atoi(batching_timeout);
        pulsar_producer_configuration_set_batching_max_publish_delay_ms(cfg,
                                                                        value);
    } else {
        // Default to 100ms
        pulsar_producer_configuration_set_batching_max_publish_delay_ms(cfg,
                                                                        100);
    }

    pulsar_producer_configuration_set_block_if_queue_full(cfg, 1);

    return cfg;
}

static char *normalize_auth_method(char *const value);

static void log_pulsar_msg(pulsar_logger_level_t level,
                           const char *file,
                           int line, const char *msg, void *ctx);

pulsar_client_configuration_t *flb_pulsar_config_client_config_create(struct
                                                                      flb_output_instance
                                                                      *const
                                                                      ins)
{
    pulsar_client_configuration_t *cfg = pulsar_client_configuration_create();

    if (!cfg) {
        return NULL;
    }

    pulsar_client_configuration_set_logger(cfg, &log_pulsar_msg, NULL);

    char *config_auth_method = flb_output_get_property("auth_method", ins);
    char *auth_method = normalize_auth_method(config_auth_method);

    if (auth_method) {
        char *auth_params = flb_output_get_property("auth_params", ins);
        if (!auth_params) {
            flb_warn
                ("[out_pulsar] Auth_Method is set (%s) but no Auth_Params were provided, using empty string.",
                 auth_method);
            auth_params = "";
        }

        pulsar_authentication_t *auth =
            pulsar_authentication_create(auth_method, auth_params);
        if (!auth) {
            flb_error
                ("[out_pulsar] Failed to create client authentication policy (method: %s, params: %s)",
                 auth_method, auth_params);
            pulsar_client_configuration_free(cfg);
            return NULL;
        }

        pulsar_client_configuration_set_auth(cfg, auth);
    }

    if (ins->use_tls) {
        pulsar_client_configuration_set_use_tls(cfg, 1);
        pulsar_client_configuration_set_tls_allow_insecure_connection(cfg,
                                                                      !ins->tls_verify);
        if (ins->tls_ca_file) {
            pulsar_client_configuration_set_tls_trust_certs_file_path(cfg,
                                                                      ins->tls_ca_file);
        }
    }

    return cfg;

}

void flb_pulsar_config_producer_config_destroy(pulsar_producer_configuration_t
                                               * cfg)
{
    if (cfg) {
        pulsar_producer_configuration_free(cfg);
    }
}

void flb_pulsar_config_client_config_destroy(pulsar_client_configuration_t *
                                             cfg)
{
    if (cfg) {
        pulsar_client_configuration_free(cfg);
    }
}


static pulsar_compression_type convert_compression_setting_to_pulsar_enum(char
                                                                          const
                                                                          *const
                                                                          value)
{
    pulsar_compression_type result = pulsar_CompressionLZ4;

    if (!value) {
        return result;
    }

    if (strcasecmp(value, "none") == 0) {
        result = pulsar_CompressionNone;
    }
    else if (strcasecmp(value, "zlib") == 0) {
        result = pulsar_CompressionZLib;
    }
    else if (strcasecmp(value, "lz4") != 0) {
        flb_warn
            ("[out_pulsar] Invalid compression_type %s; defaulting to LZ4",
             value);
    }

    return result;
}

static char *normalize_auth_method(char *const value)
{
    if (!(value && strcasecmp(value, "none"))) {
        return NULL;
    }

    for (char *ch = value; ch < value + strlen(value); ++ch) {
        *ch = tolower(*ch);
    }

    return value;
}

static void log_pulsar_msg(pulsar_logger_level_t level,
                           const char *file,
                           int line, const char *msg, void *unused)
{
#if FLB_LOG_DEBUG == 4 && FLB_LOG_ERROR == 1
    int flb_log_level = FLB_LOG_DEBUG - level;
#else
#error "log_pulsar_msg: Log level conversion code expectations unmet."
#endif

    if (flb_log_check(flb_log_level)) {
        flb_log_print(flb_log_level, file, line, msg);
    }
}
