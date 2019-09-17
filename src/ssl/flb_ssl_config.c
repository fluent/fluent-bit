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

#include <fluent-bit/ssl/flb_ssl.h>
#include <fluent-bit/flb_mem.h>
#include "flb_ssl_internal.h"

struct flb_ssl_config *flb_ssl_config_new(void)
{
    struct flb_ssl_config *config;

    config = flb_calloc(1, sizeof(struct flb_ssl_config));
    if (config == NULL) {
        return NULL;
    }

    flb_ssl_config_set_verify(config);
    flb_ssl_config_set_nodebug(config);

    return config;
}

void flb_ssl_config_free(struct flb_ssl_config *config)
{
    if (config == NULL) {
        return;
    }
    flb_free(config);
}

void flb_ssl_config_set_verify(struct flb_ssl_config *config)
{
    config->verify = 1;
}

void flb_ssl_config_set_insecure_noverify(struct flb_ssl_config *config)
{
    config->verify = 0;
}

void flb_ssl_config_set_verify_client(struct flb_ssl_config *config)
{
    config->verify_client = 1;
}

void flb_ssl_config_set_noverify_client(struct flb_ssl_config *config)
{
    config->verify_client = 0;
}

void flb_ssl_config_set_debug(struct flb_ssl_config *config)
{
    config->debug = 5;
}

void flb_ssl_config_set_nodebug(struct flb_ssl_config *config)
{
    config->debug = -1;
}

void flb_ssl_config_set_ca_path(struct flb_ssl_config *config,
                                const char *path)
{
    config->ca_path = path;
}

void flb_ssl_config_set_ca_file(struct flb_ssl_config *config,
                                const char *file)
{
    config->ca_file = file;
}

void flb_ssl_config_set_cert_file(struct flb_ssl_config *config,
                                  const char *file)
{
    config->cert_file = file;
}

void flb_ssl_config_set_key_file(struct flb_ssl_config *config,
                                 const char *file,
                                 const char *passwd)
{
    config->key_file = file;
    config->key_passwd = passwd;
}
