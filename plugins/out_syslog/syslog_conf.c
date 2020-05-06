/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_kv.h>

#include "syslog_conf.h"

struct flb_syslog *flb_syslog_config_create(struct flb_output_instance *ins,
                                            struct flb_config *config)
{
    struct mk_list *head;
    struct flb_kv *prop;
    const char *tmp;
    struct flb_syslog *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->mode = FLB_SYSLOG_UDP;
    ctx->format = FLB_SYSLOG_RFC5424;
    ctx->maxsize = -1;

    /* Config Mode */
    tmp = flb_output_get_property("mode", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "tcp")) {
            ctx->mode = FLB_SYSLOG_TCP;
        }
        else if (!strcasecmp(tmp, "tls")) {
            ctx->mode = FLB_SYSLOG_TLS;
        }
        else if (!strcasecmp(tmp, "udp")) {
            ctx->mode = FLB_SYSLOG_UDP;
        }
        else {
            flb_plg_error(ctx->ins, "unknown syslog mode %s", tmp);
            goto clean;
        }
    }

    mk_list_foreach(head, &ins->properties) {
        prop = mk_list_entry(head, struct flb_kv, _head);

        if (strncasecmp(prop->key, "syslog_", 7) != 0) {
            continue;
        }

        if (!strcasecmp(prop->key, "syslog_format")) {
            if (!strcasecmp(prop->val, "rfc3164")) {
                ctx->format = FLB_SYSLOG_RFC3164;
            }
            else if (!strcasecmp(prop->val, "rfc5424")) {
                ctx->format = FLB_SYSLOG_RFC5424;
            }
            else {
                flb_plg_error(ctx->ins, "unknown syslog format %s", prop->val);
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_maxsize")) {
            if (ctx->maxsize > 0) {
                if (atoi(prop->val) > 0) {
                    ctx->maxsize = atoi(prop->val);
                }
                else {
                    flb_plg_error(ctx->ins, "syslog_maxsize must be > 0");
                    goto clean;
                }
            }
            else {
                flb_plg_error(ctx->ins, "syslog_maxsize already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_severity_key")) {
            if (ctx->severity_key == NULL) {
                ctx->severity_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_severity_key already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_facility_key")) {
            if (ctx->facility_key == NULL) {
                ctx->facility_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_facility_key already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_hostname_key")) {
            if (ctx->hostname_key == NULL) {
                ctx->hostname_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_hostname_key already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_appname_key")) {
            if (ctx->appname_key == NULL) {
                ctx->appname_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_appname_key already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_procid_key")) {
            if (ctx->procid_key == NULL) {
                ctx->procid_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_procid_key already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_msgid_key")) {
            if (ctx->msgid_key == NULL) {
                ctx->msgid_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_msgid_key already defined");
                goto clean;
            }
        }
        else if (!strcasecmp(prop->key, "syslog_sd_key")) {
            flb_sds_t *ftmp;
            ftmp = flb_realloc(ctx->sd_key, sizeof(flb_sds_t) * (ctx->nsd+1));
            if (ftmp == NULL) {
                flb_errno();
                goto clean;
            }
            ctx->sd_key = ftmp;
            ctx->sd_key[ctx->nsd] = flb_sds_create(prop->val);
            ctx->nsd++;
        }
        else if (!strcasecmp(prop->key, "syslog_message_key")) {
            if (ctx->message_key == NULL) {
                ctx->message_key = flb_sds_create(prop->val);
            }
            else {
                flb_plg_error(ctx->ins, "syslog_message_key already defined");
                goto clean;
            }
        }
    }

    return ctx;

clean:
    flb_syslog_config_destroy(ctx);
    return NULL;
}

void flb_syslog_config_destroy(struct flb_syslog *ctx)
{
    flb_sds_destroy(ctx->severity_key);
    flb_sds_destroy(ctx->facility_key);
    flb_sds_destroy(ctx->hostname_key);
    flb_sds_destroy(ctx->appname_key);
    flb_sds_destroy(ctx->procid_key);
    flb_sds_destroy(ctx->msgid_key);
    flb_sds_destroy(ctx->message_key);

    flb_free(ctx->sd_key);
    flb_free(ctx);
}
