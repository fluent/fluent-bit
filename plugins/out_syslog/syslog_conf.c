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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <fluent-bit/flb_utils.h>

#include <monkey/mk_core.h>

#include "syslog_conf.h"

static int is_valid_severity(struct flb_output_instance *ins, int val, int format)
{
    if (format != FLB_SYSLOG_RFC5424 && format != FLB_SYSLOG_RFC3164) {
        flb_plg_error(ins, "[%s] unknown syslog format.", __FUNCTION__);
        return -1;
    }

    if (ins == NULL) {
        flb_plg_error(ins, "[%s] arg is null. ins=%p", __FUNCTION__, ins);
        return -1;
    }
    if (val < 0 || val > 7) {
        flb_plg_error(ins, "[%s] invalid severity level %d. It should be 0-7.", __FUNCTION__, val);
        return -1;
    }

    return 0;
}

static int is_valid_facility(struct flb_output_instance *ins, int val, int format)
{
    if (format != FLB_SYSLOG_RFC5424 && format != FLB_SYSLOG_RFC3164) {
        flb_plg_error(ins, "[%s] unknown syslog format.", __FUNCTION__);
        return -1;
    }

    if (ins == NULL) {
        flb_plg_error(ins, "[%s] arg is null. ins=%p", __FUNCTION__, ins);
        return -1;
    }

    if (val < 0 || val > 23) {
        flb_plg_error(ins, "[%s] invalid facility level %d. It should be 0-23.", __FUNCTION__, val);
        return -1;
    }
    return 0;
}

static inline void syslog_normalize_cat(struct flb_ra_parser *rp, flb_sds_t *name)
{
    int sub;
    int len;
    char tmp[64];
    struct mk_list *s_head;
    struct flb_ra_key *key;
    struct flb_ra_subentry *entry;

    /* Iterate record accessor keys */
    key = rp->key;
    if (rp->type == FLB_RA_PARSER_STRING) {
        flb_sds_cat_safe(name, key->name, flb_sds_len(key->name));
    }
    else if (rp->type == FLB_RA_PARSER_KEYMAP) {
        flb_sds_cat_safe(name, key->name, flb_sds_len(key->name));
        if (mk_list_size(key->subkeys) > 0) {
            flb_sds_cat_safe(name, ".", 1);
        }

        sub = 0;
        mk_list_foreach(s_head, key->subkeys) {
            entry = mk_list_entry(s_head, struct flb_ra_subentry, _head);

            if (sub > 0) {
                flb_sds_cat_safe(name, ".", 1);
            }
            if (entry->type == FLB_RA_PARSER_STRING) {
                flb_sds_cat_safe(name, entry->str, flb_sds_len(entry->str));
            }
            else if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
                len = snprintf(tmp, sizeof(tmp) -1, "%d",
                               entry->array_id);
                flb_sds_cat_safe(name, tmp, len);
            }
            sub++;
        }
    }
}

static flb_sds_t syslog_normalize_ra_key_name(struct flb_record_accessor *ra)
{
    int c = 0;
    flb_sds_t name;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    name = flb_sds_create_size(flb_sds_len(ra->pattern));
    if (!name) {
        return NULL;
    }

    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (c > 0) {
            flb_sds_cat_safe(&name, ".", 1);
        }
        syslog_normalize_cat(rp, &name);
        c++;
    }

    return name;
}

struct flb_syslog *flb_syslog_config_create(struct flb_output_instance *ins,
                                            struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct flb_syslog *ctx = NULL;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_syslog_sd_key *sk_key_ra;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->parsed_mode = FLB_SYSLOG_UDP;
    ctx->parsed_format = FLB_SYSLOG_RFC5424;
    ctx->maxsize = -1;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        goto error;
    }

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Config Mode */
    tmp = flb_output_get_property("mode", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "tcp")) {
            ctx->parsed_mode = FLB_SYSLOG_TCP;
        }
        else if (!strcasecmp(tmp, "tls")) {
            ctx->parsed_mode = FLB_SYSLOG_TLS;
        }
        else if (!strcasecmp(tmp, "udp")) {
            ctx->parsed_mode = FLB_SYSLOG_UDP;
        }
        else {
            flb_plg_error(ctx->ins, "unknown syslog mode %s", tmp);
            goto error;
        }
    }

    /* syslog_format */
    tmp = flb_output_get_property("syslog_format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "rfc3164") == 0) {
            ctx->parsed_format = FLB_SYSLOG_RFC3164;
        }
        else if (strcasecmp(tmp, "rfc5424") == 0) {
            ctx->parsed_format = FLB_SYSLOG_RFC5424;
        }
        else {
            flb_plg_error(ctx->ins, "unknown syslog format %s", tmp);
            goto error;
        }
    }

    if (ctx->parsed_format == FLB_SYSLOG_RFC5424 && ctx->allow_longer_sd_id == FLB_TRUE) {
        flb_plg_warn(ctx->ins, "Allow longer SD-ID. It may violate RFC5424.");
    }

    /* validate preset values */
    ret = is_valid_severity(ctx->ins, ctx->severity_preset, ctx->parsed_format);
    if (ret != 0) {
        goto error;
    }

    ret = is_valid_facility(ctx->ins, ctx->facility_preset, ctx->parsed_format);
    if (ret != 0) {
        goto error;
    }


    /* syslog maxsize */
    if (ctx->maxsize <= 0) {
        if (ctx->parsed_format == FLB_SYSLOG_RFC3164) {
            ctx->maxsize = 1024;
        }
        else if (ctx->parsed_format == FLB_SYSLOG_RFC5424) {
            ctx->maxsize = 2048;
        }
    }

    if (ctx->severity_key) {
        ctx->ra_severity_key = flb_ra_create(ctx->severity_key, FLB_FALSE);
        if (ctx->ra_severity_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Severity Key");
            goto error;
        }
    }

    if (ctx->facility_key) {
        ctx->ra_facility_key = flb_ra_create(ctx->facility_key, FLB_FALSE);
        if (ctx->ra_facility_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Facility Key");
            goto error;
        }
    }

    if (ctx->hostname_key) {
        ctx->ra_hostname_key = flb_ra_create(ctx->hostname_key, FLB_FALSE);
        if (ctx->ra_hostname_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Hostname Key");
            goto error;
        }
    }

    if (ctx->appname_key) {
        ctx->ra_appname_key = flb_ra_create(ctx->appname_key, FLB_FALSE);
        if (ctx->ra_appname_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Appname Key");
            goto error;
        }
    }

    if (ctx->procid_key) {
        ctx->ra_procid_key = flb_ra_create(ctx->procid_key, FLB_FALSE);
        if (ctx->ra_procid_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Procid Key");
            goto error;
        }
    }

    if (ctx->msgid_key) {
        ctx->ra_msgid_key = flb_ra_create(ctx->msgid_key, FLB_FALSE);
        if (ctx->ra_msgid_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Msgid Key");
            goto error;
        }
    }

    if (ctx->message_key) {
        ctx->ra_message_key = flb_ra_create(ctx->message_key, FLB_FALSE);
        if (ctx->ra_message_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Message Key");
            goto error;
        }
    }

    if (ctx->sd_keys) {
        /* Initialize sd_keys RAs */
        ctx->ra_sd_keys = flb_malloc(sizeof(struct mk_list));
        if (!ctx->ra_sd_keys) {
            flb_errno();
            goto error;
        }
        mk_list_init(ctx->ra_sd_keys);
        flb_config_map_foreach(head, mv, ctx->sd_keys) {
            sk_key_ra = flb_malloc(sizeof(struct flb_syslog_sd_key));
            if (!sk_key_ra) {
                flb_errno();
                goto error;
            }
            sk_key_ra->ra_sd_key = flb_ra_create(mv->val.str, FLB_FALSE);
            if (sk_key_ra->ra_sd_key == NULL) {
                flb_plg_error(ins, "could not create record accessor for SD Key %s",
                    mv->val.str);
                flb_free(sk_key_ra);
                goto error;
            }
            sk_key_ra->key_normalized = syslog_normalize_ra_key_name(
                sk_key_ra->ra_sd_key);
            if (sk_key_ra->key_normalized == NULL) {
                flb_plg_error(ins, "could not normalize name for SD Key %s",
                    mv->val.str);
                flb_ra_destroy(sk_key_ra->ra_sd_key);
                flb_free(sk_key_ra);
                goto error;
            }
            mk_list_add(&sk_key_ra->_head, ctx->ra_sd_keys);
        }
    }

    return ctx;

error:
    flb_syslog_config_destroy(ctx);
    return NULL;
}

void flb_syslog_config_destroy(struct flb_syslog *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_syslog_sd_key *sd_key_item;

    if (!ctx) {
        return;
    }

    if (ctx->ra_severity_key) {
        flb_ra_destroy(ctx->ra_severity_key);
        ctx->ra_severity_key = NULL;
    }

    if (ctx->ra_facility_key) {
        flb_ra_destroy(ctx->ra_facility_key);
        ctx->ra_facility_key = NULL;
    }

    if (ctx->ra_hostname_key) {
        flb_ra_destroy(ctx->ra_hostname_key);
        ctx->ra_hostname_key = NULL;
    }

    if (ctx->ra_appname_key) {
        flb_ra_destroy(ctx->ra_appname_key);
        ctx->ra_appname_key = NULL;
    }

    if (ctx->ra_procid_key) {
        flb_ra_destroy(ctx->ra_procid_key);
        ctx->ra_procid_key = NULL;
    }

    if (ctx->ra_msgid_key) {
        flb_ra_destroy(ctx->ra_msgid_key);
        ctx->ra_msgid_key = NULL;
    }

    if (ctx->ra_sd_keys) {
        mk_list_foreach_safe(head, tmp, ctx->ra_sd_keys) {
            sd_key_item = mk_list_entry(head, struct flb_syslog_sd_key, _head);

            if (sd_key_item->ra_sd_key) {
                flb_ra_destroy(sd_key_item->ra_sd_key);
                sd_key_item->ra_sd_key = NULL;
            }

            if (sd_key_item->key_normalized) {
                flb_sds_destroy(sd_key_item->key_normalized);
                sd_key_item->key_normalized = NULL;
            }

            mk_list_del(&sd_key_item->_head);
            flb_free(sd_key_item);
        }
        flb_free(ctx->ra_sd_keys);
        ctx->ra_sd_keys = NULL;
    }

    if (ctx->ra_message_key) {
        flb_ra_destroy(ctx->ra_message_key);
        ctx->ra_message_key = NULL;
    }

    flb_free(ctx);
}
