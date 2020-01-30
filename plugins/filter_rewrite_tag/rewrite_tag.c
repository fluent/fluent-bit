/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_record_accessor.h>
#include <msgpack.h>

/* Rewrite rule  */
struct rewrite_rule {
    int keep_record;                       /* keep original record ? */
    struct flb_regex *regex;               /* matching regex */
    struct flb_record_accessor *ra_key;    /* key record accessor */
    struct flb_record_accessor *ra_tag;    /* tag record accessor */
    struct mk_list _head;                  /* link to flb_rewrite_tag->rules */
};

/* Plugin context */
struct flb_rewrite_tag {
    flb_sds_t emitter_name;                /* emitter input plugin name */
    struct mk_list rules;                  /* processed rules */
    struct mk_list *cm_rules;              /* config_map rules (only strings) */
    struct flb_input_instance *in_emitter; /* emitter input plugin instance */
    struct flb_config *config;             /* Fluent Bit context */
};

/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in);
int in_emitter_get_collector_id(struct flb_input_instance *in);

/* Create an emitter input instance */
static int emitter_create(struct flb_rewrite_tag *ctx)
{
    int ret;
    int coll_fd;
    struct flb_input_instance *in;

    ret = flb_input_name_exists(ctx->emitter_name, ctx->config);
    if (ret == FLB_TRUE) {
        flb_error("[filter_rewrite_tag] emitter_name '%s' already exists");
        return -1;
    }

    in = flb_input_new(ctx->config, "emitter", NULL, FLB_FALSE);
    if (!in) {
        flb_error("[filter_rewrite_tag] cannot create emitter instance");
        return -1;
    }

    /* Set the alias name */
    ret = flb_input_set_property(in, "alias", ctx->emitter_name);
    if (ret == -1) {
        flb_warn("[filter_rewrite_tag] cannot set emitter_name, using "
                 "fallback name '%s'", in->name);
    }

    /* Initialize emitter plugin */
    ret = flb_input_instance_init(in, ctx->config);
    if (ret == -1) {
        flb_error("[filter_rewrite_tg] cannot initialize emitter instance '%s'",
                  in->name);
        flb_input_instance_exit(in, ctx->config);
        flb_input_instance_free(in);
        return -1;
    }

    /* Retrieve the collector id registered on the in_emitter initialization */
    coll_fd = in_emitter_get_collector_id(in);

    /* Initialize plugin collector (event callback) */
    flb_input_collector_start(coll_fd, in);

#ifdef FLB_HAVE_METRICS
    /* Override Metrics title */
    ret = flb_metrics_title(ctx->emitter_name, in->metrics);
    if (ret == -1) {
        flb_warn("[filter_rewrite_tag] cannot set metrics title, using fallback name %s",
                 in->name);
    }
#endif

    /* Storage context */
    ret = flb_storage_input_create(ctx->config->cio, in);
    if (ret == -1) {
        flb_error("[filter_rewrite_tag] cannot initialize storage for stream '%s'",
                  ctx->emitter_name);
        return -1;
    }
    ctx->in_emitter = in;
    return 0;
}

/*
 * Validate and prepare internal contexts based on the received
 * config_map values.
 */
static int process_config(struct flb_rewrite_tag *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct rewrite_rule *rule;
    struct flb_config_map_val *val;

    if (!ctx->cm_rules) {
        return -1;
    }

    mk_list_foreach(head, ctx->cm_rules) {
        /*
         * When multiple entries are allowed in a config map, this becomes
         * a list of struct flb_config_map_val. Every entry is linked in the
         * 'mult' field
         */
        val = mk_list_entry(head, struct flb_config_map_val, _head);

        /* Allocate a rule */
        rule = flb_malloc(sizeof(struct rewrite_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        /* key */
        entry = flb_slist_entry_get(val->val.list, 0);
        rule->ra_key = flb_ra_create(entry->str, FLB_FALSE);
        if (!rule->ra_key) {
            flb_error("[filter_rewrite_tag] invalid record accessor key? '%s'",
                      entry->str);
            flb_free(rule);
            return -1;
        }

        /* regex */
        entry = flb_slist_entry_get(val->val.list, 1);
        rule->regex = flb_regex_create(entry->str);
        if (!rule->regex) {
            flb_error("[filter_rewrite_tag] could not compile regex pattern '%s'",
                      entry->str);
            flb_ra_destroy(rule->ra_key);
            flb_free(rule);
            return -1;
        }

        /* tag */
        entry = flb_slist_entry_get(val->val.list, 2);
        rule->ra_tag = flb_ra_create(entry->str, FLB_FALSE);

        if (!rule->ra_tag) {
            flb_error("[filter_rewrite_tag] could not compose tag", entry->str);
            flb_ra_destroy(rule->ra_key);
            flb_regex_destroy(rule->regex);
            flb_free(rule);
            return -1;
        }

        /* keep record ? */
        entry = flb_slist_entry_get(val->val.list, 3);
        rule->keep_record = flb_utils_bool(entry->str);

        /* Link new rule */
        mk_list_add(&rule->_head, &ctx->rules);
    }

    if (mk_list_size(&ctx->rules) == 0) {
        flb_warn("[filter_rewrite_tag] no rules have defined");
        return 0;
    }

    return 0;
}

static int cb_rewrite_tag_init(struct flb_filter_instance *ins,
                               struct flb_config *config,
                               void *data)
{
    int ret;
    flb_sds_t tmp;
    struct flb_rewrite_tag *ctx;
    (void) data;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_rewrite_tag));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->config = config;
    mk_list_init(&ctx->rules);

    /* Set config_map properties in our local context */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set plugin context */
    flb_filter_set_context(ins, ctx);

    /*
     * Emitter name: every rewrite_tag instance needs an emitter input plugin, with
     * that one is able to emit records. We use a unique instance so we can use
     * the metrics interface.
     *
     * If not set, we define an emitter name
     */
    if (!ctx->emitter_name) {
        ctx->emitter_name = flb_sds_create_size(64);
        tmp = flb_sds_printf(&ctx->emitter_name, "emitter_for_%s", ins->name);
        if (!tmp) {
            flb_error("[filter rewrite_tag] cannot compose emitter_name");
            flb_free(ctx);
            return -1;
        }
        ctx->emitter_name = tmp;
    }

    /* Process the configuration */
    ret = process_config(ctx);
    if (ret == -1) {
        return -1;
    }

    /* Create the emitter context */
    ret = emitter_create(ctx);
    if (ret == -1) {
        return -1;
    }
    return 0;
}

/*
 * On given record, check if a rule applies or not to the map, if so, compose
 * the new tag, emit the record and return FLB_TRUE, otherwise just return
 * FLB_FALSE and the original record will remain.
 */
static int process_record(const char *tag, int tag_len, msgpack_object map,
                          const void *buf, size_t buf_size, int *keep,
                          struct flb_rewrite_tag *ctx)
{
    int ret;
    flb_sds_t out_tag;
    struct mk_list *head;
    struct rewrite_rule *rule = NULL;
    struct flb_regex_search result = {0};

    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct rewrite_rule, _head);
        ret = flb_ra_regex_match(rule->ra_key, map, rule->regex, &result);
        if (ret < 0) { /* no match */
            rule = NULL;
            continue;
        }

        /* A record matched, just break and check 'rule' */
        break;
    }

    if (!rule) {
        return FLB_FALSE;
    }

    /* Compose new tag */
    out_tag = flb_ra_translate(rule->ra_tag, (char *) tag, tag_len, map, &result);

    /* Release any capture info from 'results' */
    flb_regex_results_release(&result);

    /* Emit record with new tag */
    ret = in_emitter_add_record(out_tag, flb_sds_len(out_tag), buf, buf_size,
                                ctx->in_emitter);

    /* Release the tag */
    flb_sds_destroy(out_tag);

    if (ret == -1) {
        return FLB_FALSE;
    }

    *keep = rule->keep_record;
    return FLB_TRUE;
}

static int cb_rewrite_tag_filter(const void *data, size_t bytes,
                                 const char *tag, int tag_len,
                                 void **out_buf, size_t *out_bytes,
                                 struct flb_filter_instance *f_ins,
                                 void *filter_context,
                                 struct flb_config *config)
{
    int ret;
    int keep;
    int emitted = 0;
    size_t pre = 0;
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object map;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_rewrite_tag *ctx = (struct flb_rewrite_tag *) filter_context;
    (void) f_ins;
    (void) config;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        map = root.via.array.ptr[1];

        /*
         * Process the record according the defined rules. If it returns FLB_TRUE means
         * the record was emitter with a different tag.
         *
         * If a record was emitted, the variable 'keep' will define if the record must
         * be preserved or not.
         */
        ret = process_record(tag, tag_len, map, data + pre, off - pre, &keep, ctx);
        if (ret == FLB_TRUE) {
            /* A record with the new tag was emitted */
            emitted++;
        }

        /*
         * Here we decide if the original record must be preserved or not:
         *
         * - record with new tag was emitted and the rule says it must be preserved
         * - record was not emitted
         */
        if ((ret == FLB_TRUE && keep == FLB_TRUE) || ret == FLB_FALSE) {
            msgpack_sbuffer_write(&mp_sbuf, data + pre, off - pre);
        }

        /* Adjust previous offset */
        pre = off;
    }
    msgpack_unpacked_destroy(&result);

    if (emitted == 0) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = mp_sbuf.data;
    *out_bytes = mp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

/* Destroy rules from context */
static void destroy_rules(struct flb_rewrite_tag *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct rewrite_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct rewrite_rule, _head);
        flb_regex_destroy(rule->regex);
        flb_ra_destroy(rule->ra_key);
        flb_ra_destroy(rule->ra_tag);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static int cb_rewrite_tag_exit(void *data, struct flb_config *config)
{
    struct flb_rewrite_tag *ctx = (struct flb_rewrite_tag *) data;

    if (!ctx) {
        return 0;
    }

    destroy_rules(ctx);
    flb_sds_destroy(ctx->emitter_name);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_4, "rule", NULL,
     FLB_TRUE, FLB_TRUE, offsetof(struct flb_rewrite_tag, cm_rules),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "emitter_name", NULL,
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_rewrite_tag, emitter_name),
     NULL
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_rewrite_tag_plugin = {
    .name         = "rewrite_tag",
    .description  = "Rewrite records tags",
    .cb_init      = cb_rewrite_tag_init,
    .cb_filter    = cb_rewrite_tag_filter,
    .cb_exit      = cb_rewrite_tag_exit,
    .config_map   = config_map,
    .flags        = 0
};
