/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#define LINE_SIZE   2048

/* plugin context */
struct checklist {
    /* config options */
    flb_sds_t file;
    flb_sds_t lookup_key;
    struct mk_list *records;

    /* internal */
    struct flb_hash *ht;
    struct flb_record_accessor *ra_lookup_key;
    struct flb_filter_instance *ins;
    struct flb_config *config;
};

static int load_file_patterns(struct checklist *ctx)
{
    int len;
    int ret;
    int line = 0;
    int size = LINE_SIZE;
    char buf[LINE_SIZE];
    FILE *f;

    /* open file */
    f = fopen(ctx->file, "r");
    if (!f) {
        flb_errno();
        flb_plg_error(ctx->ins, "could not open file: %s", ctx->file);
        return -1;
    }

    /* read and process rules on lines */
    while (fgets(buf, size - 1, f)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
            }
        }
        else if (!feof(f)) {
            flb_plg_error(ctx->ins, "length of content has exceeded limit");
            fclose(f);
            return -1;
        }

        /* skip empty and commented lines */
        if (!buf[0] || buf[0] == '#') {
            line++;
            continue;
        }

        /* add the entry as a hash table key, no value reference is needed */
        ret = flb_hash_add(ctx->ht, buf, len, "", 0);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "error registering value '%s' on %s:%i",
                          buf, ctx->file, line);
            fclose(f);
            return -1;
        }
        flb_plg_debug(ctx->ins, "file list: line=%i adds value='%s'", line, buf);
        line++;
    }

    fclose(f);
    return 0;
}

static int init_config(struct checklist *ctx)
{
    int ret;

    /* check if we have 'records' to add */
    if (mk_list_size(ctx->records) == 0) {
        flb_plg_warn(ctx->ins, "no 'record' options has been specified");
    }

    /* create hash table */
    ctx->ht = flb_hash_create(FLB_HASH_EVICT_NONE, 1024, -1);
    if (!ctx->ht) {
        flb_plg_error(ctx->ins, "could not create hash table");
        return -1;
    }

    /* record accessor pattern / key name */
    ctx->ra_lookup_key = flb_ra_create(ctx->lookup_key, FLB_TRUE);
    if (!ctx->ra_lookup_key) {
        flb_plg_error(ctx->ins, "invalid ra_lookup_key pattern: %s",
                      ctx->ra_lookup_key);
        return -1;
    }

    /* validate file */
    if (!ctx->file) {
        flb_plg_error(ctx->ins, "option 'file' is not set");
        return -1;
    }

    /* load file content */
    ret = load_file_patterns(ctx);

    return ret;
}

static int cb_checklist_init(struct flb_filter_instance *ins,
                             struct flb_config *config,
                             void *data)
{
    int ret;
    struct checklist *ctx;

    ctx = flb_calloc(1, sizeof(struct checklist));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;

    /* set context */
    flb_filter_set_context(ins, ctx);

    /* Set config_map properties in our local context */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ret = init_config(ctx);

    return 0;
}

static int set_record(struct checklist *ctx, msgpack_packer *mp_pck,
                      struct flb_time *tm, msgpack_object *map)
{
    int i;
    int len;
    int skip;
    msgpack_object k;
    msgpack_object v;
    struct mk_list *head;
    struct flb_slist_entry *r_key;
    struct flb_slist_entry *r_val;
    struct flb_mp_map_header mh;
    struct flb_config_map_val *mv;

    /* array: timestamp + map */
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(tm, mp_pck, 0);

    /* append map header */
    flb_mp_map_header_init(&mh, mp_pck);

    for (i = 0; i < map->via.map.size; i++) {
        k = map->via.map.ptr[i].key;
        v = map->via.map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        /* iterate 'records' list, check if this key is a duplicated */
        skip = FLB_FALSE;
        flb_config_map_foreach(head, mv, ctx->records) {
            r_key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
            r_val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

            len = flb_sds_len(r_key->str);
            if (k.via.str.size != len) {
                continue;
            }

            if (strncmp(k.via.str.ptr, r_key->str, len) == 0) {
                skip = FLB_TRUE;
                break;
            }
        }

        /*
         * skip is true if the current key will be overrided by some entry of
         * the 'records' list.
         */
        if (skip) {
            continue;
        }

        /* pack current key/value pair */
        flb_mp_map_header_append(&mh);
        msgpack_pack_object(mp_pck, k);
        msgpack_pack_object(mp_pck, v);
    }

    /* Pack custom records */
    flb_config_map_foreach(head, mv, ctx->records) {
        r_key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        r_val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_mp_map_header_append(&mh);
        len = flb_sds_len(r_key->str);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, r_key->str, len);


        if (strcasecmp(r_val->str, "true") == 0) {
            msgpack_pack_true(mp_pck);
        }
        else if (strcasecmp(r_val->str, "false") == 0) {
            msgpack_pack_false(mp_pck);
        }
        else if (strcasecmp(r_val->str, "null") == 0) {
            msgpack_pack_nil(mp_pck);
        }
        else {
            len = flb_sds_len(r_val->str);
            msgpack_pack_str(mp_pck, len);
            msgpack_pack_str_body(mp_pck, r_val->str, len);
        }
    }

    flb_mp_map_header_end(&mh);
    return 0;
}

static int cb_checklist_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_bytes,
                               struct flb_filter_instance *ins,
                               void *filter_context,
                               struct flb_config *config)
{
    int id;
    int found;
    int matches = 0;
    size_t pre = 0;
    size_t off = 0;
    char *tmp_buf;
    size_t tmp_size;
    struct flb_time tm;
    struct checklist *ctx = filter_context;
    msgpack_object *map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_ra_value *rval;
    (void) ins;
    (void) config;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        found = FLB_FALSE;

        flb_time_pop_from_msgpack(&tm, &result, &map);
        rval = flb_ra_get_value_object(ctx->ra_lookup_key, *map);
        if (rval) {
            if (rval->type == FLB_RA_STRING) {
                id = flb_hash_get(ctx->ht,
                                  rval->o.via.str.ptr,
                                  rval->o.via.str.size,
                                  (void *) &tmp_buf, &tmp_size);
                if (id >= 0) {
                    found = FLB_TRUE;
                }
            }
            flb_ra_key_value_destroy(rval);
        }

        if (found) {
            /* add any previous content that not matched */
            if (mp_sbuf.size == 0 && pre > 0) {
                msgpack_sbuffer_write(&mp_sbuf, data, pre);
            }
            set_record(ctx, &mp_pck, &tm, map);
            matches++;
        }
        else {
            if (mp_sbuf.size > 0) {
                /* append current record to new buffer */
                msgpack_sbuffer_write(&mp_sbuf, data + pre, off - pre);
            }
        }
        pre = off;
    }
    msgpack_unpacked_destroy(&result);

    if (matches > 0) {
        *out_buf = mp_sbuf.data;
        *out_bytes = mp_sbuf.size;
        return FLB_FILTER_MODIFIED;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    return FLB_FILTER_NOTOUCH;
}

static int cb_exit(void *data, struct flb_config *config)
{
    struct checklist *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->ra_lookup_key) {
        flb_ra_destroy(ctx->ra_lookup_key);
    }

    if (ctx->ht) {
        flb_hash_destroy(ctx->ht);
    }
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "file", NULL,
     0, FLB_TRUE, offsetof(struct checklist, file),
     "Specify the file that contains the patterns to lookup."
    },

    {
     FLB_CONFIG_MAP_STR, "lookup_key", "log",
     0, FLB_TRUE, offsetof(struct checklist, lookup_key),
     "Name of the key to lookup."
    },

    {
     FLB_CONFIG_MAP_SLIST_2, "record", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct checklist, records),
     "Name of record key to add and its value, it accept two values,e.g "
     "'record mykey my val'. You can add many 'record' entries as needed."
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_checklist_plugin = {
    .name         = "checklist",
    .description  = "Check records and flag them",
    .cb_init      = cb_checklist_init,
    .cb_filter    = cb_checklist_filter,
    .cb_exit      = cb_exit,
    .config_map   = config_map,
    .flags        = 0
};
