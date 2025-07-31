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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_thread_storage.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_gzip.h>

#include <ctype.h>
#include <sys/stat.h>

#include "loki.h"

struct flb_loki_dynamic_tenant_id_entry {
    flb_sds_t value;
    struct cfl_list _head;
};

pthread_once_t initialization_guard = PTHREAD_ONCE_INIT;

FLB_TLS_DEFINE(struct flb_loki_dynamic_tenant_id_entry,
               thread_local_tenant_id);
struct flb_loki_remove_mpa_entry {
    struct flb_mp_accessor *mpa;
    struct cfl_list _head;
};
FLB_TLS_DEFINE(struct flb_loki_remove_mpa_entry, thread_local_remove_mpa);

void initialize_thread_local_storage()
{
    FLB_TLS_INIT(thread_local_tenant_id);
    FLB_TLS_INIT(thread_local_remove_mpa);
}

static struct flb_loki_dynamic_tenant_id_entry *dynamic_tenant_id_create() {
    struct flb_loki_dynamic_tenant_id_entry *entry;

    entry = (struct flb_loki_dynamic_tenant_id_entry *) \
        flb_calloc(1, sizeof(struct flb_loki_dynamic_tenant_id_entry));

    if (entry != NULL) {
        entry->value = NULL;

        cfl_list_entry_init(&entry->_head);
    }

    return entry;
}

static void dynamic_tenant_id_destroy(struct flb_loki_dynamic_tenant_id_entry *entry) {
    if (entry != NULL) {
        if (entry->value != NULL) {
            flb_sds_destroy(entry->value);

            entry->value = NULL;
        }

        if (!cfl_list_entry_is_orphan(&entry->_head)) {
            cfl_list_del(&entry->_head);
        }

        flb_free(entry);
    }
}

static struct flb_loki_remove_mpa_entry *remove_mpa_entry_create(struct flb_loki *ctx)
{
    struct flb_loki_remove_mpa_entry *entry;

    entry = flb_calloc(1, sizeof(struct flb_loki_remove_mpa_entry));
    if (!entry) {
        flb_errno();
        return NULL;
    }

    entry->mpa = flb_mp_accessor_create(&ctx->remove_keys_derived);
    if (!entry->mpa) {
        flb_free(entry);
        return NULL;
    }

    cfl_list_entry_init(&entry->_head);

    return entry;
}

static void remove_mpa_entry_destroy(struct flb_loki_remove_mpa_entry *entry)
{
    if (entry) {
        if (entry->mpa) {
            flb_mp_accessor_destroy(entry->mpa);
            entry->mpa = NULL;
        }

        if (!cfl_list_entry_is_orphan(&entry->_head)) {
            cfl_list_del(&entry->_head);
        }

        flb_free(entry);
    }
}

static void flb_loki_kv_init(struct mk_list *list)
{
    mk_list_init(list);
}

static inline void safe_sds_cat(flb_sds_t *buf, const char *str, int len)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(*buf, str, len);
    if (tmp) {
        *buf = tmp;
    }
}

static inline void normalize_cat(struct flb_ra_parser *rp, flb_sds_t *name)
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
        safe_sds_cat(name, key->name, flb_sds_len(key->name));
    }
    else if (rp->type == FLB_RA_PARSER_KEYMAP) {
        safe_sds_cat(name, key->name, flb_sds_len(key->name));
        if (mk_list_size(key->subkeys) > 0) {
            safe_sds_cat(name, "_", 1);
        }

        sub = 0;
        mk_list_foreach(s_head, key->subkeys) {
            entry = mk_list_entry(s_head, struct flb_ra_subentry, _head);

            if (sub > 0) {
                safe_sds_cat(name, "_", 1);
            }
            if (entry->type == FLB_RA_PARSER_STRING) {
                safe_sds_cat(name, entry->str, flb_sds_len(entry->str));
            }
            else if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
                len = snprintf(tmp, sizeof(tmp) -1, "%d",
                               entry->array_id);
                safe_sds_cat(name, tmp, len);
            }
            sub++;
        }
    }
}

static flb_sds_t normalize_ra_key_name(struct flb_loki *ctx,
                                       struct flb_record_accessor *ra)
{
    int c = 0;
    flb_sds_t name;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    name = flb_sds_create_size(128);
    if (!name) {
        return NULL;
    }

    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (c > 0) {
            flb_sds_cat_safe(&name, "_", 1);
        }
        normalize_cat(rp, &name);
        c++;
    }

    return name;
}

void flb_loki_kv_destroy(struct flb_loki_kv *kv)
{
    /* destroy key and value */
    flb_sds_destroy(kv->key);
    if (kv->val_type == FLB_LOKI_KV_STR) {
        flb_sds_destroy(kv->str_val);
    }
    else if (kv->val_type == FLB_LOKI_KV_RA) {
        flb_ra_destroy(kv->ra_val);
    }

    if (kv->ra_key) {
        flb_ra_destroy(kv->ra_key);
    }

    if (kv->key_normalized) {
        flb_sds_destroy(kv->key_normalized);
    }

    flb_free(kv);
}

int flb_loki_kv_append(struct flb_loki *ctx, struct mk_list *list, char *key, char *val)
{
    int ra_count = 0;
    int k_len;
    int ret;
    struct flb_loki_kv *kv;

    if (!key) {
        return -1;
    }

    if (!val && key[0] != '$') {
        return -1;
    }

    kv = flb_calloc(1, sizeof(struct flb_loki_kv));
    if (!kv) {
        flb_errno();
        return -1;
    }

    k_len = strlen(key);
    if (key[0] == '$' && k_len >= 2 && isdigit(key[1])) {
        flb_plg_error(ctx->ins,
                      "key name for record accessor cannot start with a number: %s",
                      key);
        flb_free(kv);
        return -1;
    }

    kv->key = flb_sds_create(key);
    if (!kv->key) {
        flb_free(kv);
        return -1;
    }

    /*
     * If the key starts with a '$', it means its a record accessor pattern and
     * the key value pair will be formed using the key name and it proper value.
     */
    if (key[0] == '$' && val == NULL) {
        kv->ra_key = flb_ra_create(key, FLB_TRUE);
        if (!kv->ra_key) {
            flb_plg_error(ctx->ins,
                          "invalid key record accessor pattern for key '%s'",
                          key);
            flb_loki_kv_destroy(kv);
            return -1;
        }

        /* Normalize 'key name' using record accessor pattern */
        kv->key_normalized = normalize_ra_key_name(ctx, kv->ra_key);
        if (!kv->key_normalized) {
            flb_plg_error(ctx->ins,
                          "could not normalize key pattern name '%s'\n",
                          kv->ra_key->pattern);
            flb_loki_kv_destroy(kv);
            return -1;
        }
        /* remove record keys placed as stream labels via 'labels' and 'label_keys' */
        ret = flb_slist_add(&ctx->remove_keys_derived, key);
        if (ret < 0) {
            flb_loki_kv_destroy(kv);
            return -1;
        }
        ra_count++;
    }
    else if (val[0] == '$') {
        /* create a record accessor context */
        kv->val_type = FLB_LOKI_KV_RA;
        kv->ra_val = flb_ra_create(val, FLB_TRUE);
        if (!kv->ra_val) {
            flb_plg_error(ctx->ins,
                          "invalid record accessor pattern for key '%s': %s",
                          key, val);
            flb_loki_kv_destroy(kv);
            return -1;
        }
        ret = flb_slist_add(&ctx->remove_keys_derived, val);
        if (ret < 0) {
            flb_loki_kv_destroy(kv);
            return -1;
        }
        ra_count++;
    }
    else {
        kv->val_type = FLB_LOKI_KV_STR;
        kv->str_val = flb_sds_create(val);
        if (!kv->str_val) {
            flb_loki_kv_destroy(kv);
            return -1;
        }
    }
    mk_list_add(&kv->_head, list);

    /* return the number of record accessor values */
    return ra_count;
}

static void flb_loki_kv_exit(struct flb_loki *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_loki_kv *kv;

    mk_list_foreach_safe(head, tmp, &ctx->labels_list) {
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* unlink and destroy */
        mk_list_del(&kv->_head);
        flb_loki_kv_destroy(kv);
    }
    mk_list_foreach_safe(head, tmp, &ctx->structured_metadata_list) {
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* unlink and destroy */
        mk_list_del(&kv->_head);
        flb_loki_kv_destroy(kv);
    }
    mk_list_foreach_safe(head, tmp, &ctx->structured_metadata_map_keys_list) {
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* unlink and destroy */
        mk_list_del(&kv->_head);
        flb_loki_kv_destroy(kv);
    }
}

/* Pack a label key, it also perform sanitization of the characters */
static int pack_label_key(msgpack_packer *mp_pck, char *key, int key_len)
{
    int i;
    int k_len = key_len;
    int is_digit = FLB_FALSE;
    char *p;
    size_t prev_size;

    /* Normalize key name using the packed value */
    if (isdigit(*key)) {
        is_digit = FLB_TRUE;
        k_len++;
    }

    /* key: pack the length */
    msgpack_pack_str(mp_pck, k_len);
    if (is_digit) {
        msgpack_pack_str_body(mp_pck, "_", 1);
    }

    /* save the current offset */
    prev_size = ((msgpack_sbuffer *) mp_pck->data)->size;

    /* Pack the key name */
    msgpack_pack_str_body(mp_pck, key, key_len);

    /* 'p' will point to where the key was written */
    p = (char *) (((msgpack_sbuffer*) mp_pck->data)->data + prev_size);

    /* and sanitize the key characters */
    for (i = 0; i < key_len; i++) {
        if (!isalnum(p[i]) && p[i] != '_') {
            p[i] = '_';
        }
    }

    return 0;
}

static void pack_kv(struct flb_loki *ctx,
                    msgpack_packer *mp_pck,
                    char *tag, int tag_len,
                    msgpack_object *map,
                    struct flb_mp_map_header *mh,
                    struct mk_list *list)
{
    struct mk_list *head;
    struct flb_loki_kv *kv;
    flb_sds_t ra_val;
    mk_list_foreach(head, list) {
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* record accessor key/value pair */
        if (kv->ra_key != NULL && kv->ra_val == NULL) {
            ra_val = flb_ra_translate(kv->ra_key, tag, tag_len, *(map), NULL);
            if (!ra_val || flb_sds_len(ra_val) == 0) {
                /* if no value is retruned or if it's empty, just skip it */
                flb_plg_debug(ctx->ins,
                             "empty record accessor key translation for pattern: %s",
                             kv->ra_key->pattern);
            }
            else {
                /* Pack the key and value */
                flb_mp_map_header_append(mh);

                /* We skip the first '$' character since it won't be valid in Loki */
                pack_label_key(mp_pck, kv->key_normalized,
                               flb_sds_len(kv->key_normalized));

                msgpack_pack_str(mp_pck, flb_sds_len(ra_val));
                msgpack_pack_str_body(mp_pck, ra_val, flb_sds_len(ra_val));
            }

            if (ra_val) {
                flb_sds_destroy(ra_val);
            }
            continue;
        }

        /*
         * The code is a bit duplicated to be able to manage the exception of an
         * invalid or empty value, on that case the k/v is skipped.
         */
        if (kv->val_type == FLB_LOKI_KV_STR) {
            flb_mp_map_header_append(mh);
            msgpack_pack_str(mp_pck, flb_sds_len(kv->key));
            msgpack_pack_str_body(mp_pck, kv->key, flb_sds_len(kv->key));
            msgpack_pack_str(mp_pck, flb_sds_len(kv->str_val));
            msgpack_pack_str_body(mp_pck, kv->str_val, flb_sds_len(kv->str_val));
        }
        else if (kv->val_type == FLB_LOKI_KV_RA) {
            /* record accessor type */
            ra_val = flb_ra_translate(kv->ra_val, tag, tag_len, *(map), NULL);
            if (!ra_val || flb_sds_len(ra_val) == 0) {
                flb_plg_debug(ctx->ins, "could not translate record accessor");
            }
            else {
                flb_mp_map_header_append(mh);
                msgpack_pack_str(mp_pck, flb_sds_len(kv->key));
                msgpack_pack_str_body(mp_pck, kv->key, flb_sds_len(kv->key));
                msgpack_pack_str(mp_pck, flb_sds_len(ra_val));
                msgpack_pack_str_body(mp_pck, ra_val, flb_sds_len(ra_val));
            }

            if (ra_val) {
                flb_sds_destroy(ra_val);
            }
        }
    }
}

/*
 * Similar to pack_kv above, except will only use msgpack_objects of type
 * MSGPACK_OBJECT_MAP, and will iterate over the keys adding each entry as a
 * separate item. Non-string map values are serialised to JSON, as Loki requires
 * all values to be strings.
*/
static void pack_maps(struct flb_loki *ctx,
                        msgpack_packer *mp_pck,
                        char *tag, int tag_len,
                        msgpack_object *map,
                        struct flb_mp_map_header *mh,
                        struct mk_list *list,
                        struct flb_config *config)
{
    struct mk_list *head;
    struct flb_loki_kv *kv;

    msgpack_object *start_key;
    msgpack_object *out_key;
    msgpack_object *out_val;

    msgpack_object_map accessed_map;
    uint32_t accessed_map_index;
    msgpack_object_kv accessed_map_kv;

    char *accessed_map_val_json;

    mk_list_foreach(head, list) {
        /* get the flb_loki_kv for this iteration of the loop */
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* record accessor key/value pair */
        if (kv->ra_key != NULL && kv->ra_val == NULL) {

            /* try to get the value for the record accessor */
            if (flb_ra_get_kv_pair(kv->ra_key, *map, &start_key, &out_key, &out_val)
                == 0) {

                /*
                 * we require the value to be a map, or it doesn't make sense as
                 * this is adding a map's key / values
                 */
                if (out_val->type != MSGPACK_OBJECT_MAP || out_val->via.map.size <= 0) {
                    flb_plg_debug(ctx->ins, "No valid map data found for key %s",
                                  kv->ra_key->pattern);
                }
                else {
                    accessed_map = out_val->via.map;

                    /* for each entry in the accessed map... */
                    for (accessed_map_index = 0; accessed_map_index < accessed_map.size;
                         accessed_map_index++) {

                        /* get the entry */
                        accessed_map_kv = accessed_map.ptr[accessed_map_index];

                        /* Pack the key and value */
                        flb_mp_map_header_append(mh);

                        pack_label_key(mp_pck, (char*) accessed_map_kv.key.via.str.ptr,
                                       accessed_map_kv.key.via.str.size);

                        /* If the value is a string, just pack it... */
                        if (accessed_map_kv.val.type == MSGPACK_OBJECT_STR) {
                            msgpack_pack_str_with_body(mp_pck,
                                                       accessed_map_kv.val.via.str.ptr,
                                                       accessed_map_kv.val.via.str.size);
                        }
                        /*
                         * ...otherwise convert value to JSON string, as Loki always
                         * requires a string value
                         */
                        else {
                            accessed_map_val_json = flb_msgpack_to_json_str(1024,
                                                                            &accessed_map_kv.val,
                                                                            config->json_escape_unicode);
                            if (accessed_map_val_json) {
                                msgpack_pack_str_with_body(mp_pck, accessed_map_val_json,
                                                         strlen(accessed_map_val_json));
                                flb_free(accessed_map_val_json);
                            }
                        }
                    }
                }
            }
        }
    }
}

static flb_sds_t pack_structured_metadata(struct flb_loki *ctx,
                                          msgpack_packer *mp_pck,
                                          char *tag, int tag_len,
                                          msgpack_object *map,
                                          struct flb_config *config)
{
    struct flb_mp_map_header mh;
    /* Initialize dynamic map header */
    flb_mp_map_header_init(&mh, mp_pck);
    if (ctx->structured_metadata_map_keys) {
        pack_maps(ctx, mp_pck, tag, tag_len, map, &mh,
                  &ctx->structured_metadata_map_keys_list,
                  config);
    }
    /*
     * explicit structured_metadata entries override
     * structured_metadata_map_keys entries
     * */
    if (ctx->structured_metadata) {
        pack_kv(ctx, mp_pck, tag, tag_len, map, &mh, &ctx->structured_metadata_list);
    }
    flb_mp_map_header_end(&mh);
    return 0;
}

static flb_sds_t pack_labels(struct flb_loki *ctx,
                             msgpack_packer *mp_pck,
                             char *tag, int tag_len,
                             msgpack_object *map)
{
    int i;
    struct flb_ra_value *rval = NULL;
    msgpack_object k;
    msgpack_object v;
    struct flb_mp_map_header mh;

    /* Initialize dynamic map header */
    flb_mp_map_header_init(&mh, mp_pck);
    pack_kv(ctx, mp_pck, tag, tag_len, map, &mh, &ctx->labels_list);

    if (ctx->auto_kubernetes_labels == FLB_TRUE) {
        rval = flb_ra_get_value_object(ctx->ra_k8s, *map);
        if (rval && rval->o.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < rval->o.via.map.size; i++) {
                k = rval->o.via.map.ptr[i].key;
                v = rval->o.via.map.ptr[i].val;

                if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* append the key/value pair */
                flb_mp_map_header_append(&mh);

                /* Pack key */
                pack_label_key(mp_pck, (char *) k.via.str.ptr, k.via.str.size);

                /* Pack the value */
                msgpack_pack_str(mp_pck, v.via.str.size);
                msgpack_pack_str_body(mp_pck, v.via.str.ptr,  v.via.str.size);
            }
        }

        if (rval) {
            flb_ra_key_value_destroy(rval);
        }
    }

    /* Check if we added any label, if no one has been set, set the defaul 'job' */
    if (mh.entries == 0) {
        /* pack the default entry */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 3);
        msgpack_pack_str_body(mp_pck, "job", 3);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "fluent-bit", 10);
    }
    flb_mp_map_header_end(&mh);
    return 0;
}

static int create_label_map_entry(struct flb_loki *ctx,
                                  struct flb_sds_list *list, msgpack_object *val, int *ra_used)
{
    msgpack_object key;
    flb_sds_t label_key;
    flb_sds_t val_str;
    int i;
    int len;
    int ret;

    if (ctx == NULL || list == NULL || val == NULL || ra_used == NULL) {
        return -1;
    }

    switch (val->type) {
    case MSGPACK_OBJECT_STR:
        label_key = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
        if (label_key == NULL) {
            flb_errno();
            return -1;
        }

        val_str = flb_ra_create_str_from_list(list);
        if (val_str == NULL) {
            flb_plg_error(ctx->ins, "[%s] flb_ra_create_from_list failed", __FUNCTION__);
            flb_sds_destroy(label_key);
            return -1;
        }

        /* for debugging
          printf("label_key=%s val_str=%s\n", label_key, val_str);
         */

        ret = flb_loki_kv_append(ctx, &ctx->labels_list, label_key, val_str);
        flb_sds_destroy(label_key);
        flb_sds_destroy(val_str);
        if (ret == -1) {
            return -1;
        }
        *ra_used = *ra_used + 1;

        break;
    case MSGPACK_OBJECT_MAP:
        len = val->via.map.size;
        for (i=0; i<len; i++) {
            key = val->via.map.ptr[i].key;
            if (key.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "[%s] key is not string", __FUNCTION__);
                return -1;
            }
            ret = flb_sds_list_add(list, (char*)key.via.str.ptr, key.via.str.size);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_add failed", __FUNCTION__);
                return -1;
            }

            ret = create_label_map_entry(ctx, list, &val->via.map.ptr[i].val, ra_used);
            if (ret < 0) {
                return -1;
            }

            ret = flb_sds_list_del_last_entry(list);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_del_last_entry failed", __FUNCTION__);
                return -1;
            }
        }

        break;
    default:
        flb_plg_error(ctx->ins, "[%s] value type is not str or map. type=%d", __FUNCTION__, val->type);
        return -1;
    }
    return 0;
}

static int create_label_map_entries(struct flb_loki *ctx,
                                    char *msgpack_buf, size_t msgpack_size, int *ra_used)
{
    struct flb_sds_list *list = NULL;
    msgpack_unpacked result;
    size_t off = 0;
    int i;
    int len;
    int ret;
    msgpack_object key;

    if (ctx == NULL || msgpack_buf == NULL || ra_used == NULL) {
        return -1;
    }

    msgpack_unpacked_init(&result);
    while(msgpack_unpack_next(&result, msgpack_buf, msgpack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "[%s] data type is not map", __FUNCTION__);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        len = result.data.via.map.size;
        for (i=0; i<len; i++) {
            list = flb_sds_list_create();
            if (list == NULL) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_create failed", __FUNCTION__);
                msgpack_unpacked_destroy(&result);
                return -1;
            }
            key = result.data.via.map.ptr[i].key;
            if (key.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "[%s] key is not string", __FUNCTION__);
                flb_sds_list_destroy(list);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            ret = flb_sds_list_add(list, (char*)key.via.str.ptr, key.via.str.size);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_add failed", __FUNCTION__);
                flb_sds_list_destroy(list);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            ret = create_label_map_entry(ctx, list, &result.data.via.map.ptr[i].val, ra_used);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] create_label_map_entry failed", __FUNCTION__);
                flb_sds_list_destroy(list);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            flb_sds_list_destroy(list);
            list = NULL;
        }
    }

    msgpack_unpacked_destroy(&result);

    return 0;
}

static int read_label_map_path_file(struct flb_output_instance *ins, flb_sds_t path,
                                    char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;
    char *buf = NULL;
    char *msgp_buf = NULL;
    FILE *fp = NULL;
    struct stat st;
    size_t file_size;
    size_t ret_size;

    ret = access(path, R_OK);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ins, "can't access %s", path);
        return -1;
    }

    ret = stat(path, &st);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ins, "stat failed %s", path);
        return -1;
    }
    file_size = st.st_size;

    fp = fopen(path, "r");
    if (fp == NULL) {
        flb_plg_error(ins, "can't open %s", path);
        return -1;
    }

    buf = flb_malloc(file_size);
    if (buf == NULL) {
        flb_plg_error(ins, "malloc failed");
        fclose(fp);
        return -1;
    }

    ret_size = fread(buf, 1, file_size, fp);
    if (ret_size < file_size && feof(fp) != 0) {
        flb_plg_error(ins, "fread failed");
        fclose(fp);
        flb_free(buf);
        return -1;
    }

    ret = flb_pack_json(buf, file_size, &msgp_buf, &ret_size, &root_type, NULL);
    if (ret < 0) {
        flb_plg_error(ins, "flb_pack_json failed");
        fclose(fp);
        flb_free(buf);
        return -1;
    }

    *out_buf = msgp_buf;
    *out_size = ret_size;

    fclose(fp);
    flb_free(buf);
    return 0;
}

static int load_label_map_path(struct flb_loki *ctx, flb_sds_t path, int *ra_used)
{
    int ret;
    char *msgpack_buf = NULL;
    size_t msgpack_size;

    ret = read_label_map_path_file(ctx->ins, path, &msgpack_buf, &msgpack_size);
    if (ret < 0) {
        return -1;
    }

    ret = create_label_map_entries(ctx, msgpack_buf, msgpack_size, ra_used);
    if (ret < 0) {
        flb_free(msgpack_buf);
        return -1;
    }

    if (msgpack_buf != NULL) {
        flb_free(msgpack_buf);
    }

    return 0;
}

static int parse_kv(struct flb_loki *ctx, struct mk_list *kv, struct mk_list *list, int *ra_used)
{
    int ret;
    char *p;
    flb_sds_t key;
    flb_sds_t val;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    if (ctx == NULL || list == NULL || ra_used == NULL) {
        return -1;
    }

    mk_list_foreach(head, kv) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* record accessor label key ? */
        if (entry->str[0] == '$') {
            ret = flb_loki_kv_append(ctx, list, entry->str, NULL);
            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                (*ra_used)++;
            }
            continue;
        }

        p = strchr(entry->str, '=');
        if (!p) {
            flb_plg_error(ctx->ins, "invalid key value pair on '%s'",
                          entry->str);
            return -1;
        }

        key = flb_sds_create_size((p - entry->str) + 1);
        flb_sds_cat_safe(&key, entry->str, p - entry->str);
        val = flb_sds_create(p + 1);
        if (!key) {
            flb_plg_error(ctx->ins,
                          "invalid key value pair on '%s'",
                          entry->str);
            return -1;
        }
        if (!val || flb_sds_len(val) == 0) {
            flb_plg_error(ctx->ins,
                          "invalid key value pair on '%s'",
                          entry->str);
            flb_sds_destroy(key);
            return -1;
        }
        ret = flb_loki_kv_append(ctx, list, key, val);
        flb_sds_destroy(key);
        flb_sds_destroy(val);

        if (ret == -1) {
            return -1;
        }
        else if (ret > 0) {
            (*ra_used)++;
        }
    }
    return 0;
}

static int parse_labels(struct flb_loki *ctx)
{
    int ret;
    int ra_used = 0;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    flb_loki_kv_init(&ctx->labels_list);
    flb_loki_kv_init(&ctx->structured_metadata_list);
    flb_loki_kv_init(&ctx->structured_metadata_map_keys_list);

    if (ctx->structured_metadata) {
        ret = parse_kv(ctx, ctx->structured_metadata, &ctx->structured_metadata_list, &ra_used);
        if (ret == -1) {
            return -1;
        }
    }

    /* Append structured metadata map keys set in the configuration */
    if (ctx->structured_metadata_map_keys) {
        mk_list_foreach(head, ctx->structured_metadata_map_keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            if (entry->str[0] != '$') {
                flb_plg_error(ctx->ins,
                              "invalid structured metadata map key, the name must start "
                              "with '$'");
                return -1;
            }

            ret = flb_loki_kv_append(ctx, &ctx->structured_metadata_map_keys_list,
                                     entry->str, NULL);
            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                ra_used++;
            }
        }
    }

    if (ctx->labels) {
        ret = parse_kv(ctx, ctx->labels, &ctx->labels_list, &ra_used);
        if (ret == -1) {
            return -1;
        }
    }

    /* Append label keys set in the configuration */
    if (ctx->label_keys) {
        mk_list_foreach(head, ctx->label_keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            if (entry->str[0] != '$') {
                flb_plg_error(ctx->ins,
                              "invalid label key, the name must start with '$'");
                return -1;
            }

            ret = flb_loki_kv_append(ctx, &ctx->labels_list, entry->str, NULL);
            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                ra_used++;
            }
        }
    }

    /* label_map_path */
    if (ctx->label_map_path) {
        ret = load_label_map_path(ctx, ctx->label_map_path, &ra_used);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to load label_map_path");
        }
    }

    if (ctx->auto_kubernetes_labels == FLB_TRUE) {
        ctx->ra_k8s = flb_ra_create("$kubernetes['labels']", FLB_TRUE);
        if (!ctx->ra_k8s) {
            flb_plg_error(ctx->ins,
                          "could not create record accessor for Kubernetes labels");
            return -1;
        }
    }

    /*
     * If the variable 'ra_used' is greater than zero, means that record accessor is
     * being used to compose the stream labels.
     */
    ctx->ra_used = ra_used;
    return 0;
}

static int key_is_duplicated(struct mk_list *list, char *str, int len)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        if (flb_sds_len(entry->str) == len &&
            strncmp(entry->str, str, len) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int prepare_remove_keys(struct flb_loki *ctx)
{
    int ret;
    int len;
    int size;
    char *tmp;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct mk_list *patterns;

    patterns = &ctx->remove_keys_derived;

    /* Add remove keys set in the configuration */
    if (ctx->remove_keys) {
        mk_list_foreach(head, ctx->remove_keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            if (entry->str[0] != '$') {
                tmp = flb_malloc(flb_sds_len(entry->str) + 2);
                if (!tmp) {
                    flb_errno();
                    continue;
                }
                else {
                    tmp[0] = '$';
                    len = flb_sds_len(entry->str);
                    memcpy(tmp + 1, entry->str, len);
                    tmp[len + 1] = '\0';
                    len++;
                }
            }
            else {
                tmp = entry->str;
                len = flb_sds_len(entry->str);
            }

            ret = key_is_duplicated(patterns, tmp, len);
            if (ret == FLB_TRUE) {
                if (entry->str != tmp) {
                    flb_free(tmp);
                }
                continue;
            }

            ret = flb_slist_add_n(patterns, tmp, len);
            if (entry->str != tmp) {
                flb_free(tmp);
            }
            if (ret < 0) {
                return -1;
            }
        }
        size = mk_list_size(patterns);
        flb_plg_debug(ctx->ins, "remove_mpa size: %d", size);
        if (size > 0) {
            ctx->remove_mpa = flb_mp_accessor_create(patterns);
            if (ctx->remove_mpa == NULL) {
                return -1;
            }
        }
    }

    return 0;
}

static void loki_config_destroy(struct flb_loki *ctx)
{
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->ra_k8s) {
        flb_ra_destroy(ctx->ra_k8s);
    }
    if (ctx->ra_tenant_id_key) {
        flb_ra_destroy(ctx->ra_tenant_id_key);
    }

    if (ctx->remove_mpa) {
        flb_mp_accessor_destroy(ctx->remove_mpa);
    }
    flb_slist_destroy(&ctx->remove_keys_derived);

    flb_loki_kv_exit(ctx);
    flb_free(ctx);
}

static struct flb_loki *loki_config_create(struct flb_output_instance *ins,
                                           struct flb_config *config)
{
    int ret;
    int tmp;
    int io_flags = 0;
    struct flb_loki *ctx;
    struct flb_upstream *upstream;
    char *compress;
    char *drop_single_key;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_loki));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    flb_loki_kv_init(&ctx->labels_list);
    flb_loki_kv_init(&ctx->structured_metadata_list);
    flb_loki_kv_init(&ctx->structured_metadata_map_keys_list);

    /* Register context with plugin instance */
    flb_output_set_context(ins, ctx);

    /* Set networking defaults */
    flb_output_net_default(FLB_LOKI_HOST, FLB_LOKI_PORT, ins);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return NULL;
    }

    /* Initialize final remove_keys list */
    flb_slist_create(&ctx->remove_keys_derived);

    /* Parse labels */
    ret = parse_labels(ctx);
    if (ret == -1) {
        return NULL;
    }

    /* Load remove keys */
    ret = prepare_remove_keys(ctx);
    if (ret == -1) {
        return NULL;
    }

    /* tenant_id_key */
    if (ctx->tenant_id_key_config) {
        ctx->ra_tenant_id_key = flb_ra_create(ctx->tenant_id_key_config, FLB_FALSE);
        if (!ctx->ra_tenant_id_key) {
            flb_plg_error(ctx->ins,
                          "could not create record accessor for Tenant ID");
        }
    }

    /* Compress (gzip) */
    compress = (char *) flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (compress) {
        if (strcasecmp(compress, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }

    /* Drop Single Key */
    drop_single_key = (char *) flb_output_get_property("drop_single_key", ins);
    ctx->out_drop_single_key = FLB_LOKI_DROP_SINGLE_KEY_OFF;
    if (drop_single_key) {
        if (strcasecmp(drop_single_key, "raw") == 0) {
            ctx->out_drop_single_key = FLB_LOKI_DROP_SINGLE_KEY_ON | FLB_LOKI_DROP_SINGLE_KEY_RAW;
        }
        else {
            tmp = flb_utils_bool(drop_single_key);
            if (tmp == FLB_TRUE) {
                ctx->out_drop_single_key = FLB_LOKI_DROP_SINGLE_KEY_ON;
            }
            else if (tmp == FLB_FALSE) {
                ctx->out_drop_single_key = FLB_LOKI_DROP_SINGLE_KEY_OFF;
            }
            else {
                flb_plg_error(ctx->ins, "invalid 'drop_single_key' value: %s",
                              ctx->drop_single_key);
                return NULL;
            }
        }
    }

    /* Line Format */
    if (strcasecmp(ctx->line_format, "json") == 0) {
        ctx->out_line_format = FLB_LOKI_FMT_JSON;
    }
    else if (strcasecmp(ctx->line_format, "key_value") == 0) {
        ctx->out_line_format = FLB_LOKI_FMT_KV;
    }
    else {
        flb_plg_error(ctx->ins, "invalid 'line_format' value: %s",
                      ctx->line_format);
        return NULL;
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create Upstream connection context */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   ins->tls);
    if (!upstream) {
        return NULL;
    }
    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);
    ctx->tcp_port = ins->host.port;
    ctx->tcp_host = ins->host.name;

    return ctx;
}

/*
 * Convert struct flb_tm timestamp value to nanoseconds and then it pack it as
 * a string.
 */
static void pack_timestamp(msgpack_packer *mp_pck, struct flb_time *tms)
{
    int len;
    char buf[64];
    uint64_t nanosecs;

    /* convert to nanoseconds */
    nanosecs = flb_time_to_nanosec(tms);

    /* format as a string */
    len = snprintf(buf, sizeof(buf) - 1, "%" PRIu64, nanosecs);

    /* pack the value */
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, buf, len);
}


static void pack_format_line_value(flb_sds_t *buf, msgpack_object *val)
{
    int i;
    int len;
    char temp[512];
    msgpack_object k;
    msgpack_object v;

    if (val->type == MSGPACK_OBJECT_STR) {
        safe_sds_cat(buf, "\"", 1);
        safe_sds_cat(buf, val->via.str.ptr, val->via.str.size);
        safe_sds_cat(buf, "\"", 1);
    }
    else if (val->type == MSGPACK_OBJECT_NIL) {
        safe_sds_cat(buf, "null", 4);
    }
    else if (val->type == MSGPACK_OBJECT_BOOLEAN) {
        if (val->via.boolean) {
            safe_sds_cat(buf, "true", 4);
        }
        else {
            safe_sds_cat(buf, "false", 5);
        }
    }
    else if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        len = snprintf(temp, sizeof(temp)-1, "%"PRIu64, val->via.u64);
        safe_sds_cat(buf, temp, len);
    }
    else if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        len = snprintf(temp, sizeof(temp)-1, "%"PRId64, val->via.i64);
        safe_sds_cat(buf, temp, len);
    }
    else if (val->type == MSGPACK_OBJECT_FLOAT32 ||
             val->type == MSGPACK_OBJECT_FLOAT64) {
        if (val->via.f64 == (double)(long long int) val->via.f64) {
            len = snprintf(temp, sizeof(temp)-1, "%.1f", val->via.f64);
        }
        else {
            len = snprintf(temp, sizeof(temp)-1, "%.16g", val->via.f64);
        }
        safe_sds_cat(buf, temp, len);
    }
    else if (val->type == MSGPACK_OBJECT_ARRAY) {
        safe_sds_cat(buf, "\"[", 2);
        for (i = 0; i < val->via.array.size; i++) {
            v = val->via.array.ptr[i];
            if (i > 0) {
                safe_sds_cat(buf, " ", 1);
            }
            pack_format_line_value(buf, &v);
        }
        safe_sds_cat(buf, "]\"", 2);
    }
    else if (val->type == MSGPACK_OBJECT_MAP) {
        safe_sds_cat(buf, "\"map[", 5);

        for (i = 0; i < val->via.map.size; i++) {
            k = val->via.map.ptr[i].key;
            v = val->via.map.ptr[i].val;

            if (k.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (i > 0) {
                safe_sds_cat(buf, " ", 1);
            }

            safe_sds_cat(buf, k.via.str.ptr, k.via.str.size);
            safe_sds_cat(buf, ":", 1);
            pack_format_line_value(buf, &v);
        }
        safe_sds_cat(buf, "]\"", 2);
    }
    else {

        return;
    }
}

// seek tenant id from map and set it to dynamic_tenant_id
static int get_tenant_id_from_record(struct flb_loki *ctx, msgpack_object *map,
                                     flb_sds_t *dynamic_tenant_id)
{
    struct flb_ra_value *rval = NULL;
    flb_sds_t tmp_str;
    int cmp_len;

    rval = flb_ra_get_value_object(ctx->ra_tenant_id_key, *map);

    if (rval == NULL) {
        flb_plg_warn(ctx->ins, "the value of %s is missing",
                     ctx->tenant_id_key_config);
        return -1;
    }
    else if (rval->o.type != MSGPACK_OBJECT_STR) {
        flb_plg_warn(ctx->ins, "the value of %s is not string",
                     ctx->tenant_id_key_config);
        flb_ra_key_value_destroy(rval);
        return -1;
    }

    tmp_str = flb_sds_create_len(rval->o.via.str.ptr,
                                 rval->o.via.str.size);
    if (tmp_str == NULL) {
        flb_plg_warn(ctx->ins, "cannot create tenant ID string from record");
        flb_ra_key_value_destroy(rval);
        return -1;
    }

    // check if already dynamic_tenant_id is set.
    if (*dynamic_tenant_id != NULL) {
        cmp_len = flb_sds_len(*dynamic_tenant_id);

        if ((rval->o.via.str.size == cmp_len) &&
            flb_sds_cmp(tmp_str, *dynamic_tenant_id, cmp_len) == 0) {
            // tenant_id is same. nothing to do.
            flb_ra_key_value_destroy(rval);
            flb_sds_destroy(tmp_str);

            return 0;
        }

        flb_plg_warn(ctx->ins, "Tenant ID is overwritten %s -> %s",
                     *dynamic_tenant_id, tmp_str);

        flb_sds_destroy(*dynamic_tenant_id);
    }

    // this sds will be released after setting http header.
    *dynamic_tenant_id = tmp_str;
    flb_plg_debug(ctx->ins, "Tenant ID is %s", *dynamic_tenant_id);

    flb_ra_key_value_destroy(rval);
    return 0;
}

static int pack_record(struct flb_loki *ctx,
                       msgpack_packer *mp_pck, msgpack_object *rec,
                       flb_sds_t *dynamic_tenant_id,
                       struct flb_mp_accessor *remove_mpa,
                       struct flb_config *config)
{
    int i;
    int skip = 0;
    int len;
    int ret;
    int size_hint = 1024;
    char *line;
    flb_sds_t buf;
    msgpack_object key;
    msgpack_object val;
    char *tmp_sbuf_data = NULL;
    size_t tmp_sbuf_size;
    msgpack_unpacked mp_buffer;
    size_t off = 0;

    /*
     * Get tenant id from record before removing keys.
     * https://github.com/fluent/fluent-bit/issues/6207
     */
    if (ctx->ra_tenant_id_key && rec->type == MSGPACK_OBJECT_MAP) {
        get_tenant_id_from_record(ctx, rec, dynamic_tenant_id);
    }

    /* Remove keys in remove_keys */
    msgpack_unpacked_init(&mp_buffer);
    if (remove_mpa) {
        ret = flb_mp_accessor_keys_remove(remove_mpa, rec,
                                          (void *) &tmp_sbuf_data, &tmp_sbuf_size);
        if (ret == FLB_TRUE) {
            ret = msgpack_unpack_next(&mp_buffer, tmp_sbuf_data, tmp_sbuf_size, &off);
            if (ret != MSGPACK_UNPACK_SUCCESS) {
                flb_free(tmp_sbuf_data);
                msgpack_unpacked_destroy(&mp_buffer);
                return -1;
            }
            rec = &mp_buffer.data;
        }
    }

    /* Drop single key */
    if (ctx->out_drop_single_key & FLB_LOKI_DROP_SINGLE_KEY_ON &&
        rec->type == MSGPACK_OBJECT_MAP && rec->via.map.size == 1) {
        val = rec->via.map.ptr[0].val;

        if (ctx->out_line_format == FLB_LOKI_FMT_JSON) {
            if (val.type == MSGPACK_OBJECT_STR &&
                ctx->out_drop_single_key & FLB_LOKI_DROP_SINGLE_KEY_RAW) {
                msgpack_pack_str(mp_pck, val.via.str.size);
                msgpack_pack_str_body(mp_pck, val.via.str.ptr, val.via.str.size);

                msgpack_unpacked_destroy(&mp_buffer);
                if (tmp_sbuf_data) {
                    flb_free(tmp_sbuf_data);
                }

                return 0;
            }
            else {
                rec = &val;
            }
        }
        else if (ctx->out_line_format == FLB_LOKI_FMT_KV) {
            if (val.type == MSGPACK_OBJECT_STR) {
                msgpack_pack_str(mp_pck, val.via.str.size);
                msgpack_pack_str_body(mp_pck, val.via.str.ptr, val.via.str.size);
            } else {
                buf = flb_sds_create_size(size_hint);
                if (!buf) {
                    msgpack_unpacked_destroy(&mp_buffer);
                    if (tmp_sbuf_data) {
                        flb_free(tmp_sbuf_data);
                    }
                    return -1;
                }
                pack_format_line_value(&buf, &val);
                msgpack_pack_str(mp_pck, flb_sds_len(buf));
                msgpack_pack_str_body(mp_pck, buf, flb_sds_len(buf));
                flb_sds_destroy(buf);
            }

            msgpack_unpacked_destroy(&mp_buffer);
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }

            return 0;
        }
    }

    if (ctx->out_line_format == FLB_LOKI_FMT_JSON) {
        line = flb_msgpack_to_json_str(size_hint, rec, config->json_escape_unicode);
        if (!line) {
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }
            msgpack_unpacked_destroy(&mp_buffer);
            return -1;
        }
        len = strlen(line);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, line, len);
        flb_free(line);
    }
    else if (ctx->out_line_format == FLB_LOKI_FMT_KV) {
        if (rec->type != MSGPACK_OBJECT_MAP) {
            msgpack_unpacked_destroy(&mp_buffer);
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }
            return -1;
        }

        buf = flb_sds_create_size(size_hint);
        if (!buf) {
            msgpack_unpacked_destroy(&mp_buffer);
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }
            return -1;
        }

        for (i = 0; i < rec->via.map.size; i++) {
            key = rec->via.map.ptr[i].key;
            val = rec->via.map.ptr[i].val;

            if (key.type != MSGPACK_OBJECT_STR) {
                skip++;
                continue;
            }

            if (i > skip) {
                safe_sds_cat(&buf, " ", 1);
            }

            safe_sds_cat(&buf, key.via.str.ptr, key.via.str.size);
            safe_sds_cat(&buf, "=", 1);
            pack_format_line_value(&buf, &val);
        }

        msgpack_pack_str(mp_pck, flb_sds_len(buf));
        msgpack_pack_str_body(mp_pck, buf, flb_sds_len(buf));
        flb_sds_destroy(buf);
    }

    msgpack_unpacked_destroy(&mp_buffer);
    if (tmp_sbuf_data) {
        flb_free(tmp_sbuf_data);
    }

    return 0;
}

/* Initialization callback */
static int cb_loki_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    int              result;
    struct flb_loki *ctx;

    /* Create plugin context */
    ctx = loki_config_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize configuration");
        return -1;
    }

    result = pthread_mutex_init(&ctx->dynamic_tenant_list_lock, NULL);

    if (result != 0) {
        flb_errno();

        flb_plg_error(ins, "cannot initialize dynamic tenant id list lock");

        loki_config_destroy(ctx);

        return -1;
    }

    result = pthread_once(&initialization_guard,
                          initialize_thread_local_storage);

    if (result != 0) {
        flb_errno();

        flb_plg_error(ins, "cannot initialize thread local storage");

        loki_config_destroy(ctx);

        return -1;
    }

    cfl_list_init(&ctx->dynamic_tenant_list);
    result = pthread_mutex_init(&ctx->remove_mpa_list_lock, NULL);
    if (result != 0) {
        flb_errno();
        flb_plg_error(ins, "cannot initialize remove_mpa list lock");
        loki_config_destroy(ctx);
        return -1;
    }

    cfl_list_init(&ctx->remove_mpa_list);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins,
                 "configured, hostname=%s:%i",
                 ctx->tcp_host, ctx->tcp_port);
    return 0;
}

static flb_sds_t loki_compose_payload(struct flb_loki *ctx,
                                      int total_records,
                                      char *tag, int tag_len,
                                      const void *data, size_t bytes,
                                      flb_sds_t *dynamic_tenant_id,
                                      struct flb_mp_accessor *remove_mpa,
                                      struct flb_config *config)
{
    // int mp_ok = MSGPACK_UNPACK_SUCCESS;
    // size_t off = 0;
    flb_sds_t json;
    // struct flb_time tms;
    // msgpack_unpacked result;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    // msgpack_object *obj;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    /*
     * Fluent Bit uses Loki API v1 to push records in JSON format, this
     * is the expected structure:
     *
     * {
     *   "streams": [
     *     {
     *       "stream": {
     *         "label": "value"
     *       },
     *       "values": [
     *         [ "<unix epoch in nanoseconds>", "<log line>" ],
     *         [ "<unix epoch in nanoseconds>", "<log line>" ]
     *       ]
     *     }
     *   ]
     * }
     *
     * As of Loki 3.0, log entries may optionally contain a third element which is a JSON
     * object indicating structured metadata:
     *
     * "values": [
     *     [ "<unix epoch in nanoseconds>", "<log line>", {"trace_id": "0242ac120002"}]
     * ]
     */

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Main map */
    msgpack_pack_map(&mp_pck, 1);

    /* streams */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "streams", 7);

    if (ctx->ra_used == 0 && ctx->auto_kubernetes_labels == FLB_FALSE) {
        /*
         * If labels are cached, there is no record accessor or custom
         * keys, so it's safe to put one main stream and attach all the
         * values.
         */
        msgpack_pack_array(&mp_pck, 1);

        /* map content: streams['stream'] & streams['values'] */
        msgpack_pack_map(&mp_pck, 2);

        /* streams['stream'] */
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "stream", 6);

        /* Pack stream labels */
        pack_labels(ctx, &mp_pck, tag, tag_len, NULL);

        /* streams['values'] */
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "values", 6);
        msgpack_pack_array(&mp_pck, total_records);

        while ((ret = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
            msgpack_pack_array(&mp_pck, ctx->structured_metadata ||
                               ctx->structured_metadata_map_keys ? 3 : 2);

            /* Append the timestamp */
            pack_timestamp(&mp_pck, &log_event.timestamp);
            pack_record(ctx, &mp_pck, log_event.body, dynamic_tenant_id, remove_mpa, config);
            if (ctx->structured_metadata || ctx->structured_metadata_map_keys) {
                pack_structured_metadata(ctx, &mp_pck, tag, tag_len, NULL, config);
            }
        }
    }
    else {
        /*
         * Here there are no cached labels and the labels are composed by
         * each record content. To simplify the operation just create
         * one stream per record.
         */
        msgpack_pack_array(&mp_pck, total_records);

        while ((ret = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
            /* map content: streams['stream'] & streams['values'] */
            msgpack_pack_map(&mp_pck, 2);

            /* streams['stream'] */
            msgpack_pack_str(&mp_pck, 6);
            msgpack_pack_str_body(&mp_pck, "stream", 6);

            /* Pack stream labels */
            pack_labels(ctx, &mp_pck, tag, tag_len, log_event.body);

            /* streams['values'] */
            msgpack_pack_str(&mp_pck, 6);
            msgpack_pack_str_body(&mp_pck, "values", 6);
            msgpack_pack_array(&mp_pck, 1);

            msgpack_pack_array(&mp_pck, ctx->structured_metadata ||
                               ctx->structured_metadata_map_keys ? 3 : 2);

            /* Append the timestamp */
            pack_timestamp(&mp_pck, &log_event.timestamp);
            pack_record(ctx, &mp_pck, log_event.body, dynamic_tenant_id, remove_mpa, config);
            if (ctx->structured_metadata || ctx->structured_metadata_map_keys) {
                pack_structured_metadata(ctx, &mp_pck, tag, tag_len, log_event.body, config);
            }
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                       config->json_escape_unicode);

    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;
}

static void payload_release(void *payload, int compressed)
{
    if (compressed) {
        flb_free(payload);
    }
    else {
        flb_sds_destroy(payload);
    }
}

static void cb_loki_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    flb_sds_t payload = NULL;
    flb_sds_t out_buf = NULL;
    size_t out_size;
    int compressed = FLB_FALSE;
    struct flb_loki *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_loki_dynamic_tenant_id_entry *dynamic_tenant_id;
    struct flb_loki_remove_mpa_entry *remove_mpa_entry;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    dynamic_tenant_id = FLB_TLS_GET(thread_local_tenant_id);

    remove_mpa_entry = FLB_TLS_GET(thread_local_remove_mpa);

    if (remove_mpa_entry == NULL) {
        remove_mpa_entry = remove_mpa_entry_create(ctx);
        if (!remove_mpa_entry) {
            flb_plg_error(ctx->ins, "cannot allocate remove_mpa entry");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        FLB_TLS_SET(thread_local_remove_mpa, remove_mpa_entry);

        pthread_mutex_lock(&ctx->remove_mpa_list_lock);
        cfl_list_add(&remove_mpa_entry->_head, &ctx->remove_mpa_list);
        pthread_mutex_unlock(&ctx->remove_mpa_list_lock);
    }

    if (dynamic_tenant_id == NULL) {
        dynamic_tenant_id = dynamic_tenant_id_create();

        if (dynamic_tenant_id == NULL) {
            flb_errno();
            flb_plg_error(ctx->ins, "cannot allocate dynamic tenant id");

            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        FLB_TLS_SET(thread_local_tenant_id, dynamic_tenant_id);

        pthread_mutex_lock(&ctx->dynamic_tenant_list_lock);

        cfl_list_add(&dynamic_tenant_id->_head, &ctx->dynamic_tenant_list);

        pthread_mutex_unlock(&ctx->dynamic_tenant_list_lock);
    }

    /* Format the data to the expected Newrelic Payload */
    payload = loki_compose_payload(ctx,
                                   event_chunk->total_events,
                                   (char *) event_chunk->tag,
                                   flb_sds_len(event_chunk->tag),
                                   event_chunk->data, event_chunk->size,
                                   &dynamic_tenant_id->value,
                                   remove_mpa_entry->mpa,
                                   config);

    if (!payload) {
        flb_plg_error(ctx->ins, "cannot compose request payload");

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Map buffer */
    out_buf = payload;
    out_size = flb_sds_len(payload);

    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) payload, flb_sds_len(payload), (void **) &out_buf, &out_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        } else {
            compressed = FLB_TRUE;
            /* payload is not longer needed */
            flb_sds_destroy(payload);
        }
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");

        payload_release(out_buf, compressed);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        out_buf, out_size,
                        ctx->tcp_host, ctx->tcp_port,
                        NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");

        payload_release(out_buf, compressed);
        flb_upstream_conn_release(u_conn);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Set response buffer size */
    flb_http_buffer_size(c, ctx->http_buffer_max_size);

    /* Set callback context to the HTTP client context */
    flb_http_set_callback_context(c, ctx->ins->callback);

    /* User Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Auth headers */
    if (ctx->http_user && ctx->http_passwd) { /* Basic */
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    } else if (ctx->bearer_token) { /* Bearer token */
        flb_http_bearer_auth(c, ctx->bearer_token);
    }

    /* Arbitrary additional headers */
    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    /* Add Content-Type header */
    flb_http_add_header(c,
                        FLB_LOKI_CT, sizeof(FLB_LOKI_CT) - 1,
                        FLB_LOKI_CT_JSON, sizeof(FLB_LOKI_CT_JSON) - 1);

    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Add X-Scope-OrgID header */
    if (dynamic_tenant_id->value != NULL) {
        flb_http_add_header(c,
                            FLB_LOKI_HEADER_SCOPE, sizeof(FLB_LOKI_HEADER_SCOPE) - 1,
                            dynamic_tenant_id->value,
                            flb_sds_len(dynamic_tenant_id->value));
    }
    else if (ctx->tenant_id) {
        flb_http_add_header(c,
                            FLB_LOKI_HEADER_SCOPE, sizeof(FLB_LOKI_HEADER_SCOPE) - 1,
                            ctx->tenant_id, flb_sds_len(ctx->tenant_id));
    }

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    payload_release(out_buf, compressed);

    /* Validate HTTP client return status */
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status == 400) {
            /*
             * Loki will return 400 if incoming data is out of order.
             * We should not retry such data.
             */
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i Not retrying.\n%s",
                          ctx->tcp_host, ctx->tcp_port, c->resp.status,
                          c->resp.payload);
            out_ret = FLB_ERROR;
        }
        else if (c->resp.status >= 500 && c->resp.status <= 599) {
            if (c->resp.payload) {
                flb_plg_error(ctx->ins, "could not flush records to %s:%i"
                            " HTTP status=%i",
                            ctx->tcp_host, ctx->tcp_port, c->resp.status);
                flb_plg_trace(ctx->ins, "Response was:\n%s",
                            c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "could not flush records to %s:%i"
                            " HTTP status=%i",
                            ctx->tcp_host, ctx->tcp_port, c->resp.status);
            }
            /*
             * Server-side error occured, do not reuse this connection for retry.
             * This could be an issue of Loki gateway.
             * Rather initiate new connection.
             */
            flb_plg_trace(ctx->ins, "Destroying connection for %s:%i",
                          ctx->tcp_host, ctx->tcp_port);
            flb_upstream_conn_recycle(u_conn, FLB_FALSE);
            out_ret = FLB_RETRY;
        }
        else if (c->resp.status < 200 || c->resp.status > 205) {
            if (c->resp.payload) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->tcp_host, ctx->tcp_port, c->resp.status,
                              c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->tcp_host, ctx->tcp_port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->tcp_host, ctx->tcp_port,
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->tcp_host, ctx->tcp_port,
                              c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->tcp_host, ctx->tcp_port, ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(out_ret);
}

static void release_dynamic_tenant_ids(struct cfl_list *dynamic_tenant_list)
{
    struct cfl_list                         *iterator;
    struct cfl_list                         *backup;
    struct flb_loki_dynamic_tenant_id_entry *entry;

    cfl_list_foreach_safe(iterator, backup, dynamic_tenant_list) {
        entry = cfl_list_entry(iterator,
                               struct flb_loki_dynamic_tenant_id_entry,
                               _head);

        dynamic_tenant_id_destroy(entry);
    }
}

static void release_remove_mpa_entries(struct cfl_list *remove_mpa_list)
{
    struct cfl_list                    *iterator;
    struct cfl_list                    *backup;
    struct flb_loki_remove_mpa_entry   *entry;

    cfl_list_foreach_safe(iterator, backup, remove_mpa_list) {
        entry = cfl_list_entry(iterator,
                               struct flb_loki_remove_mpa_entry,
                               _head);

        remove_mpa_entry_destroy(entry);
    }
}

static int cb_loki_exit(void *data, struct flb_config *config)
{
    struct flb_loki *ctx = data;

    if (!ctx) {
        return 0;
    }

    pthread_mutex_lock(&ctx->dynamic_tenant_list_lock);

    release_dynamic_tenant_ids(&ctx->dynamic_tenant_list);

    pthread_mutex_unlock(&ctx->dynamic_tenant_list_lock);

    pthread_mutex_lock(&ctx->remove_mpa_list_lock);

    release_remove_mpa_entries(&ctx->remove_mpa_list);

    pthread_mutex_unlock(&ctx->remove_mpa_list_lock);

    loki_config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "uri", FLB_LOKI_URI,
     0, FLB_TRUE, offsetof(struct flb_loki, uri),
     "Specify a custom HTTP URI. It must start with forward slash."
    },

    {
     FLB_CONFIG_MAP_STR, "tenant_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, tenant_id),
     "Tenant ID used by default to push logs to Loki. If omitted or empty "
     "it assumes Loki is running in single-tenant mode and no X-Scope-OrgID "
     "header is sent."
    },

    {
     FLB_CONFIG_MAP_STR, "tenant_id_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, tenant_id_key_config),
     "If set, X-Scope-OrgID will be the value of the key from incoming record. "
     "It is useful to set X-Scode-OrgID dynamically."
    },

    {
     FLB_CONFIG_MAP_CLIST, "labels", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, labels),
     "labels for API requests. If no value is set, the default label is 'job=fluent-bit'"
    },

    {
     FLB_CONFIG_MAP_CLIST, "structured_metadata", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, structured_metadata),
     "optional structured metadata fields for API requests."
    },

    {
     FLB_CONFIG_MAP_CLIST, "structured_metadata_map_keys", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, structured_metadata_map_keys),
     "optional structured metadata fields, as derived dynamically from configured maps "
     "keys, for API requests."
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_kubernetes_labels", "false",
     0, FLB_TRUE, offsetof(struct flb_loki, auto_kubernetes_labels),
     "If set to true, it will add all Kubernetes labels to Loki labels.",
    },

    {
     FLB_CONFIG_MAP_STR, "drop_single_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, drop_single_key),
     "If set to true and only a single key remains, the log line sent to Loki "
     "will be the value of that key. If set to 'raw' and the log line is "
     "a string, the log line will be sent unquoted.",
    },

    {
     FLB_CONFIG_MAP_CLIST, "label_keys", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, label_keys),
     "Comma separated list of keys to use as stream labels."
    },

    {
     FLB_CONFIG_MAP_CLIST, "remove_keys", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, remove_keys),
     "Comma separated list of keys to remove."
    },

    {
     FLB_CONFIG_MAP_STR, "line_format", "json",
     0, FLB_TRUE, offsetof(struct flb_loki, line_format),
     "Format to use when flattening the record to a log line. Valid values are "
     "'json' or 'key_value'. If set to 'json' the log line sent to Loki will be "
     "the Fluent Bit record dumped as json. If set to 'key_value', the log line "
     "will be each item in the record concatenated together (separated by a "
     "single space) in the format '='."
    },

    {
     FLB_CONFIG_MAP_STR, "label_map_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, label_map_path),
     "A label map file path"
    },

    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, http_user),
     "Set HTTP auth user"
    },

    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_loki, http_passwd),
     "Set HTTP auth password"
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "512KB",
     0, FLB_TRUE, offsetof(struct flb_loki, http_buffer_max_size),
     "Maximum HTTP response buffer size in bytes"
    },

    {
     FLB_CONFIG_MAP_STR, "bearer_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, bearer_token),
     "Set bearer token auth"
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_loki, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },

    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression in network transfer. Option available is 'gzip'"
    },

    /* EOF */
    {0}
};

/* for testing */
static int cb_loki_format_test(struct flb_config *config,
                               struct flb_input_instance *ins,
                               void *plugin_context,
                               void *flush_ctx,
                               int event_type,
                               const char *tag, int tag_len,
                               const void *data, size_t bytes,
                               void **out_data, size_t *out_size)
{
    int total_records;
    flb_sds_t payload = NULL;
    flb_sds_t dynamic_tenant_id;
    struct flb_loki *ctx = plugin_context;

    dynamic_tenant_id = NULL;

    /* Count number of records */
    total_records = flb_mp_count(data, bytes);

    payload = loki_compose_payload(ctx, total_records,
                                   (char *) tag, tag_len, data, bytes,
                                   &dynamic_tenant_id,
                                   ctx->remove_mpa,
                                   config);
    if (payload == NULL) {
        if (dynamic_tenant_id != NULL) {
            flb_sds_destroy(dynamic_tenant_id);
        }

        return -1;
    }

    *out_data = payload;
    *out_size = flb_sds_len(payload);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_loki_plugin = {
    .name        = "loki",
    .description = "Loki",
    .cb_init     = cb_loki_init,
    .cb_flush    = cb_loki_flush,
    .cb_exit     = cb_loki_exit,
    .config_map  = config_map,

    /* for testing */
    .test_formatter.callback = cb_loki_format_test,

    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
