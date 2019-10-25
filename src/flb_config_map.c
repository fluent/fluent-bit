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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config_map.h>

static flb_sds_t helper_map_options(struct mk_list *map)
{
    flb_sds_t buf;
    flb_sds_t tmp;
    struct mk_list *head;
    struct flb_config_map *m;

    buf = flb_sds_create_size(256);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    tmp = flb_sds_printf(&buf, "The following properties are allowed: ");
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(buf);
        return NULL;
    }
    buf = tmp;

    mk_list_foreach(head, map) {
        m = mk_list_entry(head, struct flb_config_map, _head);
        if (head->next != map) {
            tmp = flb_sds_printf(&buf, "%s, ", m->name);
        }
        else {
            tmp = flb_sds_printf(&buf, "and %s.", m->name);
        }

        if (!tmp) {
            flb_errno();
            flb_sds_destroy(buf);
            return NULL;
        }
        buf = tmp;
    }

    return buf;
}

/*
 * Given a static plugin configuration map, create a linked list representation. We use a
 * linked list using heap memory instead of the stack since a plugin can be loaded multiple
 * times.
 *
 * In addition, for default values, we process them and populate the 'value' field with
 * proper data types.
 */
struct mk_list *flb_config_map_create(struct flb_config_map *map)
{
    int ret;
    int type;
    int max_split = 0;
    struct mk_list *tmp;
    struct mk_list *list;
    struct flb_config_map *new;
    struct flb_config_map *m;

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    /*
     * Read every property defined in the config map and create a new dynamic list
     * with the same content.
     *
     * As an additional step, it populate the 'value' field using the given default
     * value if any. Note that default values are strings so they are processed
     * to fit into the proper data type of 'value'.
     */
    m = map;
    while (m && m->name) {
        /* Allocate map node */
        new = flb_calloc(1, sizeof(struct flb_config_map));
        if (!new) {
            flb_errno();
            flb_config_map_destroy(list);
            return NULL;
        }

        new->type = m->type;
        new->name = flb_sds_create(m->name);
        new->def_value = m->def_value;
        new->offset = m->offset;
        mk_list_add(&new->_head, list);

        /* If there is no default value, just continue with the next map entry */
        if (!m->def_value) {
            m++;
            continue;
        }

        /* Based on specific data types, populate 'value' */
        if (m->type == FLB_CONFIG_MAP_STR) {
            /* Duplicate string as a flb_sds_t */
            new->value.str = flb_sds_create(m->def_value);

            /* Validate new memory allocation */
            if (!new->value.str) {
                flb_config_map_destroy(list);
                return NULL;
            }
        }
        else if (m->type == FLB_CONFIG_MAP_BOOL) {
            new->value.boolean = flb_utils_bool(m->def_value);
        }
        else if (m->type == FLB_CONFIG_MAP_INT) {
            new->value.i_num = atoi(m->def_value);
        }
        else if (m->type == FLB_CONFIG_MAP_DOUBLE) {
            new->value.d_num = atof(m->def_value);
        }
        else if (new->type >= FLB_CONFIG_MAP_CLIST &&
                 new->type <= FLB_CONFIG_MAP_SLIST_4) {
            /*
             * A CLIST (comma separated list) or SLIST (empty space separated list) are
             * values that needs to be processed. Here we create a linked list head
             * that then we use to populate it through the flb_slist_split_string()
             * function that do the parsing job.
             */
            tmp = flb_malloc(sizeof(struct mk_list));
            if (!tmp) {
                flb_errno();
                flb_config_map_destroy(list);
                return NULL;
            }

            /* Initialize slist */
            flb_slist_create(tmp);

            max_split = -1;
            type = new->type;
            if (new->type > FLB_CONFIG_MAP_CLIST && new->type < FLB_CONFIG_MAP_SLIST) {
                type = FLB_CONFIG_MAP_CLIST;
                max_split = (new->type - FLB_CONFIG_MAP_CLIST);
            }
            else if (new->type > FLB_CONFIG_MAP_SLIST) {
                type = FLB_CONFIG_MAP_SLIST;
                max_split = (new->type - FLB_CONFIG_MAP_SLIST);
            }

            /* Process string using proper separator */
            if (type == FLB_CONFIG_MAP_CLIST) {
                ret = flb_slist_split_string(tmp, m->def_value, ',', max_split);
            }
            else if (type == FLB_CONFIG_MAP_SLIST) {
                ret = flb_slist_split_string(tmp, m->def_value, ' ', max_split);
            }

            if (ret == -1) {
                flb_error("[config map] error reading default list of options");
                flb_free(tmp);
                flb_config_map_destroy(list);
                return NULL;
            }

            /* Assign linked list head to value field */
            new->value.list = tmp;
        }
        m++;
    }

    return list;
}

/* Destroy a config map context */
void flb_config_map_destroy(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_config_map *map;

    mk_list_foreach_safe(head, tmp, list) {
        map = mk_list_entry(head, struct flb_config_map, _head);
        mk_list_del(&map->_head);

        if (map->type == FLB_CONFIG_MAP_STR && map->value.str) {
            flb_sds_destroy(map->value.str);
        }
        else if ((map->type >= FLB_CONFIG_MAP_CLIST &&
                  map->type <= FLB_CONFIG_MAP_SLIST_4) &&
                 map->value.list) {
            flb_slist_destroy(map->value.list);
            flb_free(map->value.list);
        }

        flb_sds_destroy(map->name);
        flb_free(map);
    }
    flb_free(list);
}

/* Validate that the incoming properties set by the caller are allowed by the plugin */
int flb_config_map_properties_check(char *context_name,
                                    struct mk_list *in_properties,
                                    struct mk_list *map)
{
    int len;
    int found;
    flb_sds_t helper;
    struct flb_kv *kv;
    struct mk_list *head;
    struct mk_list *m_head;
    struct flb_config_map *m;

    /* Iterate all incoming property list */
    mk_list_foreach(head, in_properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        found = FLB_FALSE;

        /* Lookup the key into the provided map */
        mk_list_foreach(m_head, map) {
            m = mk_list_entry(m_head, struct flb_config_map, _head);
            len = flb_sds_len(m->name);
            if (len != flb_sds_len(kv->key)) {
                continue;
            }

            if (strncasecmp(kv->key, m->name, len) == 0) {
                found = FLB_TRUE;
                break;
            }
        }

        if (found == FLB_FALSE) {
            helper = helper_map_options(map);
            if (!helper) {
                flb_error("[config] %s: unknown configuration property '%s'",
                          context_name, kv->key);
            }
            else {
                flb_error("[config] %s: unknown configuration property '%s'. %s",
                          context_name, kv->key, helper);
                flb_sds_destroy(helper);
            }

            return -1;
        }
    }

    return 0;
}

/*
 * Function used by plugins that needs to populate their context structure with the
 * configuration properties already mapped.
 */
int flb_config_map_set(struct mk_list *properties, struct mk_list *map, void *context)
{
    int ret;
    int type;
    int max_split = -1;
    char *base;
    int *m_bool;
    int *m_i_num;
    double *m_d_num;
    flb_sds_t *m_str;
    struct flb_kv *kv;
    struct mk_list *head;
    struct mk_list *m_head;
    struct mk_list **m_list;
    struct flb_config_map *m = NULL;

    base = context;

    /* Link processed default values into caller context */
    mk_list_foreach(m_head, map) {
        m = mk_list_entry(m_head, struct flb_config_map, _head);
        if (!m->def_value) {
            continue;
        }

        if (m->type == FLB_CONFIG_MAP_STR) {
            m_str = (char **) (base + m->offset);
            *m_str = m->value.str;
        }
        else if (m->type == FLB_CONFIG_MAP_INT) {
            m_i_num = (int *) (base + m->offset);
            *m_i_num = m->value.i_num;
        }
        else if (m->type == FLB_CONFIG_MAP_DOUBLE) {
            m_d_num = (double *) (base + m->offset);
            *m_d_num = m->value.d_num;
        }
        else if (m->type == FLB_CONFIG_MAP_BOOL) {
            m_bool = (int *) (base + m->offset);
            *m_bool = m->value.boolean;
        }
        else if (m->type >= FLB_CONFIG_MAP_CLIST ||
                 m->type <= FLB_CONFIG_MAP_SLIST_4) {
            m_list = (struct mk_list **) (base + m->offset);
            *m_list = m->value.list;
        }
    }

    /*
     * Iterate all properties coming from the configuration reader. If a property overrides
     * a default value already set in the previous step, just link to the new value.
     */
    mk_list_foreach(head, properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        mk_list_foreach(m_head, map) {
            m = mk_list_entry(m_head, struct flb_config_map, _head);
            if (flb_sds_cmp(kv->key, m->name, flb_sds_len(m->name)) == 0) {
                break;
            }
            else {
                m = NULL;
                continue;
            }
        }

        if (!m) {
            continue;
        }

        if (m->type == FLB_CONFIG_MAP_STR) {
            /*
             * Do a direct mapping to the flb_kv value. This value will be destroyed
             * once the plugin exits.
             */
            m_str = (char **) (base + m->offset);
            *m_str = kv->val;
        }
        else if (m->type == FLB_CONFIG_MAP_INT) {
            m_i_num = (int *) (base + m->offset);
            *m_i_num = atoi(kv->val);
        }
        else if (m->type == FLB_CONFIG_MAP_DOUBLE) {
            m_d_num = (double *) (base + m->offset);
            *m_d_num = atof(kv->val);
        }
        else if (m->type == FLB_CONFIG_MAP_BOOL) {
            m_bool = (int *) (base + m->offset);
            *m_bool = flb_utils_bool(kv->val);
        }
        else if (m->type >= FLB_CONFIG_MAP_CLIST ||
                 m->type <= FLB_CONFIG_MAP_SLIST_4) {

            /*
             * Handling a new list is tricky, since the list already exists since it
             * was populated by a default value, we destroy the current context
             * and the new list created is assigned directly to the config map of
             * the instance so the caller don't need to worry about release the
             * resource.
             *
             * Destroying a slist, only destroy it nodes, not the list header.
             */
            if (m->value.list) {
                flb_slist_destroy(m->value.list);
            }

            max_split = -1;
            type = m->type;
            if (m->type > FLB_CONFIG_MAP_CLIST && m->type < FLB_CONFIG_MAP_SLIST) {
                type = FLB_CONFIG_MAP_CLIST;
                max_split = (m->type - FLB_CONFIG_MAP_CLIST);
            }
            else if (m->type > FLB_CONFIG_MAP_SLIST) {
                type = FLB_CONFIG_MAP_SLIST;
                max_split = (m->type - FLB_CONFIG_MAP_SLIST);
            }

            if (type == FLB_CONFIG_MAP_CLIST) {
                ret = flb_slist_split_string(m->value.list, kv->val, ',', max_split);
            }
            else if (type == FLB_CONFIG_MAP_SLIST) {
                ret = flb_slist_split_string(m->value.list, kv->val, ' ', max_split);
            }

            if (ret == -1) {
                flb_error("[config map] error reading list of options");
                return -1;
            }

            m_list = (struct mk_list **) (base + m->offset);
            *m_list = m->value.list;
        }
    }

    return 0;
}
