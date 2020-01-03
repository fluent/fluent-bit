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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config_map.h>

/*
 * Given a string, split the content using it proper separator generating a linked
 * list of 'slist'
 */
static struct mk_list *parse_string_map_to_list(struct flb_config_map *map, char *str)
{
    int ret = -1;
    int type;
    int max_split = -1;
    struct mk_list *list;

    type = map->type;

    /* Allocate list head */
    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    /* Determinate the max split value based on it type */
    if (map->type > FLB_CONFIG_MAP_CLIST && map->type < FLB_CONFIG_MAP_SLIST) {
        type = FLB_CONFIG_MAP_CLIST;
        max_split = (map->type - FLB_CONFIG_MAP_CLIST);
    }
    else if (map->type > FLB_CONFIG_MAP_SLIST) {
        type = FLB_CONFIG_MAP_SLIST;
        max_split = (map->type - FLB_CONFIG_MAP_SLIST);
    }

    if (type == FLB_CONFIG_MAP_CLIST) {
        ret = flb_slist_split_string(list, str, ',', max_split);
    }
    else if (type == FLB_CONFIG_MAP_SLIST) {
        ret = flb_slist_split_string(list, str, ' ', max_split);
    }

    if (ret == -1) {
        flb_error("[config map] error reading list of options");
        flb_free(list);
        return NULL;
    }

    return list;
}

static int translate_default_value(struct flb_config_map *map, char *val)
{
    int ret;
    struct flb_config_map_val *entry = NULL;
    struct mk_list *list = NULL;

    /* Prepare contexts if the map allows multiple entries */
    if (map->flags & FLB_CONFIG_MAP_MULT) {
        entry = flb_calloc(1, sizeof(struct flb_config_map_val));
        if (!entry) {
            flb_errno();
            /*
             * do not worry about 'list' allocation, it will be destroyed by the caller
             * when it catches this error
             */
            return -1;
        }
    }
    else {
        entry = &map->value;
    }

    /* Based on specific data types, populate 'value' */
    if (map->type == FLB_CONFIG_MAP_STR) {
        /* Duplicate string as a flb_sds_t */
        entry->val.str = flb_sds_create(val);

        /* Validate new memory allocation */
        if (!entry->val.str) {
            goto error;
        }
    }
    else if (map->type == FLB_CONFIG_MAP_BOOL) {
        ret = flb_utils_bool(val);
        if (ret == -1) {
            flb_error("[config map] invalid default value for boolean '%s=%s'",
                      map->name, val);
            goto error;
        }
        entry->val.boolean = flb_utils_bool(val);
    }
    else if (map->type == FLB_CONFIG_MAP_INT) {
        entry->val.i_num = atoi(val);
    }
    else if (map->type == FLB_CONFIG_MAP_DOUBLE) {
        entry->val.d_num = atof(val);
    }
    else if (map->type == FLB_CONFIG_MAP_SIZE) {
        entry->val.s_num = flb_utils_size_to_bytes(val);
    }
    else if (map->type >= FLB_CONFIG_MAP_CLIST &&
             map->type <= FLB_CONFIG_MAP_SLIST_4) {

        list = parse_string_map_to_list(map, val);
        if (!list) {
            flb_error("[config map] cannot parse list of values '%s'", val);
            goto error;
        }

        entry->val.list = list;
        list = NULL;
    }

    if (map->flags & FLB_CONFIG_MAP_MULT) {
        mk_list_add(&entry->_head, map->value.mult);
    }

    return 0;

 error:
    if (map->flags & FLB_CONFIG_MAP_MULT) {
        flb_free(entry);
    }
    return -1;
}

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
    struct mk_list *tmp;
    struct mk_list *list;
    struct flb_config_map *new = NULL;
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
        new->flags = m->flags;
        new->set_property = m->set_property;
        new->offset = m->offset;
        new->value.mult = NULL;
        mk_list_add(&new->_head, list);

        if (new->set_property == FLB_FALSE) {
            m++;
            continue;
        }

        /* If this is a multiple type of entries, initialize the main list */
        if (new->flags & FLB_CONFIG_MAP_MULT) {
            tmp = flb_malloc(sizeof(struct mk_list));
            if (!tmp) {
                flb_errno();
                flb_config_map_destroy(list);
                return NULL;
            }
            mk_list_init(tmp);
            new->value.mult = tmp;
        }

        /*
         * If there is no default value or the entry will not be set,  just
         * continue with the next map entry
         */
        if (!m->def_value) {
            m++;
            continue;
        }

        /* Assign value based on data type and multiple mode if set */
        ret = translate_default_value(new, m->def_value);
        if (ret == -1) {
            flb_config_map_destroy(list);
            return NULL;
        }
        m++;
    }

    return list;
}

static void destroy_map_val(int type, struct flb_config_map_val *value)
{
    if (type == FLB_CONFIG_MAP_STR && value->val.str) {
        flb_sds_destroy(value->val.str);
    }
    else if ((type >= FLB_CONFIG_MAP_CLIST &&
              type <= FLB_CONFIG_MAP_SLIST_4) &&
             value->val.list) {
        flb_slist_destroy(value->val.list);
        flb_free(value->val.list);
    }
}

/* Destroy a config map context */
void flb_config_map_destroy(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *v_head;
    struct mk_list *v_tmp;
    struct flb_config_map *map;
    struct flb_config_map_val *entry;

    mk_list_foreach_safe(head, tmp, list) {
        map = mk_list_entry(head, struct flb_config_map, _head);
        mk_list_del(&map->_head);

        if (map->flags & FLB_CONFIG_MAP_MULT && map->value.mult) {
            mk_list_foreach_safe(v_head, v_tmp, map->value.mult) {
                entry = mk_list_entry(v_head, struct flb_config_map_val, _head);
                mk_list_del(&entry->_head);
                destroy_map_val(map->type, entry);
                flb_free(entry);
            }
            flb_free(map->value.mult);
        }
        else {
            destroy_map_val(map->type, &map->value);
        }
        flb_sds_destroy(map->name);
        flb_free(map);
    }
    flb_free(list);
}

/* Count the number of times a property key exists */
int property_count(char *key, int len, struct mk_list *properties)
{
    int count = 0;
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_len(kv->key) != len) {
            continue;
        }

        if (strncmp(kv->key, key, len) == 0) {
            count++;
        }
    }
    return count;
}

/* Validate that the incoming properties set by the caller are allowed by the plugin */
int flb_config_map_properties_check(char *context_name,
                                    struct mk_list *in_properties,
                                    struct mk_list *map)
{
    int len;
    int found;
    int count = 0;
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

        /* Validate number of times the property is set */
        count = property_count(kv->key, flb_sds_len(kv->key), in_properties);
        if ((m->flags & FLB_CONFIG_MAP_MULT) == 0) {
            if (count > 1) {
                flb_error("[config] %s: configuration property '%s' is set %i times",
                          context_name, kv->key, count);
                return -1;
            }
        }
    }

    return 0;
}

/*
 * Returns FLB_TRUE or FLB_FALSE if a property aims to override the default value
 * assigned to the map key valled 'name'.
 */
static int properties_override_default(struct mk_list *properties, char *name)
{
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(kv->key, name) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/*
 * Function used by plugins that needs to populate their context structure with the
 * configuration properties already mapped.
 */
int flb_config_map_set(struct mk_list *properties, struct mk_list *map, void *context)
{
    int ret;
    char *base;
    char *m_bool;
    int *m_i_num;
    double *m_d_num;
    size_t *m_s_num;
    flb_sds_t *m_str;
    struct flb_kv *kv;
    struct mk_list *head;
    struct mk_list *m_head;
    struct mk_list **m_list;
    struct mk_list *list;
    struct flb_config_map *m = NULL;
    struct flb_config_map_val *entry = NULL;

    base = context;

    /* Link 'already processed default values' into the caller context */
    mk_list_foreach(m_head, map) {
        m = mk_list_entry(m_head, struct flb_config_map, _head);

        /*
         * If the map type allows multiple entries, the user context is a pointer
         * for a linked list. We just point their structure to our pre-processed
         * list of entries.
         */
        if (m->flags & FLB_CONFIG_MAP_MULT) {
            m_list = (struct mk_list **) (base + m->offset);
            *m_list = m->value.mult;
            continue;
        }

        /*
         * If no default value exists or the map will not write to the user
         * context.. skip it.
         */
        if (!m->def_value || m->set_property == FLB_FALSE) {
            continue;
        }

        /*
         * If a property set by the user will override the default value, just
         * do not put the default value into the context since it will be replaced
         * later.
         */
        ret = properties_override_default(properties, m->name);
        if (ret == FLB_TRUE) {
            continue;
        }


        /* All the following steps are direct writes to the user context */
        if (m->type == FLB_CONFIG_MAP_STR) {
            m_str = (char **) (base + m->offset);
            *m_str = m->value.val.str;
        }
        else if (m->type == FLB_CONFIG_MAP_INT) {
            m_i_num = (int *) (base + m->offset);
            *m_i_num = m->value.val.i_num;
        }
        else if (m->type == FLB_CONFIG_MAP_DOUBLE) {
            m_d_num = (double *) (base + m->offset);
            *m_d_num = m->value.val.d_num;
        }
        else if (m->type == FLB_CONFIG_MAP_SIZE) {
            m_s_num = (size_t *) (base + m->offset);
            *m_s_num = m->value.val.s_num;
        }
        else if (m->type == FLB_CONFIG_MAP_BOOL) {
            m_bool = (char *) (base + m->offset);
            *m_bool = m->value.val.boolean;
        }
        else if (m->type >= FLB_CONFIG_MAP_CLIST ||
                 m->type <= FLB_CONFIG_MAP_SLIST_4) {
            m_list = (struct mk_list **) (base + m->offset);
            *m_list = m->value.val.list;
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
            if (strncasecmp(kv->key, m->name, flb_sds_len(m->name)) == 0) {
                break;
            }
            m = NULL;
            continue;

        }

        if (!m || m->set_property == FLB_FALSE) {
            continue;
        }

        /* Check if the map allows multiple entries */
        if (m->flags & FLB_CONFIG_MAP_MULT) {
            /* Create node */
            entry = flb_malloc(sizeof(struct flb_config_map_val));
            if (!entry) {
                flb_errno();
                return -1;
            }

            /* Populate value */
            if (m->type == FLB_CONFIG_MAP_STR) {
                entry->val.str = kv->val;
            }
            else if (m->type == FLB_CONFIG_MAP_INT) {
                entry->val.i_num = atoi(kv->val);
            }
            else if (m->type == FLB_CONFIG_MAP_DOUBLE) {
                entry->val.d_num = atof(kv->val);
            }
            else if (m->type == FLB_CONFIG_MAP_SIZE) {
                entry->val.s_num = flb_utils_size_to_bytes(kv->val);
            }
            else if (m->type == FLB_CONFIG_MAP_BOOL) {
                ret = flb_utils_bool(kv->val);
                if (ret == -1) {
                    flb_free(entry);
                    flb_error("[config map] invalid value for boolean property '%s=%s'",
                              m->name, kv->val);
                    return -1;
                }
                entry->val.boolean = ret;
            }
            else if (m->type >= FLB_CONFIG_MAP_CLIST ||
                     m->type <= FLB_CONFIG_MAP_SLIST_4) {

                list = parse_string_map_to_list(m, kv->val);
                if (!list) {
                    flb_error("[config map] cannot parse list of values '%s'", kv->val);
                    flb_free(entry);
                    return -1;
                }
                entry->val.list = list;
            }

            /* Add entry to the map 'mult' list tail */
            mk_list_add(&entry->_head, m->value.mult);

            /* Override user context */
            m_list = (struct mk_list **) (base + m->offset);
            *m_list = m->value.mult;
        }
        else if (map != NULL) {
            /* Direct write to user context */
            if (m->type == FLB_CONFIG_MAP_STR) {
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
            else if (m->type == FLB_CONFIG_MAP_SIZE) {
                m_s_num = (size_t *) (base + m->offset);
                *m_s_num = flb_utils_size_to_bytes(kv->val);
            }
            else if (m->type == FLB_CONFIG_MAP_BOOL) {
                m_bool = (char *) (base + m->offset);
                ret = flb_utils_bool(kv->val);
                if (ret == -1) {
                    flb_error("[config map] invalid value for boolean property '%s=%s'",
                              m->name, kv->val);
                    return -1;
                }
                *m_bool = ret;
            }
            else if (m->type >= FLB_CONFIG_MAP_CLIST ||
                     m->type <= FLB_CONFIG_MAP_SLIST_4) {
                list = parse_string_map_to_list(m, kv->val);
                if (!list) {
                    flb_error("[config map] cannot parse list of values '%s'", kv->val);
                    flb_free(entry);
                    return -1;
                }

                if (m->value.val.list) {
                    destroy_map_val(m->type, &m->value);
                }

                m->value.val.list = list;
                m_list = (struct mk_list **) (base + m->offset);
                *m_list = m->value.val.list;
            }
        }
    }

    return 0;
}
