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

#ifndef FLB_CONFIG_MAP_H
#define FLB_CONFIG_MAP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>
#include <cfl/cfl.h>

/* Configuration types */
#define FLB_CONFIG_MAP_STR         0    /* string */
#define FLB_CONFIG_MAP_STR_PREFIX  1    /* string that starts with  */
#define FLB_CONFIG_MAP_INT         2    /* integer */
#define FLB_CONFIG_MAP_BOOL        3    /* boolean */
#define FLB_CONFIG_MAP_DOUBLE      4    /* double */
#define FLB_CONFIG_MAP_SIZE        5    /* string size to integer (e.g: 2M) */
#define FLB_CONFIG_MAP_TIME        6    /* string time to integer seconds (e.g: 2H) */
#define FLB_CONFIG_MAP_DEPRECATED  7    /* for deprecated parameter */

#define FLB_CONFIG_MAP_CLIST    30   /* comma separated list of strings */
#define FLB_CONFIG_MAP_CLIST_1  31   /* split up to 1 node  + remaining data */
#define FLB_CONFIG_MAP_CLIST_2  32   /* split up to 2 nodes + remaining data */
#define FLB_CONFIG_MAP_CLIST_3  33   /* split up to 3 nodes + remaining data */
#define FLB_CONFIG_MAP_CLIST_4  34   /* split up to 4 nodes + remaining data */

#define FLB_CONFIG_MAP_SLIST     40   /* empty space separated list of strings */
#define FLB_CONFIG_MAP_SLIST_1   41   /* split up to 1 node  + remaining data */
#define FLB_CONFIG_MAP_SLIST_2   42   /* split up to 2 nodes + remaining data */
#define FLB_CONFIG_MAP_SLIST_3   43   /* split up to 3 nodes + remaining data */
#define FLB_CONFIG_MAP_SLIST_4   44   /* split up to 4 nodes + remaining data */

#define FLB_CONFIG_MAP_VARIANT   50   /* variant that wraps a kvlist or array */

#define FLB_CONFIG_MAP_MULT       1

struct flb_config_map_val {
    union {
        int i_num;                    /* FLB_CONFIG_MAP_INT */
        int boolean;                  /* FLB_CONFIG_MAP_BOOL */
        double d_num;                 /* FLB_CONFIG_MAP_DOUBLE */
        size_t s_num;                 /* FLB_CONFIG_MAP_SIZE */
        flb_sds_t str;                /* FLB_CONFIG_MAP_STR */
        struct mk_list *list;         /* FLB_CONFIG_MAP_CLIST and FLB_CONFIG_MAP_SLIST */
        struct cfl_variant *variant;  /* FLB_CONFIG_MAP_VARIANT */
    } val;
    struct mk_list *mult;
    struct mk_list _head;             /* Link to list if this entry is a 'multiple' entry */
};

struct flb_config_map {
    /* Public fields used by plugins at registration */
    int type;                      /* type */
    flb_sds_t name;                /* property name */
    flb_sds_t def_value;           /* default value */
    int flags;                     /* option flags (e.g: multiple entries allowed) */
    int set_property;              /* set context property ? (use offset ?) */
    uintptr_t offset;              /* member offset */
    flb_sds_t desc;                /* description */

    struct flb_config_map_val value; /* lookup value */
    struct mk_list _head;
};

#define flb_config_map_foreach(curr, v, head)                           \
    for (curr = (head)->next, v = mk_list_entry(curr,                   \
                                                struct flb_config_map_val, \
                                                _head);                 \
         curr != (head); curr = curr->next, v = mk_list_entry(curr,     \
                                                              struct flb_config_map_val, \
                                                              _head))

static inline int flb_config_map_mult_type(int type)
{
    if (type >= FLB_CONFIG_MAP_CLIST && type <= FLB_CONFIG_MAP_CLIST_4) {
        return FLB_CONFIG_MAP_CLIST;
    }

    if (type >= FLB_CONFIG_MAP_SLIST && type <= FLB_CONFIG_MAP_SLIST_4) {
        return FLB_CONFIG_MAP_SLIST;
    }

    return -1;
}

int flb_config_map_properties_check(char *context_name,
                                    struct mk_list *in_properties,
                                    struct mk_list *map);
struct mk_list *flb_config_map_create(struct flb_config *config,
                                      struct flb_config_map *map);
void flb_config_map_destroy(struct mk_list *list);
int flb_config_map_expected_values(int type);
int flb_config_map_set(struct mk_list *properties, struct mk_list *map, void *context);

#endif
