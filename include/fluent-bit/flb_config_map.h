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

#ifndef FLB_CONFIG_MAP_H
#define FLB_CONFIG_MAP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

/* Configuration types */
#define FLB_CONFIG_MAP_STR      0    /* string */
#define FLB_CONFIG_MAP_INT      1    /* integer */
#define FLB_CONFIG_MAP_BOOL     2    /* boolean */
#define FLB_CONFIG_MAP_DOUBLE   3    /* double */
#define FLB_CONFIG_MAP_SIZE     4    /* string size to integer (e.g: 2M) */

#define FLB_CONFIG_MAP_CLIST    30   /* comma separated list of strings */
#define FLB_CONFIG_MAP_CLIST_1  31   /* split up to 1 node  + remaining data */
#define FLB_CONFIG_MAP_CLIST_2  32   /* split up to 2 nodes + remaining data */
#define FLB_CONFIG_MAP_CLIST_3  33   /* split up to 3 nodes + remaining data */
#define FLB_CONFIG_MAP_CLIST_4  34   /* split up to 4 nodes + remaining data */

#define FLB_CONFIG_MAP_SLIST    40   /* empty space separated list of strings */
#define FLB_CONFIG_MAP_SLIST_1  41   /* split up to 1 node  + remaining data */
#define FLB_CONFIG_MAP_SLIST_2  42   /* split up to 2 nodes + remaining data */
#define FLB_CONFIG_MAP_SLIST_3  43   /* split up to 3 nodes + remaining data */
#define FLB_CONFIG_MAP_SLIST_4  44   /* split up to 4 nodes + remaining data */

typedef union {
    int boolean;                  /* FLB_CONFIG_MAP_BOOL */
    int i_num;                    /* FLB_CONFIG_MAP_INT */
    double d_num;                 /* FLB_CONFIG_MAP_DOUBLE */
    size_t s_num;                 /* FLB_CONFIG_MAP_SIZE */
    flb_sds_t str;                /* FLB_CONFIG_MAP_STR */
    struct mk_list *list;         /* FLB_CONFIG_MAP_CLIST and FLB_CONFIG_MAP_SLIST */
} config_map_val;

struct flb_config_map {
    int type;                     /* type */
    flb_sds_t name;               /* property name */
    flb_sds_t def_value;          /* default value */
    uintptr_t offset;             /* member offset */
    flb_sds_t desc;               /* description */

    /* Fields used when generating a new registration in the heap */
    config_map_val value;         /* lookup value */
    struct mk_list _head;         /* */
};

int flb_config_map_properties_check(char *context_name,
                                    struct mk_list *in_properties,
                                    struct mk_list *map);
struct mk_list *flb_config_map_create(struct flb_config_map *map);
void flb_config_map_destroy(struct mk_list *list);
int flb_config_map_set(struct mk_list *properties, struct mk_list *map, void *context);

#endif
