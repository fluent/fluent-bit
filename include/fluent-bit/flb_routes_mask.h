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

/*
 * This file defines a few utility methods for handling the routing masks
 * used by input chunks to keep track of which output plugins they are
 * routed to.
 */
#ifndef FLB_ROUTES_MASK_H
#define FLB_ROUTES_MASK_H

#include <limits.h>

/*
 * The routing mask is an array integers used to store a bitfield. Each
 * bit represents the unique id of an output plugin. For example, the 9th
 * bit in the routes_mask represents the output plugin with id = 9.
 *
 * A value of 1 in the bitfield means that output plugin is selected
 * and a value of zero means that output is deselected.
 */

typedef uint64_t flb_route_mask_element;

/*
 * How many bits are in each element of the bitmask array
 */
#define FLB_ROUTES_MASK_ELEMENT_BITS (sizeof(flb_route_mask_element) * CHAR_BIT)

/* forward declaration */
struct flb_input_instance;
struct flb_config;
struct flb_router;

int flb_routes_mask_set_by_tag(flb_route_mask_element *routes_mask, 
                               const char *tag, 
                               int tag_len, 
                               struct flb_input_instance *in);
int flb_routes_mask_get_bit(flb_route_mask_element *routes_mask, int value,
                            struct flb_router *router);
void flb_routes_mask_set_bit(flb_route_mask_element *routes_mask, int value,
                             struct flb_router *router);
void flb_routes_mask_clear_bit(flb_route_mask_element *routes_mask, int value,
                               struct flb_router *router);
int flb_routes_mask_is_empty(flb_route_mask_element *routes_mask,
                             struct flb_router *router);

int flb_routes_empty_mask_create(struct flb_router *router);
void flb_routes_empty_mask_destroy(struct flb_router *router);

int flb_routes_mask_set_size(size_t mask_size, struct flb_router *router);
size_t flb_routes_mask_get_size(struct flb_router *router);
size_t flb_routes_mask_get_slots(struct flb_router *router);

#endif
