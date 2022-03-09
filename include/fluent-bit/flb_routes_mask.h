/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
 *
 * The size of the bitmask array limits the number of output plugins
 * The router can route to. For example: with a value of 4 using
 * 64-bit integers the bitmask can represent up to 256 output plugins
 */
#define FLB_ROUTES_MASK_ELEMENTS		4

/*
 * How many bits are in each element of the bitmask array
 */
#define FLB_ROUTES_MASK_ELEMENT_BITS 	(sizeof(uint64_t) * CHAR_BIT)

/*
 * The maximum number of routes that can be stored in the array
 */
#define FLB_ROUTES_MASK_MAX_VALUE		(FLB_ROUTES_MASK_ELEMENTS * FLB_ROUTES_MASK_ELEMENT_BITS)


/* forward declaration */
struct flb_input_instance;


int flb_routes_mask_set_by_tag(uint64_t *routes_mask, const char *tag, int tag_len, struct flb_input_instance *in);
int flb_routes_mask_get_bit(uint64_t *routes_mask, int value);
void flb_routes_mask_set_bit(uint64_t *routes_mask, int value);
void flb_routes_mask_clear_bit(uint64_t *routes_mask, int value);
int flb_routes_mask_is_empty(uint64_t *routes_mask);

#endif
