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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_routes_mask.h>


/*
 * Set the routes_mask for input chunk with a router_match on tag, return a
 * non-zero value if any routes matched
 */
int flb_routes_mask_set_by_tag(uint64_t *routes_mask,
                               const char *tag,
                               int tag_len,
                               struct flb_input_instance *in)
{
    int has_routes = 0;
    struct mk_list *o_head;
    struct flb_output_instance *o_ins;
    if (!in) {
        return 0;
    }

    /* Clear the bit field */
    memset(routes_mask, 0, sizeof(uint64_t) * FLB_ROUTES_MASK_ELEMENTS);

    /* Find all matching routes for the given tag */
    mk_list_foreach(o_head, &in->config->outputs) {
        o_ins = mk_list_entry(o_head,
                              struct flb_output_instance, _head);

        if (flb_router_match(tag, tag_len, o_ins->match
#ifdef FLB_HAVE_REGEX
                             , o_ins->match_regex
#else
                             , NULL
#endif
                             )) {
            flb_routes_mask_set_bit(routes_mask, o_ins->id);
            has_routes = 1;
        }
    }

    return has_routes;
}

/*
 * Sets a single bit in an array of bitfields
 *
 * For example: Given a value of 35 this routine will set the
 * 4th bit in the 2nd value of the bitfield array.
 *
 */
void flb_routes_mask_set_bit(uint64_t *routes_mask, int value)
{
    int index;
    uint64_t bit;

    if (value < 0 || value > FLB_ROUTES_MASK_MAX_VALUE) {
        flb_warn("[routes_mask] Can't set bit (%d) past limits of bitfield",
                 value);
        return;
    }

    index = value / FLB_ROUTES_MASK_ELEMENT_BITS;
    bit = 1ULL << (value % FLB_ROUTES_MASK_ELEMENT_BITS);
    routes_mask[index] |= bit;
}

/*
 * Clears a single bit in an array of bitfields
 *
 * For example: Given a value of 68 this routine will clear the
 * 4th bit in the 2nd value of the bitfield array.
 *
 */
void flb_routes_mask_clear_bit(uint64_t *routes_mask, int value)
{
    int index;
    uint64_t bit;

    if (value < 0 || value > FLB_ROUTES_MASK_MAX_VALUE) {
        flb_warn("[routes_mask] Can't set bit (%d) past limits of bitfield",
                 value);
        return;
    }

    index = value / FLB_ROUTES_MASK_ELEMENT_BITS;
    bit = 1ULL << (value % FLB_ROUTES_MASK_ELEMENT_BITS);
    routes_mask[index] &= ~(bit);
}

/*
 * Checks the value of a single bit in an array of bitfields and returns a
 * non-zero value if that bit is set.
 *
 * For example: Given a value of 68 this routine will return a non-zero value
 * if the 4th bit in the 2nd value of the bitfield array is set.
 *
 */
int flb_routes_mask_get_bit(uint64_t *routes_mask, int value)
{
    int index;
    uint64_t bit;

    if (value < 0 || value > FLB_ROUTES_MASK_MAX_VALUE) {
        flb_warn("[routes_mask] Can't get bit (%d) past limits of bitfield",
                 value);
        return 0;
    }

    index = value / FLB_ROUTES_MASK_ELEMENT_BITS;
    bit = 1ULL << (value % FLB_ROUTES_MASK_ELEMENT_BITS);
    return (routes_mask[index] & bit) != 0ULL;
}

int flb_routes_mask_is_empty(uint64_t *routes_mask)
{
    uint64_t empty[FLB_ROUTES_MASK_ELEMENTS];

    /* Clear the tmp bitfield */
    memset(empty, 0, sizeof(empty));
    return memcmp(routes_mask, empty, sizeof(empty)) == 0;
}
