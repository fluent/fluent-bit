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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/tls/flb_tls.h>

#include "es_type.h"

void flb_es_str_destroy(struct flb_es_str *ins)
{
    if (ins->value && ins->owned != FLB_FALSE) {
        flb_free(ins->value);
    }
    ins->value = NULL;
    ins->owned = FLB_FALSE;
}

void flb_es_str_set_str(struct flb_es_str *dest, char *src)
{
    flb_es_str_destroy(dest);
    dest->value = src;
    dest->owned = FLB_FALSE;
}

int flb_es_str_copy_str(struct flb_es_str *dest, const char *src)
{
    char *dup;
    if (!src) {
        flb_es_str_destroy(dest);
        return 0;
    }
    dup = flb_strdup(src);
    if (!dup) {
        return -1;
    }
    flb_es_str_destroy(dest);
    dest->value = dup;
    dest->owned = FLB_TRUE;
    return 0;
}

void flb_es_sds_destroy(struct flb_es_sds_t *ins)
{
    if (ins->value && ins->owned != FLB_FALSE) {
        flb_sds_destroy(ins->value);
    }
    ins->value = NULL;
    ins->owned = FLB_FALSE;
}

void flb_es_sds_set_sds(struct flb_es_sds_t *dest, flb_sds_t src)
{
    flb_es_sds_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_FALSE;
    }
}

int flb_es_sds_copy_str(struct flb_es_sds_t *dest, const char *src)
{
    flb_sds_t dup;
    if (!src) {
        flb_es_sds_destroy(dest);
        return 0;
    }
    dup = flb_sds_create(src);
    if (!dup) {
        return -1;
    }
    flb_es_sds_destroy(dest);
    dest->value = dup;
    dest->owned = FLB_TRUE;
    return 0;
}

void flb_es_slist_destroy(struct flb_es_slist *ins)
{
    if (ins->value && ins->owned != FLB_FALSE) {
        flb_slist_destroy(ins->value);
        flb_free(ins->value);
    }
    ins->value = NULL;
    ins->owned = FLB_FALSE;
}

void flb_es_slist_set_slist(struct flb_es_slist *dest, struct mk_list *src)
{
    flb_es_slist_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_FALSE;
    }
}

void flb_es_slist_move_slist(struct flb_es_slist *dest, struct mk_list *src)
{
    flb_es_slist_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_TRUE;
    }
}

void flb_es_tls_destroy(struct flb_es_tls *ins)
{
    if (ins->value && ins->owned != FLB_FALSE) {
        flb_tls_destroy(ins->value);
    }
    ins->value = NULL;
    ins->owned = FLB_FALSE;
}

void flb_es_tls_set_tls(struct flb_es_tls *dest, struct flb_tls *src)
{
    flb_es_tls_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_FALSE;
    }
}

void flb_es_tls_move_tls(struct flb_es_tls *dest, struct flb_tls *src)
{
    flb_es_tls_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_TRUE;
    }
}

void flb_es_ra_destroy(struct flb_es_record_accessor *ins)
{
    if (ins->value && ins->owned != FLB_FALSE) {
        flb_ra_destroy(ins->value);
    }
    ins->value = NULL;
    ins->owned = FLB_FALSE;
}

void flb_es_ra_set_ra(struct flb_es_record_accessor *dest,
                      struct flb_record_accessor *src)
{
    flb_es_ra_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_FALSE;
    }
}

void flb_es_ra_move_ra(struct flb_es_record_accessor *dest,
                       struct flb_record_accessor *src)
{
    flb_es_ra_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_TRUE;
    }
}

#ifdef FLB_HAVE_AWS
void flb_es_aws_provider_destroy(struct flb_es_aws_provider *ins)
{
    if (ins->value && ins->owned != FLB_FALSE) {
        flb_aws_provider_destroy(ins->value);
    }
    ins->value = NULL;
    ins->owned = FLB_FALSE;
}

void flb_es_aws_provider_set(struct flb_es_aws_provider *dest,
                             const struct flb_es_aws_provider *src)
{
    if (dest == src) {
        return;
    }
    flb_es_aws_provider_destroy(dest);
    if (src) {
        dest->value = src->value;
        dest->owned = FLB_FALSE;
    }
}

void flb_es_aws_provider_move(struct flb_es_aws_provider *dest,
                              struct flb_es_aws_provider *src)
{
    if (dest == src) {
        return;
    }
    flb_es_aws_provider_destroy(dest);
    if (src) {
        *dest = *src;
        src->value = NULL;
        src->owned = FLB_FALSE;
    }
}

void flb_es_aws_provider_move_provider(struct flb_es_aws_provider *dest,
                                       struct flb_aws_provider *src)
{
    flb_es_aws_provider_destroy(dest);
    if (src) {
        dest->value = src;
        dest->owned = FLB_TRUE;
    }
}
#endif
