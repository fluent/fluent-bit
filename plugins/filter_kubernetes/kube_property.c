/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>

#include <msgpack.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_property.h"

#define prop_cmp(key, len, property)                                \
    (len == sizeof(key) - 1) &&                                     \
    (strncmp(property, key, len) == 0)

static inline void prop_not_allowed(char *prop, struct flb_kube_meta *meta)
{
    flb_warn("[filter_kube] annotation '%s' not allowed "
             "(ns='%s' pod_name='%s')",
             prop, meta->namespace, meta->podname);
}

/* Property: parser */
static int prop_set_parser(struct flb_kube *ctx, struct flb_kube_meta *meta,
                           char *val_buf, size_t val_len,
                           struct flb_kube_props *props)
{
    char *tmp;
    struct flb_parser *parser;

    /* Parser property must be allowed by k8s-logging.parser */
    if (ctx->k8s_logging_parser == FLB_FALSE) {
        prop_not_allowed("fluentbit.io/parser", meta);
        return -1;
    }

    /* Check the parser exists */
    tmp = flb_strndup(val_buf, val_len);
    if (!tmp) {
        flb_errno();
        return -1;
    }

    /* Get parser context */
    parser = flb_parser_get(tmp, ctx->config);
    if (!parser) {
        flb_warn("[filter_kube] annotation parser '%s' not found "
                 "(ns='%s' pod_name='%s')",
                 tmp, meta->namespace, meta->podname);
        flb_free(tmp);
        return -1;
    }

    /* Save the parser in the properties context */
    props->parser = flb_sds_create(tmp);

    flb_free(tmp);
    return 0;
}

static int prop_set_exclude(struct flb_kube *ctx, struct flb_kube_meta *meta,
                            char *val_buf, size_t val_len,
                            struct flb_kube_props *props)
{
    char *tmp;

    /* Exclude property must be allowed by k8s-logging.exclude */
    if (ctx->k8s_logging_exclude == FLB_FALSE) {
        prop_not_allowed("fluentbit.io/exclude", meta);
        return -1;
    }

    /* Get the bool value */
    tmp = flb_strndup(val_buf, val_len);
    if (!tmp) {
        flb_errno();
        return -1;
    }

    /* Save the exclude property in the context */
    props->exclude = flb_utils_bool(tmp);
    flb_free(tmp);

    return 0;
}

int flb_kube_prop_set(struct flb_kube *ctx, struct flb_kube_meta *meta,
                      char *prop, int prop_len,
                      char *val_buf, size_t val_len,
                      struct flb_kube_props *props)
{
    if (prop_cmp("parser", prop_len, prop)) {
        prop_set_parser(ctx, meta, val_buf, val_len, props);
    }
    else if (prop_cmp("exclude", prop_len, prop)) {
        prop_set_exclude(ctx, meta, val_buf, val_len, props);
    }

    return 0;
}

int flb_kube_prop_pack(struct flb_kube_props *props,
                       void **out_buf, size_t *out_size)
{
    int size;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    /* Number of fields in props structure */
    size = 2;

    /* Create msgpack buffer */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* Main array */
    msgpack_pack_array(&pck, size);

    /* Index 0: FLB_KUBE_PROP_PARSER */
    if (props->parser) {
        msgpack_pack_str(&pck, flb_sds_len(props->parser));
        msgpack_pack_str_body(&pck, props->parser, flb_sds_len(props->parser));
    }
    else {
        msgpack_pack_nil(&pck);
    }

    /* Index 1: FLB_KUBE_PROP_EXCLUDE */
    if (props->exclude == FLB_TRUE) {
        msgpack_pack_true(&pck);
    }
    else {
        msgpack_pack_false(&pck);
    }

    /* Set outgoing msgpack buffer */
    *out_buf = sbuf.data;
    *out_size = sbuf.size;

    return 0;
}

int flb_kube_prop_unpack(struct flb_kube_props *props, char *buf, size_t size)
{
    int ret;
    size_t off = 0;
    msgpack_object o;
    msgpack_object root;
    msgpack_unpacked result;

    memset(props, '\0', sizeof(struct flb_kube_props));

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    if (ret == -1) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    root = result.data;

    /* Index 0: Parser */
    o = root.via.array.ptr[FLB_KUBE_PROPS_PARSER];
    if (o.type == MSGPACK_OBJECT_NIL) {
        props->parser = NULL;
    }
    else {
        props->parser = flb_sds_create_len((char *) o.via.str.ptr, o.via.str.size);
    }

    /* Index 1: Exclude */
    o = root.via.array.ptr[FLB_KUBE_PROPS_EXCLUDE];
    if (o.via.boolean == FLB_TRUE) {
        props->exclude = FLB_TRUE;
    }
    else {
        props->exclude = FLB_FALSE;
    }

    msgpack_unpacked_destroy(&result);
    return 0;
}

/* Destroy any resource held by a props element */
void flb_kube_prop_destroy(struct flb_kube_props *props)
{
    if (props->parser) {
        flb_sds_destroy(props->parser);
    }
}
