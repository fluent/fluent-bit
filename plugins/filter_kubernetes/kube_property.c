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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>

#include <msgpack.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_property.h"

#define FLB_KUBE_PROP_PARSER "parser"
#define FLB_KUBE_PROP_PARSER_LEN (sizeof(FLB_KUBE_PROP_PARSER) - 1)
#define FLB_KUBE_PROP_EXCLUDE "exclude"
#define FLB_KUBE_PROP_EXCLUDE_LEN (sizeof(FLB_KUBE_PROP_EXCLUDE) - 1)

static inline int prop_cmp(const char *key, size_t keylen,
                           const char *property, size_t proplen)
{
    return proplen >= keylen && strncmp(key, property, keylen) == 0;
}

static inline void prop_not_allowed(const char *prop, struct flb_kube_meta *meta,
                                    struct flb_kube *ctx)
{
    flb_plg_warn(ctx->ins, "annotation '%s' not allowed "
                 "(ns='%s' pod_name='%s')",
                 prop, meta->namespace, meta->podname);
}

/* Property: parser */
static int prop_set_parser(struct flb_kube *ctx, struct flb_kube_meta *meta,
                           int is_container_specific, int stream,
                           const char *val_buf, size_t val_len,
                           struct flb_kube_props *props)
{
    char *tmp;
    struct flb_parser *parser;

    /* Parser property must be allowed by k8s-logging.parser */
    if (ctx->k8s_logging_parser == FLB_FALSE) {
        prop_not_allowed("fluentbit.io/parser", meta, ctx);
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
        flb_plg_warn(ctx->ins, "annotation parser '%s' not found "
                     "(ns='%s' pod_name='%s', container_name='%s')",
                     tmp, meta->namespace, meta->podname, meta->container_name);
        flb_free(tmp);
        return -1;
    }

    /* Save the parser in the properties context */
    if ((stream == FLB_KUBE_PROP_NO_STREAM ||
         stream == FLB_KUBE_PROP_STREAM_STDOUT) &&
        (is_container_specific == FLB_TRUE ||
         props->stdout_parser == FLB_KUBE_PROP_UNDEF)) {
        if (props->stdout_parser) {
            flb_sds_destroy(props->stdout_parser);
        }
        props->stdout_parser = flb_sds_create(tmp);
    }
    if ((stream == FLB_KUBE_PROP_NO_STREAM ||
         stream == FLB_KUBE_PROP_STREAM_STDERR) &&
        (is_container_specific == FLB_TRUE ||
         props->stderr_parser == FLB_KUBE_PROP_UNDEF)) {
        if (props->stderr_parser) {
            flb_sds_destroy(props->stderr_parser);
        }
        props->stderr_parser = flb_sds_create(tmp);
    }

    flb_free(tmp);

    return 0;
}

static int prop_set_exclude(struct flb_kube *ctx, struct flb_kube_meta *meta,
                            int is_container_specific, int stream,
                            const char *val_buf, size_t val_len,
                            struct flb_kube_props *props)
{
    char *tmp;
    int exclude;

    /* Exclude property must be allowed by k8s-logging.exclude */
    if (ctx->k8s_logging_exclude == FLB_FALSE) {
        prop_not_allowed("fluentbit.io/exclude", meta, ctx);
        return -1;
    }

    /* Get the bool value */
    tmp = flb_strndup(val_buf, val_len);
    if (!tmp) {
        flb_errno();
        return -1;
    }

    exclude = flb_utils_bool(tmp) == FLB_TRUE ?
              FLB_KUBE_PROP_TRUE : FLB_KUBE_PROP_FALSE;

    /* Save the exclude property in the context */
    if ((stream == FLB_KUBE_PROP_NO_STREAM ||
         stream == FLB_KUBE_PROP_STREAM_STDOUT) &&
        (is_container_specific == FLB_TRUE ||
         props->stdout_exclude == FLB_KUBE_PROP_UNDEF)) {
        props->stdout_exclude = exclude;
    }
    if ((stream == FLB_KUBE_PROP_NO_STREAM ||
         stream == FLB_KUBE_PROP_STREAM_STDERR) &&
        (is_container_specific == FLB_TRUE ||
         props->stderr_exclude == FLB_KUBE_PROP_UNDEF)) {
        props->stderr_exclude = exclude;
    }

    flb_free(tmp);

    return 0;
}

int flb_kube_prop_set(struct flb_kube *ctx, struct flb_kube_meta *meta,
                      const char *prop, int prop_len,
                      const char *val_buf, size_t val_len,
                      struct flb_kube_props *props)
{
    /*
     * Property can take the following forms:
     *  <property> applies to streams stdout and stderr of every pod's containers
     *  <property>-<container> applies to streams stdout and stderr of a specific pod's container
     *  <property>_stdout applies to stream stdout of every pod's containers
     *  <property>_stderr applies to stream stderr of every pod's containers
     *  <property>_stdout-<container> applies to stream stdout of a specific pod's container
     *  <property>_stderr-<container> applies to stream stderr of a specific pod's container
     */
    const char *cur = prop;
    size_t len = prop_len;
    const char *container = NULL;
    size_t container_len = 0;
    int stream = FLB_KUBE_PROP_NO_STREAM;
    int (*function)(struct flb_kube *ctx, struct flb_kube_meta *meta,
                    int is_container_specific, int stream,
                    const char *val_buf, size_t val_len,
                    struct flb_kube_props *props);

    if (prop_cmp(FLB_KUBE_PROP_PARSER, FLB_KUBE_PROP_PARSER_LEN, prop, prop_len)) {
        function = prop_set_parser;
        cur += FLB_KUBE_PROP_PARSER_LEN;
    }
    else if (prop_cmp(FLB_KUBE_PROP_EXCLUDE, FLB_KUBE_PROP_EXCLUDE_LEN, prop, prop_len)) {
        function = prop_set_exclude;
        cur += FLB_KUBE_PROP_EXCLUDE_LEN;
    }
    else {
        flb_plg_warn(ctx->ins, "unknown annotation 'fluentbit.io/%.*s' "
                     "(ns='%s' pod_name='%s')",
                     prop_len, prop, meta->namespace, meta->podname);
        return -1;
    }

    len = prop_len - (cur - prop);

    if (prop_cmp("_", 1, cur, len)) {
        cur++;
        len--;

        if (prop_cmp("stdout", sizeof("stdout") - 1, cur, len)) {
            stream = FLB_KUBE_PROP_STREAM_STDOUT;
            cur += sizeof("stdout") - 1;
        }
        else if (prop_cmp("stderr", sizeof("stderr") - 1, cur, len)) {
            stream = FLB_KUBE_PROP_STREAM_STDERR;
            cur += sizeof("stderr") - 1;
        }
        else {
            flb_plg_warn(ctx->ins, "invalid stream in annotation "
                         "'fluentbit.io/%.*s' (ns='%s' pod_name='%s')",
                      prop_len, prop, meta->namespace, meta->podname);
            return -1;
        }

        len = prop_len - (cur - prop);
    }

    if (prop_cmp("-", 1, cur, len)) {
        cur++;
        len--;

        if (len == 0) {
            flb_plg_warn(ctx->ins, "invalid container in annotation "
                         "'fluentbit.io/%.*s' (ns='%s' pod_name='%s')",
                      prop_len, prop, meta->namespace, meta->podname);
            return -1;
        }

        container = cur;
        container_len = len;
        len = 0;
    }

    if (len > 0) {
        flb_plg_warn(ctx->ins, "invalid annotation 'fluentbit.io/%.*s' "
                     "(ns='%s' pod_name='%s')",
                     prop_len, prop, meta->namespace, meta->podname);
        return -1;
    }

    /* If the property is for a specific container, and this is not
     * that container, bail out
     */
    if (container && strncmp(container, meta->container_name, container_len)) {
        return 0;
    }

    return function(ctx, meta,
                    (container ? FLB_TRUE : FLB_FALSE), stream,
                    val_buf, val_len, props);
}

int flb_kube_prop_pack(struct flb_kube_props *props,
                       void **out_buf, size_t *out_size)
{
    int size;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    /* Number of fields in props structure */
    size = FLB_KUBE_NUMBER_OF_PROPS;

    /* Create msgpack buffer */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* Main array */
    msgpack_pack_array(&pck, size);

    /* Index 0: FLB_KUBE_PROPS_STDOUT_PARSER */
    if (props->stdout_parser) {
        msgpack_pack_str(&pck, flb_sds_len(props->stdout_parser));
        msgpack_pack_str_body(&pck, props->stdout_parser, flb_sds_len(props->stdout_parser));
    }
    else {
        msgpack_pack_nil(&pck);
    }

    /* Index 1: FLB_KUBE_PROPS_STDERR_PARSER */
    if (props->stderr_parser) {
        msgpack_pack_str(&pck, flb_sds_len(props->stderr_parser));
        msgpack_pack_str_body(&pck, props->stderr_parser, flb_sds_len(props->stderr_parser));
    }
    else {
        msgpack_pack_nil(&pck);
    }

    /* Index 2: FLB_KUBE_PROPS_STDOUT_EXCLUDE */
    if (props->stdout_exclude == FLB_KUBE_PROP_TRUE) {
        msgpack_pack_true(&pck);
    }
    else {
        msgpack_pack_false(&pck);
    }

    /* Index 3: FLB_KUBE_PROPS_STDERR_EXCLUDE */
    if (props->stderr_exclude == FLB_KUBE_PROP_TRUE) {
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

int flb_kube_prop_unpack(struct flb_kube_props *props,
                         const char *buf, size_t size)
{
    int ret;
    size_t off = 0;
    msgpack_object o;
    msgpack_object root;
    msgpack_unpacked result;

    memset(props, '\0', sizeof(struct flb_kube_props));

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    if (ret == MSGPACK_UNPACK_PARSE_ERROR) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    root = result.data;

    /* Index 0: stdout_parser */
    o = root.via.array.ptr[FLB_KUBE_PROPS_STDOUT_PARSER];
    if (o.type == MSGPACK_OBJECT_NIL) {
        props->stdout_parser = NULL;
    }
    else {
        props->stdout_parser = flb_sds_create_len(o.via.str.ptr, o.via.str.size);
    }

    /* Index 1: stderr_parser */
    o = root.via.array.ptr[FLB_KUBE_PROPS_STDERR_PARSER];
    if (o.type == MSGPACK_OBJECT_NIL) {
        props->stderr_parser = NULL;
    }
    else {
        props->stderr_parser = flb_sds_create_len(o.via.str.ptr, o.via.str.size);
    }

    /* Index 2: stdout_exclude */
    o = root.via.array.ptr[FLB_KUBE_PROPS_STDOUT_EXCLUDE];
    props->stdout_exclude = o.via.boolean;

    /* Index 3: stderr_exclude */
    o = root.via.array.ptr[FLB_KUBE_PROPS_STDERR_EXCLUDE];
    props->stderr_exclude = o.via.boolean;

    msgpack_unpacked_destroy(&result);
    return 0;
}

/* Destroy any resource held by a props element */
void flb_kube_prop_destroy(struct flb_kube_props *props)
{
    if (props->stdout_parser) {
        flb_sds_destroy(props->stdout_parser);
        props->stdout_parser = NULL;
    }
    if (props->stderr_parser) {
        flb_sds_destroy(props->stderr_parser);
        props->stderr_parser = NULL;
    }
}
