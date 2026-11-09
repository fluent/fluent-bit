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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "mqtt.h"
#include "mqtt_conf.h"
#include "mqtt_prot.h"

static int topic_part_add(struct flb_out_mqtt *ctx, int type, int index,
                          const char *str, size_t len)
{
    struct flb_out_mqtt_topic_part *part;

    part = flb_calloc(1, sizeof(struct flb_out_mqtt_topic_part));
    if (!part) {
        flb_errno();
        return -1;
    }

    part->type = type;
    part->index = index;

    if (type == FLB_MQTT_TOPIC_LITERAL) {
        part->literal = flb_sds_create_len(str, len);
        if (!part->literal) {
            flb_free(part);
            return -1;
        }
    }

    mk_list_add(&part->_head, &ctx->topic_parts);

    return 0;
}

static void topic_parts_destroy(struct flb_out_mqtt *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_out_mqtt_topic_part *part;

    mk_list_foreach_safe(head, tmp, &ctx->topic_parts) {
        part = mk_list_entry(head, struct flb_out_mqtt_topic_part, _head);
        mk_list_del(&part->_head);
        if (part->literal) {
            flb_sds_destroy(part->literal);
        }
        flb_free(part);
    }
}

static int topic_literal_add(struct flb_out_mqtt *ctx, const char *str, size_t len)
{
    if (!out_mqtt_prot_topic_fragment_valid(str, len)) {
        flb_plg_error(ctx->ins,
                      "invalid topic '%s': topic names must be valid UTF-8 "
                      "without control characters or '+' and '#' wildcards",
                      ctx->topic);
        return -1;
    }

    return topic_part_add(ctx, FLB_MQTT_TOPIC_LITERAL, 0, str, len);
}

/*
 * Parse the topic template. Only $TAG and $TAG[n] are expanded, any other
 * character, a '$' included, is kept as is so reserved topic names such as
 * '$aws/rules/...' can be used. Topic levels are separated by '/', which is
 * why the record accessor syntax is not used here.
 */
static int topic_template_parse(struct flb_out_mqtt *ctx)
{
    int index;
    size_t i;
    size_t j;
    size_t len;
    size_t start;
    const char *topic;

    topic = ctx->topic;
    len = flb_sds_len(ctx->topic);

    i = 0;
    start = 0;
    while (i < len) {
        if (topic[i] != '$' || len - i < 4 || strncmp(topic + i, "$TAG", 4) != 0) {
            i++;
            continue;
        }

        if (i > start) {
            if (topic_literal_add(ctx, topic + start, i - start) != 0) {
                return -1;
            }
        }

        i += 4;

        if (i < len && topic[i] == '[') {
            j = i + 1;
            index = 0;

            while (j < len && isdigit((unsigned char) topic[j])) {
                index = (index * 10) + (topic[j] - '0');
                if (index > FLB_MQTT_TOPIC_MAX_TAG_PART) {
                    flb_plg_error(ctx->ins, "invalid topic '%s': $TAG[n] index "
                                  "is too large", ctx->topic);
                    return -1;
                }
                j++;
            }

            if (j == i + 1 || j >= len || topic[j] != ']') {
                flb_plg_error(ctx->ins, "invalid topic '%s': expected $TAG[n] "
                              "with a numeric index", ctx->topic);
                return -1;
            }

            if (topic_part_add(ctx, FLB_MQTT_TOPIC_TAG_PART, index, NULL, 0) != 0) {
                return -1;
            }
            i = j + 1;
        }
        else {
            if (topic_part_add(ctx, FLB_MQTT_TOPIC_TAG, 0, NULL, 0) != 0) {
                return -1;
            }
        }

        ctx->topic_has_tag = FLB_TRUE;
        start = i;
    }

    if (start < len) {
        if (topic_literal_add(ctx, topic + start, len - start) != 0) {
            return -1;
        }
    }

    if (!ctx->topic_has_tag && !out_mqtt_prot_topic_valid(topic, len)) {
        flb_plg_error(ctx->ins, "invalid topic '%s'", ctx->topic);
        return -1;
    }

    return 0;
}

/*
 * Create a record accessor that must point to a single key, the leading '$'
 * is optional: 'topic' and '$topic' are equivalent.
 */
static struct flb_record_accessor *key_accessor_create(struct flb_out_mqtt *ctx,
                                                       flb_sds_t key,
                                                       const char *property)
{
    int ret;
    flb_sds_t pattern;
    struct flb_ra_parser *rp;
    struct flb_record_accessor *ra;

    if (flb_sds_len(key) == 0 || (key[0] == '$' && flb_sds_len(key) == 1)) {
        flb_plg_error(ctx->ins, "%s cannot be empty", property);
        return NULL;
    }

    if (key[0] == '$') {
        pattern = flb_sds_create(key);
    }
    else {
        pattern = flb_sds_create_size(flb_sds_len(key) + 1);
        if (pattern) {
            ret = flb_sds_cat_safe(&pattern, "$", 1);
            if (ret == 0) {
                ret = flb_sds_cat_safe(&pattern, key, flb_sds_len(key));
            }
            if (ret != 0) {
                flb_sds_destroy(pattern);
                pattern = NULL;
            }
        }
    }

    if (!pattern) {
        flb_errno();
        return NULL;
    }

    ra = flb_ra_create(pattern, FLB_TRUE);
    flb_sds_destroy(pattern);

    if (!ra) {
        flb_plg_error(ctx->ins, "invalid %s '%s'", property, key);
        return NULL;
    }

    /* Only a plain key lookup is supported, no templates or $TAG */
    if (mk_list_size(&ra->list) != 1) {
        flb_plg_error(ctx->ins, "invalid %s '%s': it must reference a single "
                      "record key", property, key);
        flb_ra_destroy(ra);
        return NULL;
    }

    rp = mk_list_entry_first(&ra->list, struct flb_ra_parser, _head);
    if (rp->type != FLB_RA_PARSER_KEYMAP || rp->key == NULL) {
        flb_plg_error(ctx->ins, "invalid %s '%s': it must reference a single "
                      "record key", property, key);
        flb_ra_destroy(ra);
        return NULL;
    }

    return ra;
}

/* Finalizer of splitmix64: every input bit changes about half of the output */
static uint64_t seed_mix(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;

    return x;
}

/* 'flb' + 12 hex digits taken from 6 random bytes */
static void client_id_prefix_init(struct flb_out_mqtt *ctx)
{
    int i;
    int ret;
    uint64_t seed;
    unsigned char bytes[6];
    static const char hex[] = "0123456789abcdef";

    /*
     * Like the other users of flb_random_bytes(), the instance does not fail
     * without random bytes. The current time, the process identifier and the
     * context address make two instances unlikely to share a prefix.
     */
    ret = flb_random_bytes(bytes, sizeof(bytes));
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "cannot read random bytes, generated client "
                     "identifiers are derived from the current time and the "
                     "process identifier, set a unique 'client_id' to rule out "
                     "collisions");
        seed = seed_mix((uint64_t) time(NULL));
        seed = seed_mix(seed ^ (uint64_t) getpid());
        seed = seed_mix(seed ^ (uint64_t) (uintptr_t) ctx);
        for (i = 0; i < (int) sizeof(bytes); i++) {
            bytes[i] = (seed >> (i * 8)) & 0xff;
        }
    }

    memcpy(ctx->client_id_prefix, "flb", 3);
    for (i = 0; i < (int) sizeof(bytes); i++) {
        ctx->client_id_prefix[3 + (i * 2)] = hex[bytes[i] >> 4];
        ctx->client_id_prefix[3 + (i * 2) + 1] = hex[bytes[i] & 0x0f];
    }
    ctx->client_id_prefix[FLB_MQTT_CLIENT_ID_PREFIX_LEN] = '\0';
}

static void upstream_tune(struct flb_out_mqtt *ctx)
{
    int target;
    struct flb_net_setup *net;

    net = &ctx->u->base.net;

    /*
     * Connections wait for CONNACK and PUBACK packets, without an I/O timeout
     * a broker that stops answering would block the flush forever.
     */
    if (net->io_timeout <= 0) {
        net->io_timeout = FLB_MQTT_DEFAULT_IO_TIMEOUT;
        flb_plg_debug(ctx->ins, "net.io_timeout is not set, using %i seconds",
                      FLB_MQTT_DEFAULT_IO_TIMEOUT);
    }

    /*
     * A client must not stay silent longer than its keep alive interval
     * (MQTT-3.1.2-23), and pooled connections send nothing while they wait
     * for the next flush. The pool closes idle connections after
     * net.keepalive_idle_timeout, checked every 1.5 seconds with a one second
     * resolution, so the idle timeout is kept 3 seconds below keep_alive.
     * Below that no idle period is safe and connections are not reused.
     */
    if (net->keepalive == FLB_TRUE && ctx->keep_alive > 0) {
        target = ctx->keep_alive - 3;

        if (target < 1) {
            net->keepalive = FLB_FALSE;
            flb_plg_info(ctx->ins, "keep_alive %i is too short to keep idle "
                         "connections, every flush opens a new connection",
                         ctx->keep_alive);
        }
        else if (net->keepalive_idle_timeout > target) {
            flb_plg_info(ctx->ins, "net.keepalive_idle_timeout lowered from %i "
                         "to %i seconds to stay within the MQTT keep_alive",
                         net->keepalive_idle_timeout, target);
            net->keepalive_idle_timeout = target;
        }
    }
}

struct flb_out_mqtt *flb_out_mqtt_conf_create(struct flb_output_instance *ins,
                                              struct flb_config *config)
{
    int ret;
    int port;
    int io_flags;
    const char *tmp;
    struct flb_out_mqtt *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_out_mqtt));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->topic_parts);

    /* Kept when a property is set to an empty value, see mqtt.h */
    ctx->qos = FLB_MQTT_DEFAULT_QOS;
    ctx->keep_alive = FLB_MQTT_DEFAULT_KEEP_ALIVE;
    ctx->max_inflight = FLB_MQTT_DEFAULT_MAX_INFLIGHT;

    ret = pthread_mutex_init(&ctx->lock, NULL);
    if (ret != 0) {
        flb_plg_error(ins, "cannot initialize session lock");
        flb_free(ctx);
        return NULL;
    }
    ctx->lock_initialized = FLB_TRUE;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        goto error;
    }

    /* Quality of service */
    if (ctx->qos == 2) {
        flb_plg_error(ins, "qos 2 is not supported: failed chunks are retried "
                      "as a whole, so exactly-once delivery cannot be "
                      "guaranteed. Use qos 1 (at least once) or 0");
        goto error;
    }
    else if (ctx->qos != 0 && ctx->qos != 1) {
        flb_plg_error(ins, "invalid qos %i, allowed values are 0 and 1", ctx->qos);
        goto error;
    }

    if (ctx->keep_alive < 0 || ctx->keep_alive > 65535) {
        flb_plg_error(ins, "invalid keep_alive %i, allowed range is 0-65535 "
                      "seconds", ctx->keep_alive);
        goto error;
    }

    if (ctx->max_inflight < 1 || ctx->max_inflight > FLB_MQTT_MAX_PACKET_ID) {
        flb_plg_error(ins, "invalid max_inflight %i, allowed range is 1-%i",
                      ctx->max_inflight, FLB_MQTT_MAX_PACKET_ID);
        goto error;
    }

    /* Credentials */
    if (ctx->password && !ctx->username) {
        flb_plg_error(ins, "password requires username: MQTT 3.1.1 does not "
                      "allow a password without a user name");
        goto error;
    }

    if (ctx->username &&
        (flb_sds_len(ctx->username) > FLB_MQTT_MAX_STRING_LENGTH ||
         !out_mqtt_prot_utf8_valid(ctx->username, flb_sds_len(ctx->username),
                                   FLB_FALSE))) {
        flb_plg_error(ins, "invalid username: it must be valid UTF-8 without "
                      "control characters, up to %i bytes",
                      FLB_MQTT_MAX_STRING_LENGTH);
        goto error;
    }

    if (ctx->password && flb_sds_len(ctx->password) > FLB_MQTT_MAX_STRING_LENGTH) {
        flb_plg_error(ins, "invalid password: it cannot be longer than %i bytes",
                      FLB_MQTT_MAX_STRING_LENGTH);
        goto error;
    }

    /* Client identifier */
    if (ctx->client_id && flb_sds_len(ctx->client_id) > 0) {
        if (flb_sds_len(ctx->client_id) > FLB_MQTT_MAX_STRING_LENGTH ||
            !out_mqtt_prot_utf8_valid(ctx->client_id, flb_sds_len(ctx->client_id),
                                      FLB_FALSE)) {
            flb_plg_error(ins, "invalid client_id: it must be valid UTF-8 "
                          "without control characters, up to %i bytes",
                          FLB_MQTT_MAX_STRING_LENGTH);
            goto error;
        }

        /*
         * The broker drops the older session when two connections share a
         * client identifier, each worker would steal the other's session.
         */
        if (ins->tp_workers > 1) {
            flb_plg_error(ins, "a fixed client_id allows a single broker "
                          "session: set 'workers' to 1, or remove client_id "
                          "to use generated identifiers");
            goto error;
        }
        ctx->fixed_client_id = FLB_TRUE;
    }
    else {
        client_id_prefix_init(ctx);
    }

    /* Payload format */
    ctx->out_format = FLB_MQTT_FORMAT_JSON;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "json") == 0) {
            ctx->out_format = FLB_MQTT_FORMAT_JSON;
        }
        else if (strcasecmp(tmp, "msgpack") == 0) {
            ctx->out_format = FLB_MQTT_FORMAT_MSGPACK;
        }
        else {
            flb_plg_error(ins, "invalid format '%s', allowed values are json "
                          "and msgpack", tmp);
            goto error;
        }
    }

    /* Date key, it can be disabled with a boolean 'off' value */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp && flb_utils_bool(tmp) == FLB_FALSE) {
        ctx->date_key = NULL;
    }

    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ins, "invalid json_date_format '%s'", tmp);
            goto error;
        }
        ctx->json_date_format = ret;
    }

    /* Topic */
    if (!ctx->topic || flb_sds_len(ctx->topic) == 0) {
        flb_plg_error(ins, "topic cannot be empty");
        goto error;
    }

    if (topic_template_parse(ctx) != 0) {
        goto error;
    }

    if (ctx->topic_key) {
        ctx->ra_topic_key = key_accessor_create(ctx, ctx->topic_key, "topic_key");
        if (!ctx->ra_topic_key) {
            goto error;
        }
    }

    if (ctx->payload_key) {
        ctx->ra_payload_key = key_accessor_create(ctx, ctx->payload_key,
                                                  "payload_key");
        if (!ctx->ra_payload_key) {
            goto error;
        }
    }

    /* Network setup: the default port depends on TLS */
    io_flags = FLB_IO_TCP;
    port = FLB_MQTT_DEFAULT_PORT;

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        port = FLB_MQTT_DEFAULT_TLS_PORT;
    }
#endif

    flb_output_net_default(FLB_MQTT_DEFAULT_HOST, port, ins);

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    ctx->u = flb_upstream_create(config,
                                 ins->host.name,
                                 ins->host.port,
                                 io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ins, "could not create upstream context");
        goto error;
    }

    ret = flb_output_upstream_set(ctx->u, ins);
    if (ret != 0) {
        flb_plg_error(ins, "could not configure upstream context");
        goto error;
    }

    upstream_tune(ctx);

    return ctx;

error:
    flb_out_mqtt_conf_destroy(ctx);
    return NULL;
}

void flb_out_mqtt_conf_destroy(struct flb_out_mqtt *ctx)
{
    if (!ctx) {
        return;
    }

    topic_parts_destroy(ctx);

    if (ctx->ra_topic_key) {
        flb_ra_destroy(ctx->ra_topic_key);
    }

    if (ctx->ra_payload_key) {
        flb_ra_destroy(ctx->ra_payload_key);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->lock_initialized) {
        pthread_mutex_destroy(&ctx->lock);
    }

    flb_free(ctx);
}
