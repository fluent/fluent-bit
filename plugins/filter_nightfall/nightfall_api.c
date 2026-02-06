/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/tls/flb_tls.h>

#include "nightfall_api.h"

static int extract_array_fields(struct nested_obj *cur, struct mk_list *stack, 
                                struct mk_list *payload_list, char *should_pop);
static int extract_map_fields(struct nested_obj *cur, struct mk_list *stack, 
                              struct mk_list *payload_list, char *should_pop);

static flb_sds_t build_request_body(struct flb_filter_nightfall *ctx, 
                             msgpack_object *data)
{
    int ret;
    struct mk_list stack;
    struct nested_obj *cur;
    struct nested_obj *new_obj;

    struct mk_list payload_list;
    struct mk_list *head;
    struct mk_list *tmp;
    struct payload *pl;
    
    msgpack_sbuffer req_sbuf;
    msgpack_packer req_pk;
    flb_sds_t num_str;
    int num_str_len;
    flb_sds_t key_str;
    flb_sds_t val_str;
    flb_sds_t key_val_str;
    int key_val_str_len;
    flb_sds_t request_body;

    char should_pop = FLB_TRUE;

    new_obj = flb_malloc(sizeof(struct nested_obj));
    if (!new_obj) {
        flb_errno();
        return NULL;
    }
    new_obj->obj = data;
    new_obj->cur_index = 0;
    new_obj->start_at_val = FLB_FALSE;
    mk_list_init(&stack);
    mk_list_add(&new_obj->_head, &stack);

    mk_list_init(&payload_list);

    /* 
     * Since logs can contain many levels of nested objects, use stack-based DFS here
     * to extract scannable fields (positive/negative ints, strings)
     */
    while (mk_list_is_empty(&stack) == -1) {
        cur = mk_list_entry_last(&stack, struct nested_obj, _head);
        should_pop = FLB_TRUE;
        
        switch (cur->obj->type) {
            case MSGPACK_OBJECT_ARRAY:
                ret = extract_array_fields(cur, &stack, &payload_list, &should_pop);
                if (ret != 0) {
                    mk_list_foreach_safe(head, tmp, &stack) {
                        cur = mk_list_entry(head, struct nested_obj, _head);
                        mk_list_del(&cur->_head);
                        flb_free(cur);
                    }
                    mk_list_foreach_safe(head, tmp, &payload_list) {
                        pl = mk_list_entry(head, struct payload, _head);
                        mk_list_del(&pl->_head);
                        flb_free(pl);
                    }
                    return NULL;
                }
                break;
            case MSGPACK_OBJECT_MAP:
                ret = extract_map_fields(cur, &stack, &payload_list, &should_pop);
                if (ret != 0) {
                    mk_list_foreach_safe(head, tmp, &stack) {
                        cur = mk_list_entry(head, struct nested_obj, _head);
                        mk_list_del(&cur->_head);
                        flb_free(cur);
                    }
                    mk_list_foreach_safe(head, tmp, &payload_list) {
                        pl = mk_list_entry(head, struct payload, _head);
                        mk_list_del(&pl->_head);
                        flb_free(pl);
                    }
                    return NULL;
                }
                break;
            default:
                break;
        }

        if (should_pop) {
            mk_list_del(&cur->_head);
            flb_free(cur);
        }
    }

    msgpack_sbuffer_init(&req_sbuf);
    msgpack_packer_init(&req_pk, &req_sbuf, msgpack_sbuffer_write);

    /* 
     * Build request according to schema at 
     * https://docs.nightfall.ai/reference/scanpayloadv3
     */
    msgpack_pack_map(&req_pk, 2);
    msgpack_pack_str_with_body(&req_pk, "payload", 7);
    msgpack_pack_array(&req_pk, mk_list_size(&payload_list));
    /* Initialize buf to hold string representation of numbers */
    num_str = flb_sds_create_size(21);
    mk_list_foreach_safe(head, tmp, &payload_list) {
        pl = mk_list_entry(head, struct payload, _head);
        if (pl->obj->type == MSGPACK_OBJECT_STR) {
            if (pl->key_to_scan_with != NULL) {
                /* 
                 * Payload is the value of a keyval pair with a string key that could
                 * provide context when scanning, so join them together and scan.
                 */
                val_str = flb_sds_create_len(pl->obj->via.str.ptr, 
                                             pl->obj->via.str.size);
                key_str = flb_sds_create_len(pl->key_to_scan_with->via.str.ptr, 
                                             pl->key_to_scan_with->via.str.size);
                key_val_str = flb_sds_create_size(pl->key_to_scan_with->via.str.size + 
                                                  pl->obj->via.str.size + 2);
                key_val_str_len = flb_sds_snprintf(&key_val_str, 
                                                   flb_sds_alloc(key_val_str), 
                                                   "%s %s", key_str, val_str);
                msgpack_pack_str_with_body(&req_pk, key_val_str, key_val_str_len);
                flb_sds_destroy(val_str);
                flb_sds_destroy(key_str);
                flb_sds_destroy(key_val_str);
            }
            else {
                msgpack_pack_str_with_body(&req_pk, pl->obj->via.str.ptr, 
                                           pl->obj->via.str.size);
            }
        }
        else {
            if (pl->key_to_scan_with != NULL) {
                /* 
                 * Payload is the value of a keyval pair with a string key that could
                 * provide context when scanning, so join them together and scan.
                 */
                key_str = flb_sds_create_len(pl->key_to_scan_with->via.str.ptr, 
                                             pl->key_to_scan_with->via.str.size);
                key_val_str = flb_sds_create_size(pl->key_to_scan_with->via.str.size + 
                                                  num_str_len + 2);
                num_str_len = flb_sds_snprintf(&num_str, flb_sds_alloc(num_str), 
                                               "%"PRIi64, pl->obj->via.i64);
                key_val_str_len = flb_sds_snprintf(&key_val_str, 
                                                   flb_sds_alloc(key_val_str), 
                                                   "%s %s", key_str, num_str);
                msgpack_pack_str_with_body(&req_pk, key_val_str, key_val_str_len);
                flb_sds_destroy(key_str);
                flb_sds_destroy(key_val_str);
            }
            else {
                num_str_len = flb_sds_snprintf(&num_str, flb_sds_alloc(num_str), 
                                               "%"PRIi64, pl->obj->via.i64);
                msgpack_pack_str_with_body(&req_pk, num_str, num_str_len);
            }
        }
        mk_list_del(&pl->_head);
        flb_free(pl);
    }
    msgpack_pack_str_with_body(&req_pk, "policyUUIDs", 11);
    msgpack_pack_array(&req_pk, 1);
    msgpack_pack_str_with_body(&req_pk, ctx->policy_id, 36);

    request_body = flb_msgpack_raw_to_json_sds(req_sbuf.data, req_sbuf.size, FLB_TRUE);

    msgpack_sbuffer_destroy(&req_sbuf);
    flb_sds_destroy(num_str);

    return request_body;
}

static int extract_array_fields(struct nested_obj *cur, struct mk_list *stack, 
                                struct mk_list *payload_list, char *should_pop) 
{
    msgpack_object *item;
    struct nested_obj *new_obj;
    struct payload *pl;
    int i;

    for (i = cur->cur_index; i < cur->obj->via.array.size; i++) {
        item = &cur->obj->via.array.ptr[i];
        if (item->type == MSGPACK_OBJECT_MAP || item->type == MSGPACK_OBJECT_ARRAY) {
            /* A nested object, so add to stack and return to DFS to process immediately */
            new_obj = flb_malloc(sizeof(struct nested_obj));
            if (!new_obj) {
                flb_errno();
                return -1;
            }
            new_obj->obj = item;
            new_obj->cur_index = 0;
            new_obj->start_at_val = FLB_FALSE;
            mk_list_add(&new_obj->_head, stack);

            /* 
             * Since we are not done yet with the current array, increment the index that 
             * keeps track of progress and don't pop the current array so we can come
             * back later.
             */
            cur->cur_index = i + 1;
            *should_pop = FLB_FALSE;
            break;
        }
        else if (item->type == MSGPACK_OBJECT_STR || 
                 item->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                 item->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            /* Field is a scannable type, so add to payload list to build request later */
            pl = flb_calloc(1, sizeof(struct payload));
            if (!pl) {
                flb_errno();
                return -1;
            }
            pl->obj = item;
            mk_list_add(&pl->_head, payload_list);
        }
    }

    return 0;
}

static int extract_map_fields(struct nested_obj *cur, struct mk_list *stack, 
                              struct mk_list *payload_list, char *should_pop) 
{
    struct nested_obj *new_obj;
    msgpack_object *k;
    msgpack_object *v;
    struct payload *pl;
    int i;

    for (i = cur->cur_index; i < cur->obj->via.map.size; i++) {
        k = &cur->obj->via.map.ptr[i].key;
        if (!cur->start_at_val) {
            /* Handle the key of this kv pair */
            if (k->type == MSGPACK_OBJECT_MAP || k->type == MSGPACK_OBJECT_ARRAY) {
                /* A nested object, so add to stack and return to DFS to process immediately */
                new_obj = flb_malloc(sizeof(struct nested_obj));
                if (!new_obj) {
                    flb_errno();
                    return -1;
                }
                new_obj->obj = k;
                new_obj->cur_index = 0;
                new_obj->start_at_val = FLB_FALSE;
                mk_list_add(&new_obj->_head, stack);

                /* 
                 * Since we are not done yet with the current kv pair, don't increment 
                 * the progress index and set flag so we know to start at the value later
                 */
                cur->cur_index = i;
                cur->start_at_val = FLB_TRUE;
                /* Set should_pop to false because we are not done with the current map */
                *should_pop = FLB_FALSE;
                break;
            }
            else if (k->type == MSGPACK_OBJECT_STR || 
                     k->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                     k->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                /* Field is a scannable type, so add to payload list to build request later */
                pl = flb_calloc(1, sizeof(struct payload));
                if (!pl) {
                    flb_errno();
                    return -1;
                }
                pl->obj = k;
                mk_list_add(&pl->_head, payload_list);
            }
        }

        /* Handle the value of this kv pair */
        v = &cur->obj->via.map.ptr[i].val;
        if (v->type == MSGPACK_OBJECT_MAP || v->type == MSGPACK_OBJECT_ARRAY) {
            /* A nested object, so add to stack and return to DFS to process immediately */
            new_obj = flb_malloc(sizeof(struct nested_obj));
            if (!new_obj) {
                flb_errno();
                return -1;
            }
            new_obj->obj = v;
            new_obj->cur_index = 0;
            new_obj->start_at_val = FLB_FALSE;
            mk_list_add(&new_obj->_head, stack);
            
            /* Increment here because we are done with this kv pair */
            cur->cur_index = i + 1;
            cur->start_at_val = FLB_FALSE;
            /* Set should_pop to false because we are not done with the current map */
            *should_pop = FLB_FALSE;
            break;
        }
        else if (v->type == MSGPACK_OBJECT_STR || 
                 v->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                 v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            /* Field is a scannable type, so add to payload list to build request later */
            pl = flb_calloc(1, sizeof(struct payload));
            if (!pl) {
                flb_errno();
                return -1;
            }
            if (k->type == MSGPACK_OBJECT_STR) {
                /* 
                 * The key could provide more context for scanning so save it to scan
                 * with the val together.
                 */
                pl->key_to_scan_with = k;
            }
            pl->obj = v;
            mk_list_add(&pl->_head, payload_list);
        }
    }

    return 0;
}

static int get_map_val(msgpack_object m, char *key, msgpack_object *ret) 
{
    msgpack_object_kv kv;
    int i;

    if (m.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }
    for (i = 0; i < m.via.map.size; i++) {
        kv = m.via.map.ptr[i];
        if (kv.key.via.str.size == strlen(key) && 
            !strncmp(kv.key.via.str.ptr, key, strlen(key))) {
            *ret = kv.val;
            return 0;
        }
    }
    return -1;
}

static int process_response(const char *resp, size_t resp_size,
                            char **to_redact, size_t *to_redact_size, 
                            char *is_sensitive)
{
    int root_type;
    char *buf;
    size_t size;
    msgpack_unpacked resp_unpacked;
    size_t off = 0;
    int ret;
    int i, j, k;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_object resp_map;
    msgpack_object findings_list;
    msgpack_object findings;
    msgpack_object finding;
    msgpack_object location;
    msgpack_object byteRange;

    /* Convert json response body to msgpack */
    ret = flb_pack_json(resp, resp_size, &buf, &size, &root_type, NULL);
    if (ret != 0) {
        flb_errno();
        return -1;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&resp_unpacked);

    /*
     * For every scannable field (positive/negative ints, strings) we sent to
     * scan, Nightfall returns an array of finding objects that inform
     * which portions of the field may be sensitive. We return those byte 
     * ranges here so we can do redaction later.
     */
    ret = msgpack_unpack_next(&resp_unpacked, buf, size, &off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        resp_map = resp_unpacked.data;
        ret = get_map_val(resp_map, "findings", &findings_list);
        if (ret != 0) {
            msgpack_unpacked_destroy(&resp_unpacked);
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_free(buf);
            flb_errno();
            return -1;
        }
        msgpack_pack_array(&mp_pck, findings_list.via.array.size);

        for (i = 0; i < findings_list.via.array.size; i++) {
            findings = findings_list.via.array.ptr[i];
            msgpack_pack_array(&mp_pck, findings.via.array.size);

            if (!*is_sensitive && findings.via.array.size > 0) {
                *is_sensitive = FLB_TRUE;
            }

            for (j = 0; j < findings.via.array.size; j++) {
                finding = findings.via.array.ptr[j];
                ret = get_map_val(finding, "location", &location);
                if (ret != 0) {
                    msgpack_unpacked_destroy(&resp_unpacked);
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    flb_free(buf);
                    flb_errno();
                    return -1;
                }

                ret = get_map_val(location, "byteRange", &byteRange);
                if (ret != 0) {
                    msgpack_unpacked_destroy(&resp_unpacked);
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    flb_free(buf);
                    flb_errno();
                    return -1;
                }

                msgpack_pack_array(&mp_pck, byteRange.via.map.size);
                for (k = 0; k < byteRange.via.map.size; k++) {
                    msgpack_pack_int64(&mp_pck, byteRange.via.map.ptr[k].val.via.i64);
                }
            }
        }
    }
    msgpack_unpacked_destroy(&resp_unpacked);
    flb_free(buf);

    *to_redact = mp_sbuf.data;
    *to_redact_size = mp_sbuf.size;

    return 0;
}

/* Scans log for sensitive content and returns the locations of such content */
int scan_log(struct flb_filter_nightfall *ctx, msgpack_object *data, 
             char **to_redact, size_t *to_redact_size, char *is_sensitive) 
{        
    struct flb_http_client *client;
    struct flb_connection *u_conn;

    flb_sds_t body;
    int ret;
    size_t b_sent;

    body = build_request_body(ctx, data);
    if (body == NULL) {
        flb_plg_error(ctx->ins, "could not build request");
        return -1;
    }

    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "connection initialization error");
        flb_sds_destroy(body);
        return -1;
    }

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn,
                             FLB_HTTP_POST, "/v3/scan",
                             body, flb_sds_len(body),
                             FLB_FILTER_NIGHTFALL_API_HOST, 443,
                             NULL, 0);

    if (!client) {
        flb_plg_error(ctx->ins, "could not create http client");
        flb_sds_destroy(body);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_buffer_size(client, 0);

    flb_http_add_header(client, "Authorization", 13, ctx->auth_header, 42);
    flb_http_add_header(client,
                        FLB_HTTP_HEADER_USER_AGENT,
                        sizeof(FLB_HTTP_HEADER_USER_AGENT) - 1,
                        FLB_HTTP_HEADER_USER_AGENT_DEFAULT,
                        sizeof(FLB_HTTP_HEADER_USER_AGENT_DEFAULT) - 1);
    flb_http_add_header(client, "Content-Type", 12, "application/json", 16);

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_plg_info(ctx->ins, "Nightfall request http_do=%i, HTTP Status: %i",
                    ret, client->resp.status);
    flb_sds_destroy(body);

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_plg_info(ctx->ins, "Nightfall request\n%s",
                            client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    
    ret = process_response(client->resp.payload, client->resp.payload_size, 
                           to_redact, to_redact_size, is_sensitive);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not process response");
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);

    return 0;
}
