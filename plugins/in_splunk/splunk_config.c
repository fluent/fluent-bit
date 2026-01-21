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

#include <fluent-bit/flb_input_plugin.h>

#include "splunk.h"
#include "splunk_config.h"
#include "splunk_conn.h"
#include "splunk_config.h"

static void delete_hec_tokens(struct flb_splunk *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_splunk_tokens *splunk_token;

    mk_list_foreach_safe(head, tmp, &ctx->auth_tokens) {
        splunk_token = mk_list_entry(head, struct flb_splunk_tokens, _head);
        flb_sds_destroy(splunk_token->header);
        mk_list_del(&splunk_token->_head);
        flb_free(splunk_token);
    }
}

static int setup_hec_tokens(struct flb_splunk *ctx)
{
    int         ret;
    const char *raw_token;
    struct mk_list *head = NULL;
    struct mk_list *kvs = NULL;
    int token_idx = 0;
    struct flb_split_entry *cur = NULL;
    flb_sds_t   auth_header = NULL;
    struct flb_splunk_tokens *splunk_token;
    flb_sds_t credential = NULL;

    struct flb_config_map_val *matching_token_mapping;
    /* iterators for token to tag mappings */
    struct mk_list *ttm_list_i;
    struct flb_config_map_val *ttm_cmval_i;
    struct flb_slist_entry *ttm_i_token;
    struct flb_slist_entry *ttm_tag;

    raw_token = flb_input_get_property("splunk_token", ctx->ins);
    if (raw_token) {
        kvs = flb_utils_split(raw_token, ',', -1 );
        if (kvs == NULL) {
            goto split_error;
        }

        mk_list_foreach(head, kvs) {
            cur = mk_list_entry(head, struct flb_split_entry, _head);

            auth_header = flb_sds_create("Splunk ");
            if (auth_header == NULL) {
                flb_plg_error(ctx->ins, "error on prefix of auth_header generation");
                goto error;
            }

            credential = flb_sds_create_len(cur->value, strlen(cur->value));
            if (credential == NULL) {
                flb_plg_warn(ctx->ins, "error on flb_sds allocation");
                continue;
            }

            ret = flb_sds_trim(credential);
            if (ret == -1) {
                flb_plg_warn(ctx->ins, "error on trimming for a credential candidate");
                goto error;
            }

            ret = flb_sds_cat_safe(&auth_header, credential, flb_sds_len(credential));
            if (ret < 0) {
                flb_plg_error(ctx->ins, "error on token generation");
                goto error;
            }

            /* Create a new token */
            splunk_token = flb_malloc(sizeof(struct flb_splunk_tokens));
            if (!splunk_token) {
                flb_errno();
                goto error;
            }

            splunk_token->header = auth_header;
            splunk_token->length = flb_sds_len(auth_header);

            if (ctx->token_to_tag_mappings != NULL) {
                int mapping_idx = 0;
                matching_token_mapping = NULL;
                /* search all the configured token_to_tag_mappings to see if the current
                   token is one that a mapping was specified for */
                flb_config_map_foreach(ttm_list_i, ttm_cmval_i, ctx->token_to_tag_mappings) {
                    ttm_i_token = mk_list_entry_first(ttm_cmval_i->val.list,
                                        struct flb_slist_entry,
                                        _head);

                    if (flb_sds_cmp(ttm_i_token->str, credential, flb_sds_len(credential)) == 0) {
                        matching_token_mapping = ttm_cmval_i;
                        break;
                    }
                    mapping_idx += 1;
                }
                if (matching_token_mapping != NULL) {
                    /* Token is the first arg (list->next),
                       Tag is the second arg (list->next->next) */
                    ttm_tag = container_of(matching_token_mapping->val.list->next->next,
                                        struct flb_slist_entry,
                                        _head);
                    flb_plg_debug(ctx->ins, "token #%d will map to tag %s", token_idx + 1, ttm_tag->str);
                    splunk_token->map_to_tag = flb_sds_create(ttm_tag->str);
                }
                else {
                    flb_plg_warn(ctx->ins, "token #%d has no tag mapping, records from this token will not re-map to specific tag", token_idx + 1);
                    splunk_token->map_to_tag = NULL;
                }
            }
            else {
                splunk_token->map_to_tag = NULL;
            }

            flb_sds_destroy(credential);

            /* Link to parent list */
            mk_list_add(&splunk_token->_head, &ctx->auth_tokens);
            token_idx++;
        }
    }

    if (kvs != NULL) {
        flb_utils_split_free(kvs);
    }

    return 0;

split_error:
    return -1;
error:
    if (kvs != NULL) {
        flb_utils_split_free(kvs);
    }
    if (credential != NULL) {
        flb_sds_destroy(credential);
    }
    return -1;
}

struct flb_splunk *splunk_config_create(struct flb_input_instance *ins)
{
    struct mk_list            *header_iterator;
    struct flb_slist_entry    *header_value;
    struct flb_slist_entry    *header_name;
    struct flb_config_map_val *header_pair;
    char                       port[8];
    int                        ret;
    struct flb_splunk         *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_splunk));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->connections);
    mk_list_init(&ctx->auth_tokens);

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    ctx->ingested_auth_header = NULL;

    ret = setup_hec_tokens(ctx);
    if (ret != 0) {
        splunk_config_destroy(ctx);
        return NULL;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:8088) */
    flb_input_net_default_listener("0.0.0.0", 8088, ins);

    ctx->listen = flb_strdup(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_strdup(port);

    /* HTTP Server specifics */
    ctx->server = flb_calloc(1, sizeof(struct mk_server));
    if (ctx->server == NULL) {
        flb_plg_error(ctx->ins, "error on mk_server allocation");
        splunk_config_destroy(ctx);
        return NULL;
    }
    ctx->server->keep_alive = MK_TRUE;

    /* monkey detects server->workers == 0 as the server not being initialized at the
     * moment so we want to make sure that it stays that way!
     */

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        splunk_config_destroy(ctx);

        return NULL;
    }

    ctx->success_headers_str = flb_sds_create_size(1);

    if (ctx->success_headers_str == NULL) {
        splunk_config_destroy(ctx);

        return NULL;
    }

    flb_config_map_foreach(header_iterator, header_pair, ctx->success_headers) {
        header_name = mk_list_entry_first(header_pair->val.list,
                                          struct flb_slist_entry,
                                          _head);

        header_value = mk_list_entry_last(header_pair->val.list,
                                          struct flb_slist_entry,
                                          _head);

        ret = flb_sds_cat_safe(&ctx->success_headers_str,
                               header_name->str,
                               flb_sds_len(header_name->str));

        if (ret == 0) {
            ret = flb_sds_cat_safe(&ctx->success_headers_str,
                                   ": ",
                                   2);
        }

        if (ret == 0) {
            ret = flb_sds_cat_safe(&ctx->success_headers_str,
                                   header_value->str,
                                   flb_sds_len(header_value->str));
        }

        if (ret == 0) {
            ret = flb_sds_cat_safe(&ctx->success_headers_str,
                                   "\r\n",
                                   2);
        }

        if (ret != 0) {
            splunk_config_destroy(ctx);

            return NULL;
        }
    }

    /* Create record accessor for tag_key if specified */
    if (ctx->tag_key) {
        ctx->ra_tag_key = flb_ra_create(ctx->tag_key, FLB_TRUE);
        if (!ctx->ra_tag_key) {
            flb_plg_error(ctx->ins, "invalid record accessor pattern for tag_key: %s", ctx->tag_key);
            splunk_config_destroy(ctx);
            return NULL;
        }
    }

    return ctx;
}

int splunk_config_destroy(struct flb_splunk *ctx)
{
    if (ctx->ra_tag_key) {
        flb_ra_destroy(ctx->ra_tag_key);
    }

    /* release all connections */
    splunk_conn_release_all(ctx);

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    if (ctx->collector_id != -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);

        ctx->collector_id = -1;
    }

    if (ctx->downstream != NULL) {
        flb_downstream_destroy(ctx->downstream);
    }

    if (ctx->enable_http2) {
        flb_http_server_destroy(&ctx->http_server);
    }

    if (ctx->server) {
        flb_free(ctx->server);
    }

    if (ctx->success_headers_str != NULL) {
        flb_sds_destroy(ctx->success_headers_str);
    }

    delete_hec_tokens(ctx);

    flb_free(ctx->listen);
    flb_free(ctx->tcp_port);
    flb_free(ctx);
    return 0;
}
