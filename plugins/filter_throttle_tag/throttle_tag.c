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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>
#include "stdlib.h"
#include <stdio.h>
#include <sys/types.h>
#include "throttle_tag.h"

#undef PLUGIN_NAME
#define PLUGIN_NAME "filter_throttle_tag"
#define RELATIVE_ERROR 0.001

/*
 * add_new_pane_to_each will overide the old window pane with zero load and
 * with new timestamp make it the newest.
 */
inline static void add_new_pane_to_each(struct throttle_tag_table *ht,
                                        double timestamp)
{
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct throttle_tag_window *current_window;
    struct flb_time ftm;

    if (!timestamp) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);
    }

    mk_list_foreach(head, &ht->windows->entries) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
        current_window = (struct throttle_tag_window *) (entry->val);
        add_new_pane(current_window, timestamp);
        flb_debug
            ("[%s] Add new pane to \"%s\" window: timestamp: %ld, total %lu",
             PLUGIN_NAME, current_window->name,
             current_window->table[current_window->head].timestamp,
             current_window->total);
    }
}

inline static void delete_older_than_n_seconds(struct throttle_tag_table *ht,
                                               long seconds,
                                               double current_timestamp)
{
    int i;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct flb_hash_table_chain *table;
    struct throttle_tag_window *current_window;
    struct flb_time ftm;
    long time_threshold;

    if (!current_timestamp) {
        flb_time_get(&ftm);
        current_timestamp = flb_time_to_double(&ftm);
    }

    time_threshold = current_timestamp - seconds;
    for (i = 0; i < ht->windows->size; i++) {
        table = &ht->windows->table[i];
        mk_list_foreach_safe(head, tmp, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
            current_window = (struct throttle_tag_window *) entry->val;
	        /* don't delete the global window */
	        if (strcmp(current_window->name,
	            THROTTLE_TAG_DEFAULT_GLOBAL_WINDOW_NAME) == 0) {
	            break;
	        }
            if (time_threshold > current_window->timestamp) {
                flb_info
                    ("[%s] Window \"%s\" was deleted, "
                     "msg dropped: %lu. CT%ld   TT%ld   T%ld",
                     PLUGIN_NAME, current_window->name,
		             current_window->dropped,
                     (long) current_timestamp, time_threshold,
                     current_window->timestamp);
                free_stw_content(current_window);
                mk_list_del(&entry->_head);
                mk_list_del(&entry->_head_parent);
                entry->table->count--;
                ht->windows->total_count--;
                flb_free(entry->key);
                flb_free(entry->val);
                flb_free(entry);

            }
        }
    }
}

inline static void print_all(struct flb_filter_throttle_tag_ctx *ctx)
{
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct throttle_tag_window *current_window;

    mk_list_foreach(head, &ctx->hash->windows->entries) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
        current_window = (struct throttle_tag_window *) entry->val;
        /* print only tags with above 50% rate */
        if (current_window->total /
            (double) ctx->window_size / ctx->max_tag_rate > 0.5) {
            flb_plg_info(ctx->ins,
                         "Tag: %s, last_msg_time: %ld, Total: %lu, Dropped: "
                         "%lu, Rate: %.2f, Max_rate: %.2f",
                         current_window->name,
                         current_window->timestamp,
                         current_window->total,
                         current_window->dropped,
                         current_window->total / (double) current_window->size,
                         ctx->max_tag_rate);
        }
    }
}

void *time_ticker_tag(void *args)
{
    struct flb_filter_throttle_tag_ctx *ctx = args;
    struct flb_time ftm;
    long timestamp;

    while (!ctx->done) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);

        //lock_throttle_tag_table(ctx->hash);
        pthread_mutex_lock(ctx->hash->lock);
        add_new_pane_to_each(ctx->hash, timestamp);
        delete_older_than_n_seconds(ctx->hash,
                                    ctx->window_time_duration, timestamp);
        if (ctx->print_status) {
            print_all(ctx);
        }

        pthread_mutex_unlock(ctx->hash->lock);
        sleep(ctx->slide_interval);
    }
    return NULL;
}

static inline int throttle_data_by_tag(msgpack_object map,
                                       struct flb_filter_throttle_tag_ctx *ctx,
                                       const char *tag,
                                       int tag_size,
                                       struct throttle_tag_window *global_window)
{
    unsigned long load_size;
    double current_rate;
    double global_rate;
    bool global_rate_check;
    struct throttle_tag_window *window;

    load_size = 1;
    pthread_mutex_lock(ctx->hash->lock);

    window = find_throttle_tag_window(ctx->hash, tag, tag_size);
    if (window == NULL) {
        pthread_mutex_unlock(ctx->hash->lock);

        window = tag_window_create(tag, tag_size, ctx->window_size);
        if (window == NULL) {
            flb_plg_warn(ctx->ins, "not enough memory. Log will be kept.");
            return throttle_tag_RET_KEEP;
        }

        if (global_window != NULL){
            add_load(global_window, load_size);
        }
        add_load(window, load_size);
        flb_plg_debug(ctx->ins, "add msg to \"%s\" window: timestamp: %ld, "
                      "total %lu",
                      window->name,
                      window->table[window->head].timestamp, window->total);
        pthread_mutex_lock(ctx->hash->lock);
        add_throttle_tag_window(ctx->hash, window);
        pthread_mutex_unlock(ctx->hash->lock);
        flb_plg_debug(ctx->ins, "new window named \"%s\" was added with"
                      "load %lu.",
                      window->name, load_size);
        flb_free(window);
    }
    else {
        /*
         * We found the wanted window and now we are going to make check and
         * modify it if needed
         */
        flb_plg_debug(ctx->ins, "current rate is %.2f for window \"%s\"",
                      ((window->total + load_size) / (double) window->size),
                      window->name);

        current_rate = (window->total + load_size) / (double) ctx->window_size;

        global_rate_check = false;
        if (global_window){
            global_rate = (global_window->total + load_size) /
                          (double) ctx->window_size;
            /* pass the msg, if global_rate is below
             * the global_rate_max parameter */
            if (ctx->max_global_rate - global_rate > RELATIVE_ERROR) {
                add_load(global_window, load_size);
                add_load(window, load_size);
                flb_plg_debug(ctx->ins, "msg passed, due to global rate "
                              "limit(%f) not reached: %s", global_rate, tag);
                pthread_mutex_unlock(ctx->hash->lock);
                global_rate_check = true;
            }
        }
        /*
         *  the global rate check failed, but we also have to check,
         *  if the msg pass its tag limit
         */
        if (!global_rate_check) {
            if (current_rate - ctx->max_tag_rate > RELATIVE_ERROR) {
                pthread_mutex_unlock(ctx->hash->lock);
                window->dropped++;
                flb_plg_debug(ctx->ins,
                              "rate too high - tag %*.*s will be dropped.",
                              load_size, tag_size, tag);
                return throttle_tag_RET_DROP;
            }
            if (global_window != NULL){
                add_load(global_window, load_size);
            }
            add_load(window, load_size);
            flb_plg_debug(ctx->ins,
                          "add %lu msg to \"%s\" window:"
                          "timestamp: %ld, total %lu",
                          load_size,
                          window->name,
                          window->table[window->head].timestamp,
                          window->total);
            pthread_mutex_unlock(ctx->hash->lock);
            flb_plg_debug(ctx->ins,
                          "load of %lu was added and the message was kept",
                          load_size);
        }
    }
    return throttle_tag_RET_KEEP;
}

static int configure(struct flb_filter_throttle_tag_ctx *ctx,
                     struct flb_filter_instance *f_ins)
{
    int ret;

    ret = flb_filter_config_map_set(f_ins, ctx);
    if (ret == -1)  {
        flb_plg_error(f_ins, "unable to load configuration");
        return -1;
    }
    if (ctx->max_tag_rate <= 1.0) {
        flb_plg_warn(f_ins, "set max_tag_rate to DEFAULT_RATE");
        ctx->max_tag_rate = strtod(THROTTLE_TAG_DEFAULT_RATE, NULL);
    }
    if (ctx->max_global_rate <= 1.0) {
        flb_plg_warn(f_ins, "set max_global_rate to 0.0");
        ctx->max_global_rate = 0.0;
        }
    if (ctx->window_size <= 1) {
        ctx->window_size = strtoul(THROTTLE_TAG_DEFAULT_WINDOW, NULL, 10);
    }
    if (ctx->window_time_duration <= 5) {
        ctx->window_time_duration =
            (int) strtol(THROTTLE_TAG_DEFAULT_WINDOW_DURATION, NULL, 10);
    }
    if (ctx->hash_table_size <= 1) {
        ctx->hash_table_size =
            strtoul(THROTTLE_TAG_WINDOW_TABLE_DEFAULT_SIZE, NULL, 10);
    }
    ctx->hash = create_throttle_tag_table(ctx->hash_table_size);
    if (ctx->hash == NULL) {
        flb_errno();
        return -1;
    }
    ctx->startup_time = time(NULL);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_DOUBLE, "rate", THROTTLE_TAG_DEFAULT_RATE,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, max_tag_rate),
     "Set throttle rate"
    },
    {
     FLB_CONFIG_MAP_INT, "window", THROTTLE_TAG_DEFAULT_WINDOW,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, window_size),
     "Set throttle window"
    },
    {
     FLB_CONFIG_MAP_BOOL, "print_status", THROTTLE_TAG_DEFAULT_STATUS,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, print_status),
     "Set whether or not to print status information"
    },
    {
     FLB_CONFIG_MAP_INT, "interval", THROTTLE_TAG_DEFAULT_INTERVAL,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, slide_interval),
     "Set the slide interval"
    },
    {
     FLB_CONFIG_MAP_INT, "window_time_duration",
     THROTTLE_TAG_DEFAULT_WINDOW_DURATION, 0, FLB_TRUE,
     offsetof(struct flb_filter_throttle_tag_ctx, window_time_duration),
     "Set the window time duration"
    },
    {
     FLB_CONFIG_MAP_BOOL, "throttle_per_tag", "true",
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, throttle_per_tag),
     "Throttle per msg tag"
    },
    {
     FLB_CONFIG_MAP_INT, "hash_table_size", THROTTLE_TAG_WINDOW_TABLE_DEFAULT_SIZE,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, hash_table_size),
     "Number of hash table windows"
    },
    {
     FLB_CONFIG_MAP_DOUBLE, "global_rate", THROTTLE_TAG_DEFAULT_GLOBAL_RATE,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, max_global_rate),
     "Global rate, allow to breach tag throttle limit,"
     "as long the global rate is not reached"
    },
    {
     FLB_CONFIG_MAP_TIME, "startup_wait", THROTTLE_TAG_DEFAULT_STARTUP_WAIT,
     0, FLB_TRUE, offsetof(struct flb_filter_throttle_tag_ctx, startup_wait),
     "Timespan after start, without any throtting. Default: 1m"
    },
    /* EOF */
    {0}
};

static int cb_throttle_tag_init(struct flb_filter_instance *ins,
                            struct flb_config *config, void *data)
{
    int ret;
    struct flb_filter_throttle_tag_ctx *ctx;
    struct throttle_tag_window *global_window;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_throttle_tag_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* parse plugin configuration  */
    ret = configure(ctx, ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (ctx->window_time_duration < ctx->slide_interval * ctx->window_size) {
        ctx->window_time_duration = ctx->slide_interval * ctx->window_size;
    }

    /*
     * create global window "__global_window__" to keep track of the global msg rate
     */

    if (ctx->max_global_rate != 0) {
        global_window = tag_window_create(THROTTLE_TAG_DEFAULT_GLOBAL_WINDOW_NAME,
                                    strlen(THROTTLE_TAG_DEFAULT_GLOBAL_WINDOW_NAME),
                                    ctx->window_size);
        if (global_window == NULL) {
            flb_free(ctx);
            flb_errno();
            return -1;
        }
        add_throttle_tag_window(ctx->hash, global_window);
        flb_free(global_window);
    }

    ctx->ticker_id = flb_malloc(sizeof(pthread_t));
    if (!ctx->ticker_id) {
        flb_errno();
        return -1;
    }

    ctx->done = false;
    pthread_create((pthread_t *) ctx->ticker_id, NULL, &time_ticker_tag,
                   ctx);

    /* Set our context */
    flb_filter_set_context(ins, ctx);

    return 0;
}

static int cb_throttle_tag_filter(const void *data, size_t bytes,
                                   const char *tag, int tag_len,
                                   void **out_buf, size_t * out_size,
                                   struct flb_filter_instance *ins,
                                   struct flb_input_instance *i_ins,
                                   void *context, struct flb_config *config)
{
    int ret;
    int old_size = 0;
    int new_size = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    size_t off = 0;
    (void) ins;
    (void) i_ins;
    (void) config;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_filter_throttle_tag_ctx *ctx = context;
    struct throttle_tag_window *global_window;

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    if (ctx->max_global_rate != 0) {
        global_window =
            find_throttle_tag_window(ctx->hash,
                                     THROTTLE_TAG_DEFAULT_GLOBAL_WINDOW_NAME,
                                     strlen(THROTTLE_TAG_DEFAULT_GLOBAL_WINDOW_NAME));

        if (global_window == NULL) {
            flb_plg_warn(ctx->ins, " global window not found");
            global_window = NULL;
        }
    }
    else {
        global_window = NULL;
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, (const char *)data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        old_size++;

        /* get time and map */
        map = root.via.array.ptr[1];

        if ((time(NULL) - ctx->startup_time) < ctx->startup_wait) {
           ret = throttle_tag_RET_KEEP;
           flb_plg_debug(ctx->ins,
                         " skip throttle, "
                         "due to 'within plugin startup wait time': %ld",
                        (time(NULL) - ctx->startup_time));
        }
        else {
           ret = throttle_data_by_tag(map, context, tag, tag_len, global_window);
        }
        if (ret == throttle_tag_RET_KEEP) {
            msgpack_pack_object(&tmp_pck, root);
            new_size++;
        }
    }
    msgpack_unpacked_destroy(&result);

    /* we keep everything ? */
    if (old_size == new_size) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    /* link new buffers */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_throttle_tag_exit(void *data, struct flb_config *config)
{
    struct flb_filter_throttle_tag_ctx *ctx = data;

    ctx->done = true;
    pthread_join(*(pthread_t *) ctx->ticker_id, NULL);

    flb_free(ctx->ticker_id);
    destroy_throttle_tag_table(ctx->hash);
    flb_free(ctx);

    return 0;
}

struct flb_filter_plugin filter_throttle_tag_plugin = {
    .name        = "throttle_tag",
    .description = "Throttle messages by tag using sliding window algorithm",
    .cb_init     = cb_throttle_tag_init,
    .cb_filter   = cb_throttle_tag_filter,
    .cb_exit     = cb_throttle_tag_exit,
    .config_map   = config_map,
    .flags       = 0
};
