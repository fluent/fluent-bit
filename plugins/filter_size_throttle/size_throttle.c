 /* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>
#include "stdlib.h"

#include "size_throttle.h"

#undef PLUGIN_NAME
#define PLUGIN_NAME "filter_size_throttle"
#define RELATIVE_ERROR 0.001
#define KEY_DEPTH 20
#define SPLIT_DELIMITER '|'

struct field_key
{
    char *key;
    int key_len;
    struct mk_list _head;
};

static bool apply_suffix(double *x, char suffix_char)
{
    int multiplier;

    switch (suffix_char) {
    case 0:
    case 's':
        multiplier = 1;
        break;
    case 'm':
        multiplier = 60;
        break;
    case 'h':
        multiplier = 60 * 60;
        break;
    case 'd':
        multiplier = 60 * 60 * 24;
        break;
    default:
        return false;
    }

    *x *= multiplier;

    return true;
}

/*add_new_pane_to_each will overides the oldes window pane with zero load and with new timestamp make it the newest. */
inline static void add_new_pane_to_each(struct size_throttle_table *ht,
                                        double timestamp)
{
    struct mk_list *head;
    struct flb_hash_entry *entry;
    struct size_throttle_window *current_window;
    struct flb_time ftm;

    if (!timestamp) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);
    }
    mk_list_foreach(head, &ht->windows->entries) {
        entry = mk_list_entry(head, struct flb_hash_entry, _head_parent);
        current_window = (struct size_throttle_window *) (entry->val);
        add_new_pane(current_window, timestamp);
        flb_debug
            ("[%s] Add new pane to \"%s\" window: timestamp: %ld, total %lu",
             PLUGIN_NAME, current_window->name,
             current_window->table[current_window->head].timestamp,
             current_window->total);
    }
}

inline static void delete_older_than_n_seconds(struct size_throttle_table *ht,
                                               long seconds,
                                               double current_timestamp)
{
    int i;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *entry;
    struct flb_hash_table *table;
    struct size_throttle_window *current_window;
    struct flb_time ftm;
    long time_treshold;

    if (!current_timestamp) {
        flb_time_get(&ftm);
        current_timestamp = flb_time_to_double(&ftm);
    }

    time_treshold = current_timestamp - seconds;
    for (i = 0; i < ht->windows->size; i++) {
        table = &ht->windows->table[i];
        mk_list_foreach_safe(head, tmp, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_entry, _head);
            current_window = (struct size_throttle_window *) entry->val;

            if (time_treshold > current_window->timestamp) {
                free_stw_content(current_window);
                mk_list_del(&entry->_head);
                mk_list_del(&entry->_head_parent);
                entry->table->count--;
                ht->windows->total_count--;
                flb_free(entry->key);
                flb_free(entry->val);
                flb_free(entry);
                flb_info
                    ("[%s] Window \"%s\" was deleted. CT%ld   TT%ld   T%ld  ",
                     PLUGIN_NAME, current_window->name,
                     (long) current_timestamp, time_treshold,
                     current_window->timestamp);
            }
        }
    }
}

inline static void print_all(struct size_throttle_table *ht)
{
    struct mk_list *head;
    struct flb_hash_entry *entry;
    struct size_throttle_window *current_window;

    mk_list_foreach(head, &ht->windows->entries) {
        entry = mk_list_entry(head, struct flb_hash_entry, _head_parent);
        current_window = (struct size_throttle_window *) entry->val;
        printf("[%s] Name %s\n", PLUGIN_NAME, current_window->name);
        printf("[%s] Timestamp %ld\n", PLUGIN_NAME,
               current_window->timestamp);
        printf("[%s] Total %lu\n", PLUGIN_NAME, current_window->total);
        printf("[%s] Rate %f\n", PLUGIN_NAME,
               current_window->total / (double) current_window->size);
    }
}

void *size_time_ticker(void *args)
{
    struct flb_filter_size_throttle_ctx *ctx = args;
    struct flb_time ftm;
    long timestamp;

    while (!ctx->done) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);

        pthread_mutex_lock(&ctx->hash->lock);
        add_new_pane_to_each(ctx->hash, timestamp);
        delete_older_than_n_seconds(ctx->hash,
                                    ctx->window_time_duration, timestamp);
        if (ctx->print_status) {
            print_all(ctx->hash);
        }
        pthread_mutex_unlock(&ctx->hash->lock);

        sleep(ctx->slide_interval);
    }

    return NULL;
}

/*Check if a msgpack type is either binary or string*/
static inline int is_valid_key(const msgpack_object key_as_msgpack)
{
    return key_as_msgpack.type == MSGPACK_OBJECT_BIN ||
        key_as_msgpack.type == MSGPACK_OBJECT_STR;
}

/*If msg_pack can be represented as string get_msgobject_as_str returns that representation*/
static inline uint32_t get_msgobject_as_str(const msgpack_object msg,
                                            char **out)
{
    if (msg.type == MSGPACK_OBJECT_STR) {
        *out = (char *) msg.via.str.ptr;
        return (uint32_t) msg.via.str.size;
    }
    if (msg.type == MSGPACK_OBJECT_BIN) {
        *out = (char *) msg.via.bin.ptr;
        return (uint32_t) msg.via.bin.size;
    }
    *out = NULL;
    return (uint32_t) 0;
}

static inline unsigned long get_msgpack_object_size(msgpack_object msg)
{
    int i;
    unsigned long size = 0;

    switch (msg.type) {
    case MSGPACK_OBJECT_STR:{
            return msg.via.str.size;
        }
    case MSGPACK_OBJECT_BIN:{
            return msg.via.bin.size;
        }
    case MSGPACK_OBJECT_MAP:{
            for (i = 0; i < msg.via.map.size; i++) {
                size += get_msgpack_object_size(msg.via.map.ptr[i].key);
                size += get_msgpack_object_size(msg.via.map.ptr[i].val);
            }
            return size;
        }
    case MSGPACK_OBJECT_ARRAY:{
            for (i = 0; i < msg.via.array.size; i++) {
                size += get_msgpack_object_size(msg.via.array.ptr[i]);
            }
            return size;
        }
    default:{
            return 0;
        }
    }

    return 0;
}

/*get_value_of_msgpack_object_map_ search in msgpack_object map for @key and returns the value as msgpack_object if key is found
  or return NULL if not.This is helper function to get_value_of_msgpack_object_map*/
static inline const msgpack_object
    * get_value_of_msgpack_object_map_(msgpack_object map,
                                       struct field_key *key)
{
    int i;
    char *current_field = NULL;
    int current_field_size;

    /* Lookup target key/value */
    for (i = 0; i < map.via.map.size; i++) {

        if (!is_valid_key(map.via.map.ptr[i].key)) {
            continue;
        }

        current_field_size =
            get_msgobject_as_str(map.via.map.ptr[i].key, &current_field);
        if (key->key_len != current_field_size) {
            continue;
        }
        if (strncmp(key->key, current_field, current_field_size) != 0) {
            continue;
        }

        return &map.via.map.ptr[i].val;
    }
    return NULL;
}

/*get_value_of_msgpack_object_map search in msgpack_object map for @key and returns the value as msgpack_object if key is found
  or return NULL if not. @key is a list of strings representing the nested key. Each element in thje list represent the next element in depth.*/
static inline const msgpack_object
    * get_value_of_msgpack_object_map(msgpack_object map,
                                      const struct mk_list *fields_name)
{
    struct mk_list *head = NULL;
    struct field_key *field;
    const msgpack_object *msg = &map;

    mk_list_foreach(head, fields_name) {
        field = mk_list_entry(head, struct field_key, _head);
        msg = get_value_of_msgpack_object_map_(*msg, field);
        if (msg == NULL) {
            //not found
            flb_debug("Could not found field named %s", field->key);
            return NULL;
        }
    }

    return msg;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int throttle_data_by_size(msgpack_object map,
                                        struct flb_filter_size_throttle_ctx
                                        *ctx)
{
    char *name_field_str = NULL;
    uint32_t name_field_size;
    unsigned long load_size;
    double current_rate;
    struct size_throttle_window *window;
    const msgpack_object *log_field;
    const msgpack_object *name_field;
    if (ctx->name_fields_depth > 0) {
        // We are looking for a message with a specific field. The other will not be taken to account.
        name_field = get_value_of_msgpack_object_map(map, &ctx->name_fields);
        if (name_field == NULL) {
            // We don't have such field so we keep the log.
            flb_debug
                ("[%s] The name field is missing , so we are keeping the log",
                 PLUGIN_NAME);
            return SIZE_THROTTLE_RET_KEEP;
        }
        name_field_size = get_msgobject_as_str(*name_field, &name_field_str);
        if (name_field_str == NULL) {
            // We don't have such field so we keep the log.
            flb_info
                ("[%s] The value of the name field is nether string not binary format. The log will not be throttle",
                 PLUGIN_NAME);
            return SIZE_THROTTLE_RET_KEEP;
        }
        flb_debug("[%s] Field name found.", PLUGIN_NAME);
    }
    else {
        flb_debug
            ("[%s] Using default field name. All log will be taken to account.",
             PLUGIN_NAME);
        //take all logs into account.
        name_field_str = SIZE_THROTTLE_DEFAULT_NAME_FIELD;
        name_field_size = strlen(SIZE_THROTTLE_DEFAULT_NAME_FIELD);
    }

    if (ctx->log_fields_depth > 0) {
        //we are looking for specific field and we will take only its size.
        log_field = get_value_of_msgpack_object_map(map, &ctx->log_fields);
        if (log_field == NULL) {
            flb_debug
                ("[%s] The log field is missing so we are keeping this log",
                 PLUGIN_NAME);
            return SIZE_THROTTLE_RET_KEEP;
        }
        flb_debug("[%s] Log field found.", PLUGIN_NAME);
        load_size = get_msgpack_object_size(*log_field);
    }
    else {
        flb_debug
            ("[%s] Using default log field name. All fields will be taken into account.",
             PLUGIN_NAME);
        load_size = get_msgpack_object_size(map);
    }
    flb_debug("[%s]Load size is %lu.", PLUGIN_NAME, load_size);

    pthread_mutex_lock(&ctx->hash->lock);

    window =
        find_size_throttle_window(ctx->hash, name_field_str, name_field_size);

    if (window == NULL) {
        /*Since fluent-bit works on one thread and there is no chance someone to create the same window so we can unlock the mutex
           to give it to the ticker */
        pthread_mutex_unlock(&ctx->hash->lock);
        current_rate = load_size / (double) ctx->window_size;
        if (current_rate - ctx->max_size_rate > RELATIVE_ERROR) {
            flb_info
                ("[%s] Load is too much for window \"%*.*s\". The log record will be dropped.",
                 PLUGIN_NAME, name_field_size, name_field_str);
            return SIZE_THROTTLE_RET_DROP;
        }
        window =
            size_window_create(name_field_str, name_field_size,
                               ctx->window_size);
        if (window == NULL) {
            flb_warn("[%s] Not enough memory. Log will be kept.", PLUGIN_NAME,
                     load_size);
            return SIZE_THROTTLE_RET_KEEP;
        }
        add_load(window, load_size);
        flb_debug
            ("[%s] Add %lu bytes to \"%s\" window: timestamp: %ld, total %lu",
             PLUGIN_NAME, load_size, window->name,
             window->table[window->head].timestamp, window->total);
        pthread_mutex_lock(&ctx->hash->lock);
        add_size_throttle_window(ctx->hash, window);
        pthread_mutex_unlock(&ctx->hash->lock);
        flb_debug("[%s] New window named \"%s\" was added with load %lu.",
                  PLUGIN_NAME, window->name, load_size);
        flb_free(window);
    }
    else {
        /*We found the wanted window and now we are going to make check and modify it if needed */
        flb_debug("[%s] Current rate is %.2f for windoe \"%s\"", PLUGIN_NAME,
                  ((window->total + load_size) / (double) window->size),
                  window->name);
        current_rate =
            (window->total + load_size) / (double) ctx->window_size;
        if (current_rate - ctx->max_size_rate > RELATIVE_ERROR) {
            pthread_mutex_unlock(&ctx->hash->lock);
            flb_info
                ("[%s] Load is too much. The log %*.*s record will be dropped.",
                 PLUGIN_NAME, load_size, name_field_size, name_field_str);
            return SIZE_THROTTLE_RET_DROP;
        }
        add_load(window, load_size);
        flb_debug
            ("[%s] Add %lu bytes to \"%s\" window: timestamp: %ld, total %lu",
             PLUGIN_NAME, load_size, window->name,
             window->table[window->head].timestamp, window->total);
        pthread_mutex_unlock(&ctx->hash->lock);
        flb_debug("[%s] Load of %lu was added and the message was kept.",
                  PLUGIN_NAME, load_size);
    }
    return SIZE_THROTTLE_RET_KEEP;
}

/*load_field_key_list split @str into list of string representing the depth of a nested key.
The split is base on SPLIT_DELIMITER*/
static inline int load_field_key_list(char *str, struct mk_list *the_list,
                                      size_t * list_size)
{
    struct mk_list *split;
    struct mk_list *head = NULL;
    struct field_key *fk;
    struct flb_split_entry *entry;

    mk_list_init(the_list);
    *list_size = 0;
    if (str != NULL) {
        split = flb_utils_split(str, SPLIT_DELIMITER, KEY_DEPTH);
        if (mk_list_size(split) < 1) {
            return 0;
        }
        mk_list_foreach(head, split) {
            fk = flb_malloc(sizeof(struct field_key));
            if (!fk) {
                flb_error("[%s] Not enough memory!", PLUGIN_NAME);
                flb_utils_split_free(split);
                return -1;
            }

            entry = mk_list_entry(head, struct flb_split_entry, _head);

            fk->key = strndup(entry->value, entry->len);
            fk->key_len = entry->len;
            mk_list_add(&fk->_head, the_list);
            (*list_size)++;
        }

        flb_utils_split_free(split);
    }
    return 0;
}

static int parse_duration(char *interval, int default_seconds)
{
    double seconds = 0.0;
    double s;
    char *p;

    s = strtod(interval, &p);
    if (0 >= s
        /* No extra chars after the number and an optional s,m,h,d char.  */
        || (*p && *(p + 1))
        /* Check any suffix char and update S based on the suffix.  */
        || !apply_suffix(&s, *p)) {
        flb_warn
            ("[filter_size_throttle] invalid time interval %s falling back to default: %d second",
             interval, default_seconds);
        return default_seconds;
    }

    seconds += s;
    return seconds;
}

static inline int configure(struct flb_filter_size_throttle_ctx *ctx,
                            struct flb_filter_instance *f_ins)
{
    char *str = NULL;
    double val = 0;
    char *endp;
    ssize_t bytes;

    ctx->name_fields_depth = 0;

    /* rate per second */
    str = flb_filter_get_property("rate", f_ins);
    if (str) {
        bytes = flb_utils_size_to_bytes(str);
        if (bytes > 0) {
            ctx->max_size_rate = (double) bytes;
        }
        else {
            ctx->max_size_rate = SIZE_THROTTLE_DEFAULT_RATE;
        }
    }
    else {
        ctx->max_size_rate = SIZE_THROTTLE_DEFAULT_RATE;
    }

    /* windows size */
    str = flb_filter_get_property("window", f_ins);
    if (str != NULL && (val = strtoul(str, &endp, 10)) > 1) {
        ctx->window_size = val;
    }
    else {
        ctx->window_size = SIZE_THROTTLE_DEFAULT_WINDOW;
    }

    /* print informational status */
    str = flb_filter_get_property("print_status", f_ins);
    if (str != NULL) {
        ctx->print_status = flb_utils_bool(str);
    }
    else {
        ctx->print_status = SIZE_THROTTLE_DEFAULT_STATUS;
    }

    /* sliding interval */
    str = flb_filter_get_property("interval", f_ins);
    if (str != NULL) {
        ctx->slide_interval =
            parse_duration(str, SIZE_THROTTLE_DEFAULT_INTERVAL);
    }
    else {
        ctx->slide_interval = SIZE_THROTTLE_DEFAULT_INTERVAL;
    }

    /* the field which size will be taken into account */
    str = flb_filter_get_property("log_field", f_ins);
    if (load_field_key_list(str, &ctx->log_fields, &ctx->log_fields_depth)) {
        return -1;
    }

    str = NULL;

    /* the field base on which new throttling window will be created */
    str = flb_filter_get_property("name_field", f_ins);
    if (load_field_key_list(str, &ctx->name_fields, &ctx->name_fields_depth)) {
        return -1;
    }

    /* The time after which the window will be delete when there is no log size recorded to it */
    str = flb_filter_get_property("window_time_duration", f_ins);
    if (str != NULL) {
        ctx->window_time_duration =
            parse_duration(str, SIZE_THROTTLE_DEFAULT_WINDOW_DURATION);
    }
    else {
        ctx->window_time_duration = SIZE_THROTTLE_DEFAULT_WINDOW_DURATION;
    }

    /* Create the hash table of windows */
    str = flb_filter_get_property("hash_table_size", f_ins);
    if (str != NULL && (val = strtoul(str, &endp, 10)) > 0) {
        ctx->hash = create_size_throttle_table(val);
    }
    else {
        ctx->hash =
            create_size_throttle_table
            (SIZE_THROTTLE_WINDOW_TABLE_DEFAULT_SIZE);
    }
    if (ctx->hash == NULL) {
        flb_errno();
        return -1;
    }

    return 0;
}

static int cb_throttle_init(struct flb_filter_instance *f_ins,
                            struct flb_config *config, void *data)
{
    int ret;
    struct flb_filter_size_throttle_ctx *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct flb_filter_size_throttle_ctx));
    if (!ctx) {
        flb_error("[%s] Not enough memory!", PLUGIN_NAME);
        return -1;
    }

    /* parse plugin configuration  */
    ret = configure(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (ctx->window_time_duration < ctx->slide_interval * ctx->window_size) {
        ctx->window_time_duration = ctx->slide_interval * ctx->window_size;
    }

    //if we cpecify "*" as a name field then all logs will be under
    // the same window which we must make at initial time to save
    // some checks later
    if (ctx->name_fields_depth == 0) {
        struct size_throttle_window *window =
            size_window_create(SIZE_THROTTLE_DEFAULT_NAME_FIELD,
                               strlen(SIZE_THROTTLE_DEFAULT_NAME_FIELD),
                               ctx->window_size);
        if (window == NULL) {
            flb_errno();
            return -1;
        }
        add_size_throttle_window(ctx->hash, window);
        flb_free(window);
    }

    ctx->ticker_id = flb_malloc(sizeof(pthread_t));
    if (!ctx->ticker_id) {
        flb_error("[%s] Not enough memory!", PLUGIN_NAME);
        return -1;
    }

    ctx->done = false;
    pthread_create((pthread_t *) ctx->ticker_id, NULL, &size_time_ticker,
                   ctx);

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_throttle_filter(void *data, size_t bytes,
                              char *tag, int tag_len,
                              void **out_buf, size_t * out_size,
                              struct flb_filter_instance *f_ins,
                              void *context, struct flb_config *config)
{
    int ret;
    int old_size = 0;
    int new_size = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    // Records come in the format,
    //
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ],
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ]
    //
    // Example record,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        old_size++;

        /* get time and map */
        map = root.via.array.ptr[1];

        ret = throttle_data_by_size(map, context);
        if (ret == SIZE_THROTTLE_RET_KEEP) {
            msgpack_pack_object(&tmp_pck, root);
            new_size++;
        }
        else if (ret == SIZE_THROTTLE_RET_DROP) {
            /* Do nothing */
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

static void delete_field_key(struct mk_list *head)
{
    struct mk_list *curr = NULL, *n = NULL;
    struct field_key *field;

    mk_list_foreach_safe(curr, n, head) {
        field = mk_list_entry(curr, struct field_key, _head);
        mk_list_del(curr);
        flb_free(field->key);
        flb_free(field);
    }
}

static int cb_throttle_exit(void *data, struct flb_config *config)
{
    struct flb_filter_size_throttle_ctx *ctx = data;
    ctx->done = true;
    pthread_join(*(pthread_t *) ctx->ticker_id, NULL);
    flb_free(ctx->ticker_id);
    destroy_size_throttle_table(ctx->hash);
    delete_field_key(&ctx->log_fields);
    delete_field_key(&ctx->name_fields);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_size_throttle_plugin = {
    .name = "size_throttle",
    .description = "Throttle messages by size using sliding window algorithm",
    .cb_init = cb_throttle_init,
    .cb_filter = cb_throttle_filter,
    .cb_exit = cb_throttle_exit,
    .flags = 0
};
