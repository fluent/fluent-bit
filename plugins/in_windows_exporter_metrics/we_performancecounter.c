/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_sds.h>
#include <cmetrics/cmt_map.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "we_performancecounter.h"
#include "we_util.h"

static char *sanitize_metric_name(char *name)
{
    size_t i;
    size_t j;
    size_t len;
    char *out;
    int last_was_separator;

    len = strlen(name);
    if (len == 0) {
        return NULL;
    }

    out = flb_strdup(name);
    if (out == NULL) {
        flb_errno();
        return NULL;
    }

    j = 0;
    last_was_separator = FLB_TRUE;

    for (i = 0; i < len; i++) {
        if (isalnum((unsigned char) name[i])) {
            out[j] = tolower((unsigned char) name[i]);
            j++;
            last_was_separator = FLB_FALSE;
            continue;
        }

        if (!last_was_separator) {
            out[j] = '_';
            j++;
            last_was_separator = FLB_TRUE;
        }
    }

    if (j > 0 && out[j - 1] == '_') {
        j--;
    }

    out[j] = '\0';

    if (j == 0) {
        flb_free(out);
        return NULL;
    }

    return out;
}

static int parse_counter_config(struct flb_we *ctx,
                                char *entry,
                                char **out_name,
                                char **out_path,
                                int *out_has_wildcard)
{
    char *separator;
    char *name;
    char *path;
    char *name_end;

    separator = strchr(entry, '=');
    if (separator == NULL) {
        name = entry;
        path = entry;
    }
    else {
        name = entry;
        path = separator + 1;
        *separator = '\0';
    }

    while (isspace((unsigned char) *name)) {
        name++;
    }

    if (separator != NULL) {
        name_end = separator - 1;
        while (name_end >= name && isspace((unsigned char) *name_end)) {
            *name_end = '\0';
            name_end--;
        }
    }

    while (isspace((unsigned char) *path)) {
        path++;
    }

    if ((separator != NULL && *name == '\0') || *path == '\0') {
        flb_plg_error(ctx->ins,
                      "invalid PerformanceCounter '%s', expected name=counter_path",
                      entry);
        return -1;
    }

    *out_name = name;
    *out_path = path;
    *out_has_wildcard = FLB_FALSE;

    if (strchr(path, '*') != NULL) {
        *out_has_wildcard = FLB_TRUE;
    }

    return 0;
}

static char *compose_instance_label(char *parent, char *instance, DWORD index)
{
    size_t len;
    char *out;
    char index_buf[32];
    int has_parent;
    int has_index;

    has_parent = FLB_FALSE;
    has_index = FLB_FALSE;
    index_buf[0] = '\0';

    if (parent != NULL && parent[0] != '\0') {
        has_parent = FLB_TRUE;
    }

    if (index != (DWORD) -1) {
        snprintf(index_buf, sizeof(index_buf), "#%lu", (unsigned long) index);
        has_index = FLB_TRUE;
    }

    len = strlen(instance) + 1;
    if (has_parent) {
        len += strlen(parent) + 1;
    }
    if (has_index) {
        len += strlen(index_buf);
    }

    out = flb_malloc(len);
    if (out == NULL) {
        flb_errno();
        return NULL;
    }

    if (has_parent && has_index) {
        snprintf(out, len, "%s/%s%s", parent, instance, index_buf);
    }
    else if (has_parent) {
        snprintf(out, len, "%s/%s", parent, instance);
    }
    else if (has_index) {
        snprintf(out, len, "%s%s", instance, index_buf);
    }
    else {
        snprintf(out, len, "%s", instance);
    }

    return out;
}

static char *get_counter_instance(wchar_t *path_w)
{
    PDH_STATUS status;
    DWORD size;
    PPDH_COUNTER_PATH_ELEMENTS_W elements;
    char *instance;
    char *parent;
    char *label;

    size = 0;
    status = PdhParseCounterPathW(path_w, NULL, &size, 0);
    if (status != PDH_MORE_DATA) {
        return NULL;
    }

    elements = flb_calloc(1, size);
    if (elements == NULL) {
        flb_errno();
        return NULL;
    }

    status = PdhParseCounterPathW(path_w, elements, &size, 0);
    if (status != ERROR_SUCCESS) {
        flb_free(elements);
        return NULL;
    }

    if (elements->szInstanceName == NULL) {
        flb_free(elements);
        return NULL;
    }

    instance = we_convert_wstr(elements->szInstanceName, CP_UTF8);
    if (instance == NULL) {
        flb_free(elements);
        return NULL;
    }

    parent = NULL;
    if (elements->szParentInstance != NULL) {
        parent = we_convert_wstr(elements->szParentInstance, CP_UTF8);
        if (parent == NULL) {
            flb_free(instance);
            flb_free(elements);
            return NULL;
        }
    }

    label = compose_instance_label(parent, instance, elements->dwInstanceIndex);

    flb_free(parent);
    flb_free(instance);
    flb_free(elements);

    return label;
}

static void remove_counter(struct we_performancecounter_counter *counter,
                           int remove_metric)
{
    struct cmt_metric *metric;

    if (counter->handle != NULL) {
        PdhRemoveCounter(counter->handle);
    }

    if (remove_metric && counter->label_count > 0) {
        metric = cmt_map_metric_get(&counter->metric->opts,
                                    counter->metric->map,
                                    counter->label_count,
                                    counter->label_values,
                                    CMT_FALSE);
        if (metric != NULL) {
            cmt_map_metric_destroy(metric);
        }
    }

    mk_list_del(&counter->_head);

    flb_free(counter->name);
    flb_free(counter->path);
    flb_free(counter->path_w);
    flb_free(counter->instance);
    flb_free(counter);
}

static struct we_performancecounter_counter *find_counter_path(
        struct flb_we *ctx, struct we_performancecounter_definition *definition,
        char *path)
{
    struct mk_list *head;
    struct we_performancecounter_counter *counter;

    mk_list_foreach(head, &ctx->performancecounter->counters) {
        counter = mk_list_entry(head, struct we_performancecounter_counter, _head);
        if (counter->definition == definition && strcmp(counter->path, path) == 0) {
            return counter;
        }
    }

    return NULL;
}

static int add_counter_path(struct flb_we *ctx,
                            struct we_performancecounter_definition *definition,
                            char *path,
                            int with_instance_label,
                            int use_english_path)
{
    PDH_STATUS status;
    wchar_t *path_w;
    struct we_performancecounter_counter *counter;

    path_w = we_convert_str(path);
    if (path_w == NULL) {
        return -1;
    }

    counter = flb_calloc(1, sizeof(struct we_performancecounter_counter));
    if (counter == NULL) {
        flb_errno();
        flb_free(path_w);
        return -1;
    }

    counter->definition = definition;
    counter->name = flb_strdup(definition->name);
    counter->path = flb_strdup(path);
    counter->path_w = path_w;
    counter->metric = definition->metric;
    counter->label_count = 0;
    counter->valid = FLB_FALSE;
    counter->seen_valid = FLB_FALSE;
    counter->stale = FLB_FALSE;

    if (counter->name == NULL || counter->path == NULL) {
        flb_errno();
        flb_free(counter->path_w);
        flb_free(counter->name);
        flb_free(counter->path);
        flb_free(counter);
        return -1;
    }

    if (with_instance_label) {
        counter->instance = get_counter_instance(counter->path_w);
        if (counter->instance == NULL) {
            counter->instance = flb_strdup(counter->path);
        }
        if (counter->instance == NULL) {
            flb_errno();
            flb_free(counter->path_w);
            flb_free(counter->name);
            flb_free(counter->path);
            flb_free(counter);
            return -1;
        }
        counter->label_values[0] = counter->instance;
        counter->label_count = 1;
    }

    if (use_english_path) {
        status = PdhAddEnglishCounterW(ctx->performancecounter->query,
                                       counter->path_w,
                                       0,
                                       &counter->handle);
    }
    else {
        status = PdhAddCounterW(ctx->performancecounter->query,
                                counter->path_w,
                                0,
                                &counter->handle);
    }

    if (status == ERROR_SUCCESS) {
        counter->valid = FLB_TRUE;
    }
    else {
        flb_plg_warn(ctx->ins,
                     "could not add PerformanceCounter '%s' (%s): 0x%08lx",
                     counter->name, counter->path, (unsigned long) status);
    }

    mk_list_add(&counter->_head, &ctx->performancecounter->counters);

    return 0;
}

static void free_definition(struct we_performancecounter_definition *definition)
{
    mk_list_del(&definition->_head);

    flb_free(definition->name);
    flb_free(definition->path);
    flb_free(definition->path_w);
    flb_free(definition);
}

static int get_localized_wildcard_path(struct flb_we *ctx,
                                       struct we_performancecounter_definition *definition,
                                       wchar_t **out_path)
{
    PDH_STATUS status;
    PDH_HCOUNTER handle;
    DWORD size;
    PPDH_COUNTER_INFO_W info;
    wchar_t *localized_path;

    handle = NULL;
    size = 0;
    info = NULL;
    localized_path = NULL;
    *out_path = NULL;

    status = PdhAddEnglishCounterW(ctx->performancecounter->query,
                                   definition->path_w,
                                   0,
                                   &handle);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    status = PdhGetCounterInfoW(handle, TRUE, &size, NULL);
    if (status != PDH_MORE_DATA) {
        PdhRemoveCounter(handle);
        return status;
    }

    info = flb_calloc(1, size);
    if (info == NULL) {
        flb_errno();
        PdhRemoveCounter(handle);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    status = PdhGetCounterInfoW(handle, TRUE, &size, info);
    if (status != ERROR_SUCCESS) {
        flb_free(info);
        PdhRemoveCounter(handle);
        return status;
    }

    localized_path = flb_calloc(wcslen(info->szFullPath) + 1, sizeof(wchar_t));
    if (localized_path == NULL) {
        flb_errno();
        flb_free(info);
        PdhRemoveCounter(handle);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    wcscpy(localized_path, info->szFullPath);

    flb_free(info);
    PdhRemoveCounter(handle);

    *out_path = localized_path;

    return ERROR_SUCCESS;
}

static int add_expanded_counter_paths(struct flb_we *ctx,
                                      struct we_performancecounter_definition *definition)
{
    PDH_STATUS status;
    DWORD length;
    wchar_t *paths;
    wchar_t *path;
    wchar_t *localized_path;
    char *path_utf8;
    struct we_performancecounter_counter *counter;
    int added;

    length = 0;
    localized_path = NULL;

    status = get_localized_wildcard_path(ctx, definition, &localized_path);
    if (status != ERROR_SUCCESS) {
        if (!definition->warned_expand_failure) {
            flb_plg_warn(ctx->ins,
                         "could not localize PerformanceCounter wildcard '%s': 0x%08lx",
                         definition->path, (unsigned long) status);
            definition->warned_expand_failure = FLB_TRUE;
        }
        return 1;
    }

    status = PdhExpandWildCardPathW(NULL, localized_path, NULL, &length, 0);
    if (status != PDH_MORE_DATA) {
        if (!definition->warned_expand_failure) {
            flb_plg_warn(ctx->ins,
                         "could not expand PerformanceCounter wildcard '%s': 0x%08lx",
                         definition->path, (unsigned long) status);
            definition->warned_expand_failure = FLB_TRUE;
        }
        flb_free(localized_path);
        return 1;
    }

    paths = flb_calloc(length, sizeof(wchar_t));
    if (paths == NULL) {
        flb_errno();
        flb_free(localized_path);
        return -1;
    }

    status = PdhExpandWildCardPathW(NULL, localized_path, paths, &length, 0);
    flb_free(localized_path);

    if (status != ERROR_SUCCESS) {
        if (!definition->warned_expand_failure) {
            flb_plg_warn(ctx->ins,
                         "could not expand PerformanceCounter wildcard '%s': 0x%08lx",
                         definition->path, (unsigned long) status);
            definition->warned_expand_failure = FLB_TRUE;
        }
        flb_free(paths);
        return 1;
    }

    definition->warned_expand_failure = FLB_FALSE;

    added = 0;
    path = paths;

    while (*path != L'\0') {
        path_utf8 = we_convert_wstr(path, CP_UTF8);
        if (path_utf8 == NULL) {
            flb_free(paths);
            return -1;
        }

        counter = find_counter_path(ctx, definition, path_utf8);
        if (counter != NULL) {
            counter->stale = FLB_FALSE;
            flb_free(path_utf8);
            added++;
            path += wcslen(path) + 1;
            continue;
        }

        if (add_counter_path(ctx, definition, path_utf8, FLB_TRUE, FLB_FALSE) != 0) {
            flb_free(path_utf8);
            flb_free(paths);
            return -1;
        }

        flb_free(path_utf8);
        added++;
        path += wcslen(path) + 1;
    }

    if (added == 0) {
        if (!definition->warned_no_instances) {
            flb_plg_warn(ctx->ins,
                         "PerformanceCounter wildcard '%s' did not match any instances",
                         definition->path);
            definition->warned_no_instances = FLB_TRUE;
        }
    }
    else {
        definition->warned_no_instances = FLB_FALSE;
    }

    flb_free(paths);

    return 0;
}

static int refresh_wildcard_counters(struct flb_we *ctx,
                                     struct we_performancecounter_definition *definition)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct we_performancecounter_counter *counter;
    int ret;

    mk_list_foreach(head, &ctx->performancecounter->counters) {
        counter = mk_list_entry(head, struct we_performancecounter_counter, _head);
        if (counter->definition == definition) {
            counter->stale = FLB_TRUE;
        }
    }

    ret = add_expanded_counter_paths(ctx, definition);
    if (ret < 0) {
        return -1;
    }
    else if (ret > 0) {
        mk_list_foreach(head, &ctx->performancecounter->counters) {
            counter = mk_list_entry(head, struct we_performancecounter_counter, _head);
            if (counter->definition == definition) {
                counter->stale = FLB_FALSE;
            }
        }
        return 0;
    }

    mk_list_foreach_safe(head, tmp, &ctx->performancecounter->counters) {
        counter = mk_list_entry(head, struct we_performancecounter_counter, _head);
        if (counter->definition == definition && counter->stale) {
            remove_counter(counter, FLB_TRUE);
        }
    }

    return 0;
}

static int add_counter(struct flb_we *ctx, char *entry)
{
    char *name;
    char *path;
    char *metric_name;
    struct cmt_gauge *gauge;
    int has_wildcard;
    int label_count;
    char *labels[] = { "instance" };
    struct we_performancecounter_definition *definition;
    int ret;

    if (parse_counter_config(ctx, entry, &name, &path, &has_wildcard) != 0) {
        return -1;
    }

    metric_name = sanitize_metric_name(name);
    if (metric_name == NULL) {
        return -1;
    }

    label_count = 0;
    if (has_wildcard) {
        label_count = 1;
    }

    gauge = cmt_gauge_create(ctx->cmt, "windows", "performancecounter",
                             metric_name,
                             "Windows Performance Counter value",
                             label_count, labels);
    if (gauge == NULL) {
        flb_plg_error(ctx->ins,
                      "could not create performancecounter metric '%s'",
                      metric_name);
        flb_free(metric_name);
        return -1;
    }

    definition = flb_calloc(1, sizeof(struct we_performancecounter_definition));
    if (definition == NULL) {
        flb_errno();
        flb_free(metric_name);
        return -1;
    }

    definition->name = flb_strdup(metric_name);
    definition->path = flb_strdup(path);
    definition->path_w = we_convert_str(path);
    definition->metric = gauge;
    definition->has_wildcard = has_wildcard;
    definition->warned_expand_failure = FLB_FALSE;
    definition->warned_no_instances = FLB_FALSE;

    if (definition->name == NULL || definition->path == NULL ||
        definition->path_w == NULL) {
        flb_errno();
        flb_free(definition->name);
        flb_free(definition->path);
        flb_free(definition->path_w);
        flb_free(definition);
        flb_free(metric_name);
        return -1;
    }

    mk_list_add(&definition->_head, &ctx->performancecounter->definitions);

    if (!has_wildcard) {
        ret = add_counter_path(ctx, definition, path, FLB_FALSE, FLB_TRUE);
        flb_free(metric_name);
        return ret;
    }

    ret = add_expanded_counter_paths(ctx, definition);
    if (ret > 0) {
        ret = 0;
    }

    flb_free(metric_name);

    return ret;
}

int we_performancecounter_init(struct flb_we *ctx)
{
    PDH_STATUS status;
    struct mk_list *head;
    struct flb_config_map_val *mv;

    ctx->performancecounter = flb_calloc(1, sizeof(struct we_performancecounter_counters));
    if (ctx->performancecounter == NULL) {
        flb_errno();
        return -1;
    }

    ctx->performancecounter->query = NULL;
    ctx->performancecounter->operational = FLB_FALSE;
    mk_list_init(&ctx->performancecounter->definitions);
    mk_list_init(&ctx->performancecounter->counters);

    if (ctx->raw_performance_counters == NULL ||
        mk_list_size(ctx->raw_performance_counters) == 0) {
        flb_plg_error(ctx->ins,
                      "performancecounter metrics require at least one PerformanceCounter entry");
        we_performancecounter_exit(ctx);
        return -1;
    }

    status = PdhOpenQueryW(NULL, 0, &ctx->performancecounter->query);
    if (status != ERROR_SUCCESS) {
        flb_plg_warn(ctx->ins,
                     "could not initialize PerformanceCounter PDH query: 0x%08lx",
                     (unsigned long) status);
        we_performancecounter_exit(ctx);
        return -1;
    }

    flb_config_map_foreach(head, mv, ctx->raw_performance_counters) {
        if (add_counter(ctx, mv->val.str) != 0) {
            we_performancecounter_exit(ctx);
            return -1;
        }
    }

    status = PdhCollectQueryData(ctx->performancecounter->query);
    if (status != ERROR_SUCCESS) {
        flb_plg_debug(ctx->ins,
                      "initial PerformanceCounter collection failed: 0x%08lx",
                      (unsigned long) status);
    }

    ctx->performancecounter->operational = FLB_TRUE;

    return 0;
}

int we_performancecounter_exit(struct flb_we *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct we_performancecounter_counter *counter;
    struct we_performancecounter_definition *definition;

    if (ctx->performancecounter == NULL) {
        return 0;
    }

    ctx->performancecounter->operational = FLB_FALSE;

    mk_list_foreach_safe(head, tmp, &ctx->performancecounter->counters) {
        counter = mk_list_entry(head, struct we_performancecounter_counter, _head);
        remove_counter(counter, FLB_FALSE);
    }

    mk_list_foreach_safe(head, tmp, &ctx->performancecounter->definitions) {
        definition = mk_list_entry(head, struct we_performancecounter_definition, _head);
        free_definition(definition);
    }

    if (ctx->performancecounter->query != NULL) {
        PdhCloseQuery(ctx->performancecounter->query);
    }

    flb_free(ctx->performancecounter);
    ctx->performancecounter = NULL;

    return 0;
}

int we_performancecounter_update(struct flb_we *ctx)
{
    PDH_STATUS status;
    PDH_FMT_COUNTERVALUE value;
    uint64_t timestamp;
    struct mk_list *head;
    struct we_performancecounter_counter *counter;
    struct we_performancecounter_definition *definition;

    if (ctx->performancecounter == NULL ||
        !ctx->performancecounter->operational) {
        flb_plg_debug(ctx->ins,
                      "performancecounter collector not in operational state");
        return 0;
    }

    mk_list_foreach(head, &ctx->performancecounter->definitions) {
        definition = mk_list_entry(head, struct we_performancecounter_definition, _head);
        if (definition->has_wildcard) {
            if (refresh_wildcard_counters(ctx, definition) != 0) {
                flb_plg_debug(ctx->ins,
                              "PerformanceCounter wildcard refresh failed for '%s'",
                              definition->path);
            }
        }
    }

    status = PdhCollectQueryData(ctx->performancecounter->query);
    if (status != ERROR_SUCCESS) {
        flb_plg_debug(ctx->ins,
                      "PerformanceCounter collection failed: 0x%08lx",
                      (unsigned long) status);
        return 0;
    }

    timestamp = cfl_time_now();

    mk_list_foreach(head, &ctx->performancecounter->counters) {
        counter = mk_list_entry(head, struct we_performancecounter_counter, _head);
        if (!counter->valid) {
            continue;
        }

        memset(&value, 0, sizeof(value));

        status = PdhGetFormattedCounterValue(counter->handle,
                                             PDH_FMT_DOUBLE,
                                             NULL,
                                             &value);
        if (status != ERROR_SUCCESS || value.CStatus != ERROR_SUCCESS) {
            flb_plg_debug(ctx->ins,
                          "PerformanceCounter '%s' returned invalid data: "
                          "status=0x%08lx cstatus=0x%08lx",
                          counter->name,
                          (unsigned long) status,
                          (unsigned long) value.CStatus);
            continue;
        }

        counter->seen_valid = FLB_TRUE;
        cmt_gauge_set(counter->metric, timestamp, value.doubleValue,
                      counter->label_count, counter->label_values);
    }

    return 0;
}
