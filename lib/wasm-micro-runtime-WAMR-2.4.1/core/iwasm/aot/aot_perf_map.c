/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_perf_map.h"
#include "bh_log.h"
#include "bh_platform.h"

struct func_info {
    uint32 idx;
    void *ptr;
};

static uint32
get_func_size(const AOTModule *module, struct func_info *sorted_func_ptrs,
              uint32 idx)
{
    uint32 func_sz;

    if (idx == module->func_count - 1)
        func_sz = (uintptr_t)module->code + module->code_size
                  - (uintptr_t)(sorted_func_ptrs[idx].ptr);
    else
        func_sz = (uintptr_t)(sorted_func_ptrs[idx + 1].ptr)
                  - (uintptr_t)(sorted_func_ptrs[idx].ptr);

    return func_sz;
}

static int
compare_func_ptrs(const void *f1, const void *f2)
{
    uintptr_t ptr1 = (uintptr_t)((struct func_info *)f1)->ptr;
    uintptr_t ptr2 = (uintptr_t)((struct func_info *)f2)->ptr;

    if (ptr1 < ptr2)
        return -1;
    else if (ptr1 > ptr2)
        return 1;
    else
        return 0;
}

static struct func_info *
sort_func_ptrs(const AOTModule *module, char *error_buf, uint32 error_buf_size)
{
    uint64 content_len;
    struct func_info *sorted_func_ptrs;
    unsigned i;

    content_len = (uint64)sizeof(struct func_info) * module->func_count;
    sorted_func_ptrs = wasm_runtime_malloc(content_len);
    if (!sorted_func_ptrs) {
        (void)snprintf(error_buf, error_buf_size,
                       "allocate memory failed when creating perf map");
        return NULL;
    }

    for (i = 0; i < module->func_count; i++) {
        sorted_func_ptrs[i].idx = i;
        sorted_func_ptrs[i].ptr = module->func_ptrs[i];
    }

    qsort(sorted_func_ptrs, module->func_count, sizeof(struct func_info),
          compare_func_ptrs);

    return sorted_func_ptrs;
}

bool
aot_create_perf_map(const AOTModule *module, char *error_buf,
                    uint32 error_buf_size)
{
    struct func_info *sorted_func_ptrs = NULL;
    char perf_map_path[64] = { 0 };
    char perf_map_info[128] = { 0 };
    FILE *perf_map = NULL;
    uint32 i;
    pid_t pid = getpid();
    bool ret = false;

    sorted_func_ptrs = sort_func_ptrs(module, error_buf, error_buf_size);
    if (!sorted_func_ptrs)
        goto quit;

    (void)snprintf(perf_map_path, sizeof(perf_map_path) - 1, "/tmp/perf-%d.map",
                   pid);
    perf_map = fopen(perf_map_path, "a");
    if (!perf_map) {
        LOG_WARNING("warning: can't create /tmp/perf-%d.map, because %s", pid,
                    strerror(errno));
        goto quit;
    }

    const char *module_name = aot_get_module_name((AOTModule *)module);
    for (i = 0; i < module->func_count; i++) {
        memset(perf_map_info, 0, 128);
        if (strlen(module_name) > 0) {
            (void)snprintf(perf_map_info, 128,
                           "%" PRIxPTR "  %x  [%s]#aot_func#%u\n",
                           (uintptr_t)sorted_func_ptrs[i].ptr,
                           get_func_size(module, sorted_func_ptrs, i),
                           module_name, sorted_func_ptrs[i].idx);
        }
        else {
            (void)snprintf(perf_map_info, 128,
                           "%" PRIxPTR "  %x  aot_func#%u\n",
                           (uintptr_t)sorted_func_ptrs[i].ptr,
                           get_func_size(module, sorted_func_ptrs, i),
                           sorted_func_ptrs[i].idx);
        }

        /* fwrite() is thread safe */
        (void)fwrite(perf_map_info, 1, strlen(perf_map_info), perf_map);
    }

    LOG_VERBOSE("write map information from %s into /tmp/perf-%d.map",
                module_name, pid);
    ret = true;

quit:
    if (sorted_func_ptrs)
        wasm_runtime_free(sorted_func_ptrs);

    if (perf_map)
        (void)fclose(perf_map);

    return ret;
}
