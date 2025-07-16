/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_wmi.h"
#include "we_wmi_memory.h"
#include "we_util.h"
#include "we_metric.h"

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_memory_init(struct flb_we *ctx)
{
    struct cmt_gauge *g;

    ctx->wmi_memory = flb_calloc(1, sizeof(struct we_wmi_memory_counters));
    if (!ctx->wmi_memory) {
        flb_errno();
        return -1;
    }
    ctx->wmi_memory->operational = FLB_FALSE;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "available_bytes",
                         "The amount of physical memory, in bytes, immediately available " \
                         "for allocation to a process or for system use. (AvailableBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->available_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "cache_bytes",
                         "The size, in bytes, of the portion of the system file cache " \
                         "which is currently resident and active in physical memory "\
                         "(CacheBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->cache_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "cache_bytes_peak",
                         "the maximum number of bytes used by the system file cache " \
                         "since the system was last restarted (CacheBytesPeak)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->cache_bytes_peak = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "cache_faults_total",
                         "The rate at which faults occur when a page sought in " \
                         "the file system cache is not found and must be retrieved " \
                         "from elsewhere in memory (a soft fault) or from disk (a hard fault)" \
                         "(CacheFaultsPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->cache_faults_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "commit_limit",
                         "The amount of virtual memory that can be committed " \
                         "without having to extend the paging file(s) " \
                         "(CommitLimit)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->commit_limit = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "committed_bytes",
                         "The amount of committed virtual memory, in bytes " \
                         "(CommittedBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->committed_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "demand_zero_faults_total",
                         "The rate at which a zeroed page is required to satisfy the fault " \
                         "(DemandZeroFaultsPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->demand_zero_faults_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "free_and_zero_page_list_bytes",
                         "the amount of physical memory, in bytes, that is assigned to " \
                         "the free and zero page lists " \
                         "(FreeAndZeroPageListBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->free_and_zero_page_list_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "free_system_page_table_entries",
                         "The number of page table entries not currently in used by the system " \
                         "(FreeSystemPageTableEntries)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->free_system_page_table_entries = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "modified_page_list_bytes",
                         "The amount of physical memory, in bytes, that is assigned to " \
                         "the modified page list " \
                         "(ModifiedPageListBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->modified_page_list_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "page_faults_total",
                         "The average number of pages faulted per second. " \
                         "It is measured in number of pages faulted per second " \
                         "because only one page is faulted in each fault operation, " \
                         "hence this is also equal to the number of page fault operations " \
                         "(PageFaultsPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->page_faults_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "swap_page_reads_total",
                         "The rate at which the disk was read to resolve hard page faults " \
                         "(PageReadsPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->swap_page_reads_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "swap_pages_read_total",
                         "The rate at which pages are read from disk to resolve hard page faults " \
                         "(PagesInputPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->swap_pages_read_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "swap_pages_written_total",
                         "the rate at which pages are written to disk to free up space "\
                         "in physical memory (PagesOutputPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->swap_pages_written_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "swap_page_operations_total",
                         "the rate at which pages are read from or written " \
                         "to disk to resolve hard page faults (PagesPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->swap_page_operations_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "swap_page_writes_total",
                         "the rate at which pages are written to disk to free up space " \
                         "in physical memory (PageWritesPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->swap_page_writes_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "pool_nonpaged_allocs_total",
                         "Number of calls to allocate space in the nonpaged pool (PoolNonpagedAllocs)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->pool_nonpaged_allocs_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "pool_nonpaged_bytes",
                         "the size, in bytes, of the nonpaged pool, an area of " \
                         "the system virtual memory that is used for objects " \
                         "that cannot be written to disk, but must remain " \
                         "in physical memory as long as they are allocated " \
                         "(PoolNonpagedBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->pool_nonpaged_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "pool_paged_allocs_total",
                         "Number of bytes of allocated space in paged pool (PoolPagedAllocs)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->pool_paged_allocs_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "pool_paged_bytes",
                         "the size, in bytes, of the paged pool, an area of the system " \
                         "virtual memory that is used for objects that can be written " \
                         "to disk when they are not being used (PoolPagedBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->pool_paged_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "pool_paged_resident_bytes",
                         "the size, in bytes, of the portion of the paged pool " \
                         "that is currently resident and active in physical memory " \
                         "(PoolPagedResidentBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->pool_paged_resident_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "standby_cache_core_bytes",
                         "The amount of physical memory, in bytes, that is assigned " \
                         "to the core standby cache page lists (StandbyCacheCoreBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->standby_cache_core_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "standby_cache_normal_priority_bytes",
                         " the amount of physical memory, in bytes, that is assigned " \
                         "to the normal priority standby cache page lists " \
                         "(StandbyCacheNormalPriorityBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->standby_cache_normal_priority_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "standby_cache_reserve_bytes",
                         "Number of physical memory size(bytes) which is assigned to " \
                         "the reserve standby cache page lists (StandbyCacheReserveBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->standby_cache_reserve_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "system_cache_resident_bytes",
                         "Number of physical memory size(bytes) of the portion of " \
                         "the system file cache which is currently resident and active " \
                         "(SystemCacheResidentBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->system_cache_resident_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "system_code_resident_bytes",
                         "Number of physical memory size(bytes) of the pageable operating system code "\
                         "which is currently resident and active (SystemCodeResidentBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->system_code_resident_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "system_code_total_bytes",
                         "Number of virtual memory size(bytes) of the pageable operating system code " \
                         "which is mapped into virtual address (SystemCodeTotalBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->system_code_total_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "system_driver_resident_bytes",
                         "Number of pagable physical memory size(bytes) by used device drivers "\
                         "(SystemDriverResidentBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->system_driver_resident_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "system_driver_total_bytes",
                         "Number of virtual memory size(bytes) by used device drivers " \
                         "(SystemDriverTotalBytes)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->system_driver_total_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "transition_faults_total",
                         "Number of the rate at which page faults are resolved by recovering pages " \
                         "that were being used by another process sharing the page, " \
                         "or were on the modified page list or the standby list, " \
                         "or were being written to disk at the time of the page fault " \
                         "(TransitionFaultsPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->transition_faults_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "transition_pages_repurposed_total",
                         "Number of the rate at which the number of transition cache " \
                         "pages were reused for a different purpose " \
                         "(TransitionPagesRePurposedPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->transition_pages_repurposed_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "memory", "write_copies_total",
                         "Number of the rate at which page faults are caused by "\
                         "attempts to write that have been satisfied by coping " \
                         "of the page from elsewhere in physical memory " \
                         "(WriteCopiesPersec)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_memory->write_copies_total = g;

    ctx->wmi_memory->info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_memory->info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_memory->info->metric_instance = (void *)g;
    ctx->wmi_memory->info->type = CMT_GAUGE;
    ctx->wmi_memory->info->value_adjuster = nop_adjust;
    ctx->wmi_memory->info->wmi_counter = "Win32_PerfRawData_PerfOS_Memory";
    ctx->wmi_memory->info->wmi_property = "";
    ctx->wmi_memory->info->label_property_count = 0;
    ctx->wmi_memory->info->label_property_keys = NULL;
    ctx->wmi_memory->info->where_clause = NULL;

    ctx->wmi_memory->operational = FLB_TRUE;

    return 0;
}

int we_wmi_memory_exit(struct flb_we *ctx)
{
    ctx->wmi_memory->operational = FLB_FALSE;

    flb_free(ctx->wmi_memory->info);
    flb_free(ctx->wmi_memory);

    return 0;
}

int we_wmi_memory_update(struct flb_we *ctx)
{
    uint64_t timestamp = 0;
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;

    if (!ctx->wmi_memory->operational) {
        flb_plg_error(ctx->ins, "memory collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_coinitialize(ctx))) {
        return -1;
    }

    timestamp = cfl_time_now();

    if (FAILED(we_wmi_execute_query(ctx, ctx->wmi_memory->info, &enumerator))) {
        return -1;
    }

    while(enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &class_obj, &ret);

        if(ret == 0) {
            break;
        }

        val = we_wmi_get_property_value(ctx, "AvailableBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->available_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "CacheBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->cache_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "CacheBytesPeak", class_obj);
        cmt_gauge_set(ctx->wmi_memory->cache_bytes_peak, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "CacheFaultsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->cache_faults_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "CommitLimit", class_obj);
        cmt_gauge_set(ctx->wmi_memory->commit_limit, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "CommittedBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->committed_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "DemandZeroFaultsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->demand_zero_faults_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "FreeAndZeroPageListBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->free_and_zero_page_list_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "FreeSystemPageTableEntries", class_obj);
        cmt_gauge_set(ctx->wmi_memory->free_system_page_table_entries, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "ModifiedPageListBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->modified_page_list_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PageFaultsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->page_faults_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PageReadsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->swap_page_reads_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PagesInputPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->swap_pages_read_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PagesOutputPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->swap_pages_written_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PagesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->swap_page_operations_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PageWritesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->swap_page_writes_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PoolNonpagedAllocs", class_obj);
        cmt_gauge_set(ctx->wmi_memory->pool_nonpaged_allocs_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PoolNonpagedBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->pool_nonpaged_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PoolPagedAllocs", class_obj);
        cmt_gauge_set(ctx->wmi_memory->pool_paged_allocs_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PoolPagedBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->pool_paged_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PoolPagedResidentBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->pool_paged_resident_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "StandbyCacheCoreBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->standby_cache_core_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "StandbyCacheNormalPriorityBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->standby_cache_normal_priority_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "StandbyCacheReserveBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->standby_cache_reserve_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemCacheResidentBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->system_cache_resident_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemCacheResidentBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->system_cache_resident_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemCodeResidentBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->system_code_resident_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemCodeTotalBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->system_code_total_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemDriverResidentBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->system_driver_resident_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemDriverTotalBytes", class_obj);
        cmt_gauge_set(ctx->wmi_memory->system_driver_total_bytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "TransitionFaultsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->transition_faults_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "TransitionPagesRePurposedPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->transition_pages_repurposed_total, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "WriteCopiesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_memory->write_copies_total, timestamp, val, 0, NULL);

        class_obj->lpVtbl->Release(class_obj);
    }

    enumerator->lpVtbl->Release(enumerator);

    we_wmi_cleanup(ctx);

    return 0;
}
