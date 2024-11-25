/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "app_manager.h"
#include "app_manager_host.h"
#include "bh_platform.h"
#include "bi-inc/attr_container.h"
#include "event.h"
#include "watchdog.h"
#include "coap_ext.h"

/* Lock of the module data list */
korp_mutex module_data_list_lock;

/* Module data list */
module_data *module_data_list;

bool
module_data_list_init()
{
    module_data_list = NULL;
    return !os_mutex_init(&module_data_list_lock) ? true : false;
}

void
module_data_list_destroy()
{

    os_mutex_lock(&module_data_list_lock);
    if (module_data_list) {
        while (module_data_list) {
            module_data *p = module_data_list->next;
            APP_MGR_FREE(module_data_list);
            module_data_list = p;
        }
    }
    os_mutex_unlock(&module_data_list_lock);
    os_mutex_destroy(&module_data_list_lock);
}

static void
module_data_list_add(module_data *m_data)
{
    static uint32 module_id_max = 1;
    os_mutex_lock(&module_data_list_lock);
    // reserve some special ID
    // TODO: check the new id is not already occupied!
    if (module_id_max == 0xFFFFFFF0)
        module_id_max = 1;
    m_data->id = module_id_max++;
    if (!module_data_list) {
        module_data_list = m_data;
    }
    else {
        /* Set as head */
        m_data->next = module_data_list;
        module_data_list = m_data;
    }
    os_mutex_unlock(&module_data_list_lock);
}

void
module_data_list_remove(module_data *m_data)
{
    os_mutex_lock(&module_data_list_lock);
    if (module_data_list) {
        if (module_data_list == m_data)
            module_data_list = module_data_list->next;
        else {
            /* Search and remove it */
            module_data *p = module_data_list;

            while (p && p->next != m_data)
                p = p->next;
            if (p && p->next == m_data)
                p->next = p->next->next;
        }
    }
    os_mutex_unlock(&module_data_list_lock);
}

module_data *
module_data_list_lookup(const char *module_name)
{
    os_mutex_lock(&module_data_list_lock);
    if (module_data_list) {
        module_data *p = module_data_list;

        while (p) {
            /* Search by module name */
            if (!strcmp(module_name, p->module_name)) {
                os_mutex_unlock(&module_data_list_lock);
                return p;
            }
            p = p->next;
        }
    }
    os_mutex_unlock(&module_data_list_lock);
    return NULL;
}

module_data *
module_data_list_lookup_id(unsigned int module_id)
{
    os_mutex_lock(&module_data_list_lock);
    if (module_data_list) {
        module_data *p = module_data_list;

        while (p) {
            /* Search by module name */
            if (module_id == p->id) {
                os_mutex_unlock(&module_data_list_lock);
                return p;
            }
            p = p->next;
        }
    }
    os_mutex_unlock(&module_data_list_lock);
    return NULL;
}

module_data *
app_manager_get_module_data(uint32 module_type, void *module_inst)
{
    if (module_type < Module_Max && g_module_interfaces[module_type]
        && g_module_interfaces[module_type]->module_get_module_data)
        return g_module_interfaces[module_type]->module_get_module_data(
            module_inst);
    return NULL;
}

void *
app_manager_get_module_queue(uint32 module_type, void *module_inst)
{
    module_data *m_data = app_manager_get_module_data(module_type, module_inst);
    return m_data ? m_data->queue : NULL;
}

const char *
app_manager_get_module_name(uint32 module_type, void *module_inst)
{
    module_data *m_data = app_manager_get_module_data(module_type, module_inst);
    return m_data ? m_data->module_name : NULL;
}

unsigned int
app_manager_get_module_id(uint32 module_type, void *module_inst)
{
    module_data *m_data = app_manager_get_module_data(module_type, module_inst);
    return m_data ? m_data->id : ID_NONE;
}

void *
app_manager_get_module_heap(uint32 module_type, void *module_inst)
{
    module_data *m_data = app_manager_get_module_data(module_type, module_inst);
    return m_data ? m_data->heap : NULL;
}

module_data *
app_manager_lookup_module_data(const char *name)
{
    return module_data_list_lookup(name);
}

void
app_manager_add_module_data(module_data *m_data)
{
    module_data_list_add(m_data);
}

void
app_manager_del_module_data(module_data *m_data)
{
    module_data_list_remove(m_data);

    release_module(m_data);
}

bool
app_manager_is_interrupting_module(uint32 module_type, void *module_inst)
{
    module_data *m_data = app_manager_get_module_data(module_type, module_inst);
    return m_data ? m_data->wd_timer.is_interrupting : false;
}

extern void
destroy_module_timer_ctx(unsigned int module_id);

void
release_module(module_data *m_data)
{
    watchdog_timer_destroy(&m_data->wd_timer);

#ifdef HEAP_ENABLED /* TODO */
    if (m_data->heap)
        gc_destroy_for_instance(m_data->heap);
#endif

    if (m_data->queue)
        bh_queue_destroy(m_data->queue);

    m_data->timer_ctx = NULL;

    destroy_module_timer_ctx(m_data->id);

    APP_MGR_FREE(m_data);
}

uint32
check_modules_timer_expiry()
{
    os_mutex_lock(&module_data_list_lock);
    module_data *p = module_data_list;
    uint32 ms_to_expiry = (uint32)-1;

    while (p) {
        uint32 next = get_expiry_ms(p->timer_ctx);
        if (next != (uint32)-1) {
            if (ms_to_expiry == (uint32)-1 || ms_to_expiry > next)
                ms_to_expiry = next;
        }

        p = p->next;
    }
    os_mutex_unlock(&module_data_list_lock);
    return ms_to_expiry;
}
