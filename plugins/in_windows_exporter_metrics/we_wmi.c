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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_util.h"
#include "we_wmi.h"

static int wmi_coinitialize(struct flb_we *ctx, char* wmi_namespace)
{
    IWbemLocator *locator = 0;
    IWbemServices *service = 0;
    HRESULT hr;
    wchar_t *wnamespace;

    flb_plg_debug(ctx->ins, "initializing WMI instance....");

    /* Initialize COM library */
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        flb_plg_error(ctx->ins, "Failed to initialize COM library. Error code = %x", hr);
        return -1;
    }

    /* Initialize COM security */
    hr = CoInitializeSecurity(NULL,
                              -1,
                              NULL,
                              NULL,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL,
                              EOAC_NONE,
                              NULL);

    if (FAILED(hr)) {
        return hr;
    }

    /* Create WMI instance */
    hr = CoCreateInstance(&CLSID_WbemLocator, 0,
                          CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &locator);
    if (FAILED(hr)) {
        flb_plg_error(ctx->ins, "Failed to create IWbemLocator object. Error code = %x", hr);
        CoUninitialize();
        return hr;
    }
    ctx->locator = locator;

    if (wmi_namespace == NULL) {
        wnamespace = we_convert_str("ROOT\\CIMV2");
    }
    else {
        wnamespace = we_convert_str(wmi_namespace);
    }
    /* Connect WMI server */
    hr = locator->lpVtbl->ConnectServer(locator,
                                        wnamespace,
                                        NULL,
                                        NULL,
                                        0,
                                        0,
                                        0,
                                        NULL,
                                        &service);
    flb_free(wnamespace);

    if (FAILED(hr)) {
        flb_plg_error(ctx->ins, "Could not connect. Error code = %x", hr);
        locator->lpVtbl->Release(locator);
        CoUninitialize();
        return hr;
    }
    ctx->service = service;

    /* Set up ProxyBlanket */
    hr = CoSetProxyBlanket(service,
                           RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE,
                           NULL,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           NULL,
                           EOAC_NONE
                           );
    if (FAILED(hr)) {
        flb_plg_error(ctx->ins, "Could not set proxy blanket. Error code = %x", hr);
        service->lpVtbl->Release(service);
        locator->lpVtbl->Release(locator);
        CoUninitialize();
        return hr;
    }

    return 0;
}



int wmi_utils_str_to_double(char *str, double *out_val)
{
    double val;
    char *end;

    errno = 0;
    val = strtod(str, &end);
    if (errno != 0 || *end != '\0') {
        return -1;
    }
    *out_val = val;
    return 0;
}

static int wmi_update_counters(struct wmi_query_spec *spec, uint64_t timestamp, double val, int metric_label_count, char **metric_label_set)
{
    val = spec->value_adjuster(val);

    if (spec->type == CMT_GAUGE) {
        cmt_gauge_set((struct cmt_gauge *)spec->metric_instance, timestamp,
                      val,
                      metric_label_count, metric_label_set);
    }
    else if (spec->type == CMT_COUNTER) {
        cmt_counter_set((struct cmt_counter *)spec->metric_instance, timestamp,
                        val,
                        metric_label_count, metric_label_set);
    }

    return 0;
}

static char *convert_prop_to_str(VARIANT *prop, int handle_null)
{
    char *strlabel = NULL;
    char *newstr = NULL;

    if (handle_null == FLB_TRUE && prop->vt == VT_NULL) {
        newstr = strdup("");
        if (newstr == NULL) {
            return NULL;
        }
    }
    else {
        if (VariantChangeType(prop, prop, 0, VT_BSTR) != S_OK) {
            return NULL;
        }
        strlabel = we_convert_wstr(prop->bstrVal, CP_UTF8);
        if (strlabel == NULL) {
            return NULL;
        }
        newstr = strdup(strlabel);
        if (newstr == NULL) {
            free(strlabel);
            return NULL;
        }
        free(strlabel);
    }
    return newstr;
}

static double wmi_get_value(struct flb_we *ctx, struct wmi_query_spec *spec, IWbemClassObject *class_obj)
{
    VARIANT prop;
    char *strprop;
    double val = 1.0;
    HRESULT hr;
    wchar_t *wproperty;

    VariantInit(&prop);
    wproperty = we_convert_str(spec->wmi_property);
    hr = class_obj->lpVtbl->Get(class_obj, wproperty, 0, &prop, 0, 0);
    if (FAILED(hr)) {
        flb_plg_warn(ctx->ins, "Retrive prop failed. Error code = %x", hr);
    }
    strprop = convert_prop_to_str(&prop, FLB_FALSE);
    if (strprop == NULL) {
        return 0;
    }
    wmi_utils_str_to_double(strprop, &val);
    flb_free(strprop);
    VariantClear(&prop);
    flb_free(wproperty);

    return val;
}

static double wmi_get_property_value(struct flb_we *ctx, char *raw_property_key, IWbemClassObject *class_obj)
{
    VARIANT prop;
    char *strprop;
    double val = 1.0;
    HRESULT hr;
    wchar_t *wproperty;

    VariantInit(&prop);
    wproperty = we_convert_str(raw_property_key);
    hr = class_obj->lpVtbl->Get(class_obj, wproperty, 0, &prop, 0, 0);
    if (FAILED(hr)) {
        flb_plg_warn(ctx->ins, "Retrive prop failed. Error code = %x", hr);
    }
    strprop = convert_prop_to_str(&prop, FLB_FALSE);
    if (strprop == NULL) {
        return 0;
    }
    wmi_utils_str_to_double(strprop, &val);
    flb_free(strprop);
    VariantClear(&prop);
    flb_free(wproperty);

    return val;
}


static inline int wmi_update_metrics(struct flb_we *ctx, struct wmi_query_spec *spec,
                                     double val, IWbemClassObject *class_obj, uint64_t timestamp)
{

    VARIANT prop;
    int label_index = 0;
    HRESULT hr;
    char *metric_label_set[WE_WMI_METRIC_LABEL_LIST_SIZE];
    int metric_label_count = 0;
    char buf[16] = {0};
    wchar_t *wlabel;
    char *newstr = NULL;

    VariantInit(&prop);
    metric_label_count = 0;
    for (label_index = 0; label_index < spec->label_property_count; label_index++) {
        wlabel = we_convert_str(spec->label_property_keys[label_index]);
        hr = class_obj->lpVtbl->Get(class_obj, wlabel, 0, &prop, 0, 0);
        if (FAILED(hr)) {
            flb_plg_warn(ctx->ins, "Retrive prop failed. Error code = %x", hr);
        }
        newstr = convert_prop_to_str(&prop, FLB_TRUE);
        if (newstr == NULL) {
            continue;
        }
        metric_label_set[label_index] = newstr;
        metric_label_count++;
        VariantClear(&prop);
        flb_free(wlabel);
    }

    wmi_update_counters(spec, timestamp, val, metric_label_count, metric_label_set);

    VariantClear(&prop);

    return 0;
}

static inline int wmi_execute_query(struct flb_we *ctx, struct wmi_query_spec *spec, IEnumWbemClassObject **out_enumerator)
{
    HRESULT hr;
    wchar_t *wquery;
    char *query = NULL;
    IEnumWbemClassObject* enumerator = NULL;
    size_t size;

    size = 14 + strlen(spec->wmi_counter);
    query = flb_calloc(size, sizeof(char *));
    if (!query) {
        flb_errno();
        return -1;
    }
    snprintf(query, size, "SELECT * FROM %s", spec->wmi_counter);
    wquery = we_convert_str(query);
    flb_free(query);

    hr = ctx->service->lpVtbl->ExecQuery(
            ctx->service,
            L"WQL",
            wquery,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &enumerator);

    flb_free(wquery);

    if (FAILED(hr)) {
        flb_plg_error(ctx->ins, "Query for %s %s failed. Error code = %x",
                      spec->wmi_counter, spec->wmi_counter, hr);
        ctx->service->lpVtbl->Release(ctx->service);
        ctx->locator->lpVtbl->Release(ctx->locator);
        CoUninitialize();
        return -1;
    }

    *out_enumerator = enumerator;

    return 0;
}

static int wmi_exec_query_fixed_val(struct flb_we *ctx, struct wmi_query_spec *spec)
{
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    uint64_t timestamp = 0;

    timestamp = cfl_time_now();

    if (FAILED(wmi_execute_query(ctx, spec, &enumerator))) {
        return -1;
    }

    while (enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1,
            &class_obj, &ret);

        if(0 == ret) {
            break;
        }

        wmi_update_metrics(ctx, spec, 1.0, class_obj, timestamp);

        class_obj->lpVtbl->Release(class_obj);
    }

    enumerator->lpVtbl->Release(enumerator);

    return 0;
}

static int wmi_exec_query(struct flb_we *ctx, struct wmi_query_spec *spec)
{
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;
    uint64_t timestamp = 0;

    timestamp = cfl_time_now();

    if (FAILED(wmi_execute_query(ctx, spec, &enumerator))) {
        return -1;
    }

    while (enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1,
            &class_obj, &ret);

        if(0 == ret) {
            break;
        }

        val = wmi_get_value(ctx, spec, class_obj);

        wmi_update_metrics(ctx, spec, val, class_obj, timestamp);

        class_obj->lpVtbl->Release(class_obj);
    }

    enumerator->lpVtbl->Release(enumerator);

    return 0;
}

static int wmi_cleanup(struct flb_we *ctx)
{
    flb_plg_debug(ctx->ins, "deinitializing WMI instance....");

    /* Clean up */
    if (ctx->service != NULL) {
        ctx->service->lpVtbl->Release(ctx->service);
        ctx->service = NULL;
    }
    if (ctx->locator != NULL) {
        ctx->locator->lpVtbl->Release(ctx->locator);
        ctx->locator = NULL;
    }
    CoUninitialize();

    return 0;
}

static int wmi_query(struct flb_we *ctx, struct wmi_query_spec *spec)
{
    if (FAILED(wmi_coinitialize(ctx, NULL))) {
        return -1;
    }
    if (FAILED(wmi_exec_query(ctx, spec))) {
        return -1;
    }

    wmi_cleanup(ctx);

    return 0;
}

static int wmi_query_namespace(struct flb_we *ctx, struct wmi_query_spec *spec, char *namespace)
{
    if (FAILED(wmi_coinitialize(ctx, namespace))) {
        return -1;
    }
    if (FAILED(wmi_exec_query(ctx, spec))) {
        return -1;
    }

    wmi_cleanup(ctx);

    return 0;
}

static int wmi_query_fixed_val(struct flb_we *ctx, struct wmi_query_spec *spec)
{
    if (FAILED(wmi_coinitialize(ctx, NULL))) {
        return -1;
    }
    if (FAILED(wmi_exec_query_fixed_val(ctx, spec))) {
        return -1;
    }

    wmi_cleanup(ctx);

    return 0;
}

int we_wmi_init(struct flb_we *ctx)
{
    ctx->locator = NULL;
    ctx->service = NULL;

    return 0;
}

int we_wmi_cleanup(struct flb_we *ctx)
{
    wmi_cleanup(ctx);

    return 0;
}

int we_wmi_exit(struct flb_we *ctx)
{
    return 0;
}

/* Abstract APIs */
int we_wmi_query_fixed_val(struct flb_we *ctx, struct wmi_query_specs *spec)
{
    if (FAILED(wmi_query_fixed_val(ctx, spec))) {
        return -1;
    }
    return 0;
}

int we_wmi_query(struct flb_we *ctx, struct wmi_query_specs *spec)
{
    if (FAILED(wmi_query(ctx, spec))) {
        return -1;
    }
    return 0;
}

int we_wmi_query_namespace(struct flb_we *ctx, struct wmi_query_specs *spec, char *namespace)
{
    if (FAILED(wmi_query_namespace(ctx, spec, namespace))) {
        return -1;
    }
    return 0;
}

/* Concreate APIs */
int we_wmi_coinitialize(struct flb_we *ctx)
{
    if (FAILED(wmi_coinitialize(ctx, NULL))) {
        return -1;
    }

    return 0;
}

int we_wmi_execute_query(struct flb_we *ctx, struct wmi_query_spec *spec, IEnumWbemClassObject **out_enumerator)
{
    IEnumWbemClassObject* enumerator = NULL;

    if (FAILED(wmi_execute_query(ctx, spec, &enumerator))) {
        return -1;
    }

    *out_enumerator = enumerator;

    return 0;
}

double we_wmi_get_value(struct flb_we *ctx, struct wmi_query_spec *spec, IWbemClassObject *class_obj)
{
    return wmi_get_value(ctx, spec, class_obj);
}

double we_wmi_get_property_value(struct flb_we *ctx, char *raw_property_key, IWbemClassObject *class_obj)
{
    return wmi_get_property_value(ctx, raw_property_key, class_obj);
}

int we_wmi_update_counters(struct flb_we *ctx, struct wmi_query_spec *spec, uint64_t timestamp, double val, int metric_label_count, char **metric_label_set)
{
    wmi_update_counters(spec, timestamp, val, metric_label_count, metric_label_set);

    return 0;
}

/*
https://stackoverflow.com/questions/33033111/create-com-object-using-plain-c
https://stackoverflow.com/questions/1431103/how-to-obtain-data-from-wmi-using-a-c-application
https://stackoverflow.com/questions/626674/wmi-queries-in-c
https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/WmiSdk/example--getting-wmi-data-from-the-local-computer.md
https://docs.microsoft.com/en-us/windows/win32/wmisdk/creating-wmi-clients
*/
