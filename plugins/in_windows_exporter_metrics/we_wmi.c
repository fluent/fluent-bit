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
#include "we_wmi.h"

static char* convert_wstr(wchar_t *wstr, UINT codePage);
static wchar_t* convert_str(char *str);

static int wmi_coinitialize(struct flb_we *ctx)
{
    IWbemLocator *locator = 0;
    IWbemServices *service = 0;
    HRESULT hr;

    flb_plg_info(ctx->ins, "initializing WMI instance....");

    /* Initialize COM library */
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
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
    if (FAILED(hr))
    {
        flb_plg_error(ctx->ins, "Failed to create IWbemLocator object. Error code = %x", hr);
        CoUninitialize();
        return hr;
    }
    ctx->locator = locator;

    /* Connect WMI server */
    hr = locator->lpVtbl->ConnectServer(locator,
                                        L"ROOT\\CIMV2",
                                        NULL,
                                        NULL,
                                        0,
                                        0,
                                        0,
                                        NULL,
                                        &service);
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

static char* convert_wstr(wchar_t *wstr, UINT codePage)
{
    int size = 0;
    char *buf = NULL;

    size = WideCharToMultiByte(codePage, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size == 0) {
        return NULL;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = WideCharToMultiByte(codePage, 0, wstr, -1, buf, size, NULL, NULL);
    if (size == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

static wchar_t* convert_str(char *str)
{
    int size = 0;
    wchar_t *buf = NULL;

    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size == 0) {
        return NULL;
    }

    buf = flb_malloc(sizeof(PWSTR) * size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, size);
    if (size == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

static int wmi_exec_query(struct flb_we *ctx, char* wmi_counter, char* wmi_property)
{
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;
    char *strprop;
    wchar_t *wquery, *wproperty, query[256];

    snprintf(query, 14 + strlen(wmi_counter), "SELECT * FROM %s", wmi_counter);
    wquery = convert_str(query);

    hr = ctx->service->lpVtbl->ExecQuery(
            ctx->service,
            L"WQL",
            wquery,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &enumerator);

    flb_free(wquery);

    if (FAILED(hr)) {
        flb_plg_error(ctx->ins, "Query for %s %s failed. Error code = %x", wmi_counter, wmi_property, hr);
        ctx->service->lpVtbl->Release(ctx->service);
        ctx->locator->lpVtbl->Release(ctx->locator);
        CoUninitialize();
        return -1;
    }

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    DWORD len;

    while (enumerator)
    {
        HRESULT hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1,
            &class_obj, &ret);

        if(0 == ret)
        {
            break;
        }

        VARIANT prop;

        VariantInit(&prop);
        // Get the value of the Name property
        wproperty = convert_str(wmi_property);
        hr = class_obj->lpVtbl->Get(class_obj, wproperty, 0, &prop, 0, 0);
        strprop = convert_wstr(prop.bstrVal, CP_UTF8);
        flb_plg_info(ctx->ins, " %s : %s", wmi_property, strprop);
        flb_free(wproperty);
        flb_free(strprop);
        VariantClear(&prop);

        class_obj->lpVtbl->Release(class_obj);
    }

    return 0;
}

static int wmi_query(struct flb_we *ctx, char* wmi_counter, char* wmi_property)
{
    wmi_exec_query(ctx, wmi_counter, wmi_property);

    return 0;
}

static int wmi_cleanup(struct flb_we *ctx)
{
    /* Clean up */
    ctx->service->lpVtbl->Release(ctx->service);
    ctx->locator->lpVtbl->Release(ctx->locator);
    CoUninitialize();

    return 0;
}

int we_wmi_init(struct flb_we *ctx)
{
    if (FAILED(wmi_coinitialize(ctx))) {
        return -1;
    }

    if (FAILED(wmi_query(ctx, "Win32_OperatingSystem", "Name"))) {
        return -1;
    }

    return 0;
}

int we_wmi_exit(struct flb_we *ctx)
{
    wmi_cleanup(ctx);

    return 0;
}

/*
https://stackoverflow.com/questions/33033111/create-com-object-using-plain-c
https://stackoverflow.com/questions/1431103/how-to-obtain-data-from-wmi-using-a-c-application
https://stackoverflow.com/questions/626674/wmi-queries-in-c
https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/WmiSdk/example--getting-wmi-data-from-the-local-computer.md
https://docs.microsoft.com/en-us/windows/win32/wmisdk/creating-wmi-clients
*/
