/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>

#include "pgsql_loadlib.h"

int loadPqDll(struct flb_output_instance* ins) {
    // Load library
    pqDll = LoadLibrary(TEXT("libpq.dll"));
    if (!pqDll) {
        flb_plg_warn(ins, "Couldn't load libpq.dll");
        return 0;
    }
    else {
        flb_plg_info(ins, "Library was loaded");
    }

    // Load all symbols
    PQconsumeInput = (PQconsumeInputP)GetProcAddress((HMODULE)pqDll, "PQconsumeInput");
    PQstatus = (PQstatusP)GetProcAddress((HMODULE)pqDll, "PQstatus");
    PQgetResult = (PQgetResultP)GetProcAddress((HMODULE)pqDll, "PQgetResult");
    PQresultStatus = (PQresultStatusP)GetProcAddress((HMODULE)pqDll, "PQresultStatus");
    PQerrorMessage = (PQerrorMessageP)GetProcAddress((HMODULE)pqDll, "PQerrorMessage");
    PQclear = (PQclearP)GetProcAddress((HMODULE)pqDll, "PQclear");
    PQfinish = (PQfinishP)GetProcAddress((HMODULE)pqDll, "PQfinish");
    PQsetdbLogin = (PQsetdbLoginP)GetProcAddress((HMODULE)pqDll, "PQsetdbLogin");
    PQsetnonblocking = (PQsetnonblockingP)GetProcAddress((HMODULE)pqDll, "PQsetnonblocking");
    PQisBusy = (PQisBusyP)GetProcAddress((HMODULE)pqDll, "PQisBusy");
    PQescapeIdentifier = (PQescapeIdentifierP)GetProcAddress((HMODULE)pqDll, "PQescapeIdentifier");
    PQfreemem = (PQfreememP)GetProcAddress((HMODULE)pqDll, "PQfreemem");
    PQexec = (PQexecP)GetProcAddress((HMODULE)pqDll, "PQexec");
    PQreset = (PQresetP)GetProcAddress((HMODULE)pqDll, "PQreset");
    PQescapeLiteral = (PQescapeLiteralP)GetProcAddress((HMODULE)pqDll, "PQescapeLiteral");
    PQsendQuery = (PQsendQueryP)GetProcAddress((HMODULE)pqDll, "PQsendQuery");
    PQflush = (PQflushP)GetProcAddress((HMODULE)pqDll, "PQflush");

    return 1;
}

void freePqDll(void) {
    // Free library
    if (pqDll)
        FreeLibrary(pqDll);
    return;
}
