/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_compat.h>

static LPSTR errbuf;
static CHAR *currerr;
static char dlerrorbuf[65536];

static void store_error(void)
{
    DWORD err = GetLastError();
    if (err == NO_ERROR) {
        return;
    }

    if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       err,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPTSTR) &errbuf,
                       _countof(errbuf), NULL))
        errbuf[0] = '\0';
    currerr = errbuf;
}

__declspec(noinline)
void *dlopen(const char *filename, int _flag)
{
    HMODULE handle;

    handle = LoadLibrary(filename);
    if (handle == NULL) {
        store_error();
        return NULL;
    }
    return (void *)handle;
}

char *dlerror(void)
{
    char *errorptr = dlerrorbuf;

    if (currerr == NULL)
    {
        return NULL;
    }

    memcpy(errorptr, currerr, strlen(currerr) + 1);

    currerr = NULL;

    return errorptr;
}

__declspec(noinline)
void *dlsym(void *handle, const char *name)
{
    FARPROC *symbol;
    symbol = NULL;

    symbol = GetProcAddress((HMODULE) handle, name);
    if (symbol == NULL) {
        store_error();
        return NULL;
    }

    return (void *)symbol;
}

int dlclose(void *handle)
{
    BOOL result;

    result = FreeLibrary((HMODULE) handle);
    if (!result)
        store_error();

    /* dlcose(3) returns 0 on success, and nonzero on error. */
    /* FreeLibrary returns nonzero on success, and 0 on error. */
    /* ref:
     * https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-freelibrary */
    return !result;
}
