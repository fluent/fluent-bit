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

#include <fluent-bit/flb_sds.h>

#include "we.h"
#include "we_util.h"

double we_get_windows_version()
{
    LSTATUS result;
    DWORD   data_size;
    HKEY    key_handle;
    char    version_text[8];
    double  version_number;

    data_size = sizeof(version_text);

    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                           WE_VERSION_REGISTRY_PATH,
                           0,
                           KEY_READ,
                           &key_handle);

    if (result != ERROR_SUCCESS) {
        return 0;
    }

    result = RegQueryValueExA(key_handle,
                              WE_VERSION_KEY_NAME,
                              NULL,
                              0,
                              version_text,
                              &data_size);

    RegCloseKey(key_handle);

    if (result != ERROR_SUCCESS)
    {
        return 0;
    }

    return strtod(version_text, NULL);
}
